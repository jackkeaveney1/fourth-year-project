"""Wires the deterministic scenario engine to the agentic red/blue loop.

This is the "Agent Orchestrator" box in the project design doc: it owns
guardrail construction, tool registration, provisioning/teardown, and
turns a raw trajectory into a `RunReport`. It deliberately contains no
attack logic itself — that all lives in the agents and tools.
"""

from __future__ import annotations

import ipaddress
import time
from datetime import UTC, datetime

import docker

from app.agents.base import StepCallback
from app.agents.blue_team import BlueTeamAgent
from app.agents.goal_check import check_goal_achieved, check_privilege_escalation
from app.agents.llm_client import LLMClient
from app.agents.red_team import RedTeamAgent
from app.guardrails.policy import (
    CostBudget,
    NetworkAllowlist,
    RunGuardrails,
    StepBudget,
    ToolAllowlist,
)
from app.models.schemas import (
    LaunchRunRequest,
    RunReport,
    RunStatus,
    Scenario,
)
from app.scenario_engine.engine import ProvisionedRange, ScenarioEngine, new_run_id
from app.tools.base import ToolRegistry
from app.tools.bruteforce import CredentialStuffTool
from app.tools.exfil import ExtractRecordsTool
from app.tools.inspection import DiffBaselineTool, ListServicesTool, ReadConfigTool
from app.tools.recon import ScanPortsTool
from app.tools.shell import RunCommandTool
from app.tools.web import HttpRequestTool

RED_TEAM_TOOL_NAMES = {"scan_ports", "http_request", "run_shell", "try_credentials", "extract_records"}
BLUE_TEAM_TOOL_NAMES = {"read_config", "list_services", "diff_baseline"}


class AgentOrchestrator:
    def __init__(self, llm: LLMClient, docker_client: docker.DockerClient | None = None) -> None:
        self.llm = llm
        self.docker_client = docker_client or docker.from_env()
        self.engine = ScenarioEngine()

    def run_red_team(
        self,
        scenario: Scenario,
        request: LaunchRunRequest,
        on_step: StepCallback | None = None,
    ) -> tuple[RunReport, ProvisionedRange]:
        run_id = new_run_id()
        provisioned = self.engine.render_compose(scenario, run_id)

        started_at = datetime.now(UTC)
        status = RunStatus.PROVISIONING
        trajectory: list = []
        goal_achieved = False
        privesc = False
        elapsed: float | None = None

        try:
            self.engine.up(provisioned)
            status = RunStatus.RUNNING

            guardrails = self._build_guardrails(provisioned, request, RED_TEAM_TOOL_NAMES)
            tools = self._build_red_team_tools(provisioned, guardrails.network)

            agent = RedTeamAgent(llm=self.llm, tools=tools, guardrails=guardrails, on_step=on_step)

            t0 = time.monotonic()
            trajectory = agent.run(scenario.objective)
            elapsed = time.monotonic() - t0

            goal_achieved = check_goal_achieved(trajectory, [provisioned.success_marker])
            privesc = check_privilege_escalation(trajectory)
            status = RunStatus.SUCCEEDED if goal_achieved else RunStatus.FAILED

        except Exception:  # noqa: BLE001 - surfaced as a FAILED report, never crashes the API
            status = RunStatus.FAILED
        finally:
            try:
                self.engine.down(provisioned)
            except Exception:  # noqa: BLE001 - teardown best-effort; provisioning may have partially failed
                pass

        report = RunReport(
            run_id=run_id,
            scenario_id=scenario.id,
            status=status,
            objective=scenario.objective,
            goal_achieved=goal_achieved,
            trajectory=trajectory,
            vulnerabilities_exploited=[v.id for s in scenario.services for v in s.vulnerabilities]
            if goal_achieved
            else [],
            privilege_escalation=privesc,
            detected_by_blue_team=False,
            time_to_compromise_seconds=elapsed if goal_achieved else None,
            agent_step_count=len(trajectory),
            started_at=started_at,
            ended_at=datetime.now(UTC),
        )
        return report, provisioned

    def run_blue_team(
        self,
        scenario: Scenario,
        provisioned: ProvisionedRange,
        max_steps: int,
        on_step: StepCallback | None = None,
    ) -> list:
        guardrails = self._build_guardrails(
            provisioned,
            LaunchRunRequest(scenario_id=scenario.id, max_steps=max_steps),
            BLUE_TEAM_TOOL_NAMES,
        )
        tools = self._build_blue_team_tools(scenario, provisioned)
        agent = BlueTeamAgent(llm=self.llm, tools=tools, guardrails=guardrails, on_step=on_step)
        return agent.run(f"Assess hardening for scenario: {scenario.title}")

    def _build_guardrails(
        self,
        provisioned: ProvisionedRange,
        request: LaunchRunRequest,
        tool_names: set[str],
    ) -> RunGuardrails:
        subnet = ipaddress.ip_network(f"{provisioned.subnet_base}.0/24")
        return RunGuardrails(
            steps=StepBudget(max_steps=request.max_steps),
            cost=CostBudget(max_cost_usd=request.max_cost_usd),
            tools=ToolAllowlist(allowed=tool_names),
            network=NetworkAllowlist(allowed_subnet=subnet),
        )

    def _build_red_team_tools(self, provisioned: ProvisionedRange, network: NetworkAllowlist) -> ToolRegistry:
        registry = ToolRegistry()
        subnet = network.allowed_subnet
        registry.register(ScanPortsTool(allowed_subnet=subnet))
        registry.register(HttpRequestTool(network=network))
        registry.register(RunCommandTool(self.docker_client, provisioned.attacker_container_name))
        registry.register(CredentialStuffTool(network=network))
        registry.register(ExtractRecordsTool())
        return registry

    def _build_blue_team_tools(self, scenario: Scenario, provisioned: ProvisionedRange) -> ToolRegistry:
        registry = ToolRegistry()
        allowed_containers = {f"{provisioned.run_id}-{s.name}" for s in scenario.services}
        registry.register(ReadConfigTool(self.docker_client, allowed_containers))
        registry.register(ListServicesTool(self.docker_client, scenario_label=scenario.id))
        registry.register(DiffBaselineTool(self.docker_client, baselines={}))
        return registry
