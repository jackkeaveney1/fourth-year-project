"""Wires the deterministic scenario engine to the agentic red/blue loop.

This is the "Agent Orchestrator" box in the project design doc: it owns
guardrail construction, tool registration, provisioning/teardown, and
turns a raw trajectory into a `RunReport`. It deliberately contains no
attack logic itself — that all lives in the agents and tools.
"""

from __future__ import annotations

import ipaddress
import logging
import time
from collections.abc import Callable
from datetime import UTC, datetime

import docker

logger = logging.getLogger(__name__)

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
from app.reporting.attack_report import build_attack_report
from app.scenario_engine.engine import ProvisionedRange, ScenarioEngine, new_run_id
from app.scoring.scorer import compute_scorecard, derive_posture
from app.tools.base import ToolRegistry
from app.tools.bruteforce import CredentialStuffTool
from app.tools.discovery import DiscoverPathsTool
from app.tools.exfil import ExtractRecordsTool
from app.tools.inspection import ListServicesTool, ReadConfigTool
from app.tools.recon import ScanPortsTool
from app.tools.shell import RunCommandTool
from app.tools.web import HttpRequestTool

RED_TEAM_TOOL_NAMES = {
    "scan_ports",
    "discover_paths",
    "http_request",
    "run_shell",
    "try_credentials",
    "extract_records",
}
BLUE_TEAM_TOOL_NAMES = {"read_config", "list_services"}


class AgentOrchestrator:
    def __init__(
        self,
        llm: LLMClient,
        docker_client: docker.DockerClient | None = None,
        blue_llm: LLMClient | None = None,
    ) -> None:
        self.llm = llm
        # Defaults to the same client as the red team, but callers can pass a
        # separate one (e.g. a different model) so the two agents don't
        # compete for the same provider-side rate-limit budget.
        self.blue_llm = blue_llm or llm
        self.docker_client = docker_client or docker.from_env()
        self.engine = ScenarioEngine()

    def run_red_team(
        self,
        scenario: Scenario,
        request: LaunchRunRequest,
        on_step: StepCallback | None = None,
        blue_max_steps: int = 8,
        on_phase: Callable[[str], None] | None = None,
    ) -> tuple[RunReport, ProvisionedRange]:
        """Run a full assessment: red-team attack, then blue-team review of the
        *same still-live range* before it's torn down, then deterministic
        scoring. `on_step` receives steps from both agents — each
        `TrajectoryStep.role` distinguishes which one produced it.
        """
        run_id = new_run_id()
        provisioned = self.engine.render_compose(scenario, run_id)

        started_at = datetime.now(UTC)
        status = RunStatus.PROVISIONING
        trajectory: list = []
        blue_trajectory: list = []
        goal_achieved = False
        privesc = False
        elapsed: float | None = None

        try:
            self.engine.up(provisioned)
            status = RunStatus.RUNNING

            guardrails = self._build_guardrails(provisioned, request, RED_TEAM_TOOL_NAMES, scenario)
            tools = self._build_red_team_tools(provisioned)

            agent = RedTeamAgent(llm=self.llm, tools=tools, guardrails=guardrails, on_step=on_step)

            # A real pentest starts from a defined scope, not a blind guess —
            # without this the agent has no way to know the target's actual
            # hostnames and will invent an IP that the guardrails then (correctly) block.
            in_scope_hosts = ", ".join(s.internal_hostname for s in scenario.services)
            briefed_objective = (
                f"{scenario.objective}\n\n"
                f"Hosts in scope (address them by these exact hostnames, not IP addresses): "
                f"{in_scope_hosts}"
            )

            t0 = time.monotonic()
            trajectory = agent.run(briefed_objective)
            elapsed = time.monotonic() - t0

            goal_achieved = check_goal_achieved(trajectory, [provisioned.success_marker])
            privesc = check_privilege_escalation(trajectory)
            status = RunStatus.SUCCEEDED if goal_achieved else RunStatus.FAILED

            # Blue-team reviews the *same still-live range* the red-team just
            # attacked, before it's torn down — not a fresh one.
            if on_phase is not None:
                on_phase("assessing")
            try:
                blue_trajectory = self.run_blue_team(
                    scenario, provisioned, max_steps=blue_max_steps, on_step=on_step
                )
            except Exception:  # noqa: BLE001 - blue-team failure shouldn't sink the whole report
                logger.exception("Blue-team assessment for run %s failed", run_id)
                blue_trajectory = []

        except Exception:  # noqa: BLE001 - surfaced as a FAILED report, never crashes the API
            logger.exception("Red-team run %s failed", run_id)
            status = RunStatus.FAILED
        finally:
            try:
                self.engine.down(provisioned)
            except Exception:  # noqa: BLE001 - teardown best-effort; provisioning may have partially failed
                # Never leave this silent: a failed teardown means the range's
                # containers/network are still live and need manual cleanup.
                logger.exception(
                    "Failed to tear down run %s (project cyber-range-%s) — "
                    "containers/network may still be running, clean up manually",
                    run_id,
                    run_id,
                )

        posture = derive_posture(scenario, goal_achieved, trajectory)
        scorecard = compute_scorecard(posture)

        # A step whose thought is "LLM call failed: ..." means the agent crashed
        # before reaching a conclusion, not that it *concluded* that text — keep
        # it out of blue_team_summary so a provider error never masquerades as
        # a real assessment, and surface it separately instead.
        last_blue_step = blue_trajectory[-1] if blue_trajectory else None
        blue_error = (
            last_blue_step.thought
            if last_blue_step is not None
            and last_blue_step.tool_call is None
            and (last_blue_step.thought or "").startswith("LLM call failed:")
            else None
        )
        blue_summary = next(
            (
                step.thought
                for step in reversed(blue_trajectory)
                if step.thought and not step.thought.startswith("LLM call failed:")
            ),
            None,
        )

        vulnerabilities_exploited = (
            [v.id for s in scenario.services for v in s.vulnerabilities] if goal_achieved else []
        )
        attack_report = build_attack_report(trajectory, goal_achieved, scenario, vulnerabilities_exploited)

        report = RunReport(
            run_id=run_id,
            scenario_id=scenario.id,
            status=status,
            objective=scenario.objective,
            goal_achieved=goal_achieved,
            trajectory=trajectory,
            vulnerabilities_exploited=vulnerabilities_exploited,
            privilege_escalation=privesc,
            detected_by_blue_team=False,
            time_to_compromise_seconds=elapsed if goal_achieved else None,
            agent_step_count=len(trajectory),
            started_at=started_at,
            ended_at=datetime.now(UTC),
            scorecard=scorecard,
            blue_team_trajectory=blue_trajectory,
            blue_team_summary=blue_summary,
            blue_team_error=blue_error,
            attack_report=attack_report,
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
            scenario,
        )
        tools = self._build_blue_team_tools(scenario, provisioned)
        agent = BlueTeamAgent(llm=self.blue_llm, tools=tools, guardrails=guardrails, on_step=on_step)
        return agent.run(f"Assess hardening for scenario: {scenario.title}")

    def _build_guardrails(
        self,
        provisioned: ProvisionedRange,
        request: LaunchRunRequest,
        tool_names: set[str],
        scenario: Scenario,
    ) -> RunGuardrails:
        subnet = ipaddress.ip_network(f"{provisioned.subnet_base}.0/24")
        # Tools reach range hosts by their compose service name (e.g. "web"),
        # resolved by Docker's embedded DNS *inside* the attacker container —
        # the host process this guardrail check runs in can't resolve or
        # reach them at all, so hostname-vs-IP allowlisting is advisory here;
        # the real confinement is the range network being `internal: true`.
        allowed_hostnames = {s.internal_hostname for s in scenario.services} | {"attacker"}
        return RunGuardrails(
            steps=StepBudget(max_steps=request.max_steps),
            cost=CostBudget(max_cost_usd=request.max_cost_usd),
            tools=ToolAllowlist(allowed=tool_names),
            network=NetworkAllowlist(allowed_subnet=subnet, allowed_hostnames=allowed_hostnames),
        )

    def _build_red_team_tools(self, provisioned: ProvisionedRange) -> ToolRegistry:
        registry = ToolRegistry()
        registry.register(ScanPortsTool(self.docker_client, provisioned.attacker_container_name))
        registry.register(DiscoverPathsTool(self.docker_client, provisioned.attacker_container_name))
        registry.register(HttpRequestTool(self.docker_client, provisioned.attacker_container_name))
        registry.register(RunCommandTool(self.docker_client, provisioned.attacker_container_name))
        registry.register(CredentialStuffTool(self.docker_client, provisioned.attacker_container_name))
        registry.register(ExtractRecordsTool())
        return registry

    def _build_blue_team_tools(self, scenario: Scenario, provisioned: ProvisionedRange) -> ToolRegistry:
        registry = ToolRegistry()
        allowed_containers = {f"{provisioned.run_id}-{s.name}" for s in scenario.services}
        registry.register(ReadConfigTool(self.docker_client, allowed_containers))
        registry.register(ListServicesTool(self.docker_client, scenario_label=scenario.id))
        return registry
