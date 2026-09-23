import ipaddress

from app.agents.base import Agent
from app.agents.llm_client import ScriptedLLMClient
from app.guardrails.policy import CostBudget, NetworkAllowlist, RunGuardrails, StepBudget, ToolAllowlist
from app.models.schemas import Role, ToolResult
from app.tools.base import Tool, ToolRegistry, ToolSpec


class _EchoTool(Tool):
    def __init__(self):
        self.spec = ToolSpec(name="echo", description="echo", parameters={"type": "object", "properties": {}})
        self.calls = 0

    def run(self, **kwargs):
        self.calls += 1
        return ToolResult(ok=True, output=f"echoed:{kwargs.get('message', '')}")


def _guardrails(max_steps: int) -> RunGuardrails:
    return RunGuardrails(
        steps=StepBudget(max_steps=max_steps),
        cost=CostBudget(max_cost_usd=1.0),
        tools=ToolAllowlist(allowed={"echo"}),
        network=NetworkAllowlist(allowed_subnet=ipaddress.ip_network("172.30.5.0/24")),
    )


def test_agent_loop_runs_until_llm_signals_done():
    tools = ToolRegistry()
    echo = _EchoTool()
    tools.register(echo)

    llm = ScriptedLLMClient(
        script=[
            ("first step", "echo", {"message": "hi"}),
            ("second step", "echo", {"message": "again"}),
            ("goal achieved", None, None),
        ]
    )

    agent = Agent(
        role=Role.RED,
        system_prompt="test",
        llm=llm,
        tools=tools,
        guardrails=_guardrails(max_steps=10),
    )
    trajectory = agent.run("do the thing")

    assert len(trajectory) == 3
    assert echo.calls == 2
    assert trajectory[0].observation == "echoed:hi"
    assert trajectory[-1].tool_call is None


def test_agent_loop_stops_when_step_budget_exhausted():
    tools = ToolRegistry()
    tools.register(_EchoTool())

    llm = ScriptedLLMClient(
        script=[
            ("step 1", "echo", {"message": "a"}),
            ("step 2", "echo", {"message": "b"}),
            ("step 3", "echo", {"message": "c"}),
        ]
    )

    agent = Agent(
        role=Role.RED,
        system_prompt="test",
        llm=llm,
        tools=tools,
        guardrails=_guardrails(max_steps=1),
    )
    trajectory = agent.run("do the thing")

    # First tool call consumes the only step in the budget; the second is blocked.
    assert trajectory[0].observation == "echoed:a"
    assert trajectory[1].observation is not None and trajectory[1].observation.startswith("BLOCKED")
    assert len(trajectory) == 2


def test_agent_records_step_callback():
    tools = ToolRegistry()
    tools.register(_EchoTool())
    llm = ScriptedLLMClient(script=[("only step", "echo", {"message": "x"}), ("done", None, None)])

    seen = []
    agent = Agent(
        role=Role.RED,
        system_prompt="test",
        llm=llm,
        tools=tools,
        guardrails=_guardrails(max_steps=10),
        on_step=seen.append,
    )
    agent.run("goal")
    assert len(seen) == 2
    assert seen[0].observation == "echoed:x"
