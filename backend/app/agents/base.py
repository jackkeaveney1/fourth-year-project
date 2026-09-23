"""The reason -> act -> observe loop shared by every agent role.

This is the agentic core described in the project design doc: rather than
replaying a fixed script, each step asks the LLM to decide the next
thought and tool call given everything observed so far, and the loop
stops only when the model signals it's done, a guardrail is hit, or the
step budget runs out.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from app.agents.llm_client import LLMClient
from app.guardrails.policy import GuardrailViolation, RunGuardrails
from app.models.schemas import Role, ToolCall, TrajectoryStep
from app.tools.base import ToolRegistry, ToolSpec

StepCallback = Callable[[TrajectoryStep], None]
"""Invoked after each step, e.g. to push it onto a WebSocket for live viewing."""

CONCLUDE_TOOL_NAME = "conclude"
_CONCLUDE_TOOL_SPEC = ToolSpec(
    name=CONCLUDE_TOOL_NAME,
    description=(
        "Call this when the objective is achieved or you've exhausted reasonable "
        "approaches and are stopping. Do not just describe a plan without calling "
        "a tool — every turn must either make progress with a real tool or conclude."
    ),
    parameters={
        "type": "object",
        "properties": {
            "summary": {
                "type": "string",
                "description": "Your final assessment: what you found/achieved, or why you're stopping.",
            }
        },
        "required": ["summary"],
    },
)
"""A weaker/chattier model will sometimes narrate a plan ("let me explore them...")
without actually attaching a tool call that turn. Forcing tool selection on every
request (see each LLMClient) plus giving the model an explicit way to signal
"I'm done" turns that ambiguous silence into an unambiguous, always-required choice."""

MAX_OBSERVATION_CHARS_FOR_HISTORY = 800
"""Cap on how much of a single tool observation goes back into the LLM's own
conversation history. A raw config file (e.g. postgresql.conf) can run to
tens of KB and blow past a free-tier provider's per-request token limit in
one turn; the full text still reaches the UI/report via TrajectoryStep,
this only trims what gets fed back into the next LLM call."""

MAX_HISTORY_MESSAGES_FOR_LLM = 8
"""Sliding window on how many *recent* history messages are sent to the LLM,
on top of the per-observation cap above. Free-tier providers like Groq cap
requests at as little as 8000 tokens/minute for some models — even truncated
observations add up across a long run and can still blow that budget on a
later step, so the window keeps total request size bounded regardless of how
many steps have run. The original (untruncated) objective is always kept so
the agent never loses sight of its goal."""


def _truncate_for_history(text: str) -> str:
    if len(text) <= MAX_OBSERVATION_CHARS_FOR_HISTORY:
        return text
    omitted = len(text) - MAX_OBSERVATION_CHARS_FOR_HISTORY
    return text[:MAX_OBSERVATION_CHARS_FOR_HISTORY] + f"\n... [truncated, {omitted} more chars]"


def _windowed_history(history: list[dict[str, Any]]) -> list[dict[str, Any]]:
    if len(history) <= MAX_HISTORY_MESSAGES_FOR_LLM + 1:
        return history
    return [history[0], *history[-MAX_HISTORY_MESSAGES_FOR_LLM:]]


class Agent:
    def __init__(
        self,
        role: Role,
        system_prompt: str,
        llm: LLMClient,
        tools: ToolRegistry,
        guardrails: RunGuardrails,
        on_step: StepCallback | None = None,
    ) -> None:
        self.role = role
        self.system_prompt = system_prompt
        self.llm = llm
        self.tools = tools
        self.guardrails = guardrails
        self.on_step = on_step

    def run(self, objective: str) -> list[TrajectoryStep]:
        trajectory: list[TrajectoryStep] = []
        history: list[dict[str, Any]] = [{"role": "user", "content": f"Objective: {objective}"}]
        step_number = 0

        while True:
            step_number += 1
            try:
                response = self.llm.next_step(
                    self.system_prompt, history, [*self.tools.specs(), _CONCLUDE_TOOL_SPEC]
                )
            except Exception as exc:  # noqa: BLE001 - surfaced as a terminal trajectory step
                step = TrajectoryStep(
                    step=step_number,
                    role=self.role,
                    thought=f"LLM call failed: {exc}",
                    tool_call=None,
                    observation=None,
                )
                trajectory.append(step)
                self._emit(step)
                break

            if response.tool_call is None or response.tool_call.name == CONCLUDE_TOOL_NAME:
                summary = (
                    response.tool_call.arguments.get("summary") if response.tool_call else None
                )
                step = TrajectoryStep(
                    step=step_number,
                    role=self.role,
                    thought=summary or response.thought or "(goal reached, no further action)",
                    tool_call=None,
                    observation=None,
                )
                trajectory.append(step)
                self._emit(step)
                break

            tool_call = ToolCall(name=response.tool_call.name, arguments=response.tool_call.arguments)

            try:
                target = tool_call.arguments.get("url") or tool_call.arguments.get("host")
                self.guardrails.before_tool_call(tool_call.name, url=target)
                result = self.tools.get(tool_call.name).run(**tool_call.arguments)
                if result.ok:
                    observation = result.output
                else:
                    # Prefer the tool's own error message, but never silently
                    # drop a populated `output` in favour of a bare "ERROR: None".
                    observation = f"ERROR: {result.error}" if result.error else result.output or "ERROR: (no output)"
            except (GuardrailViolation, KeyError, TypeError) as exc:
                observation = f"BLOCKED: {exc}"

            step = TrajectoryStep(
                step=step_number,
                role=self.role,
                thought=response.thought,
                tool_call=tool_call,
                observation=observation,
            )
            trajectory.append(step)
            self._emit(step)

            history.append({"role": "assistant", "content": response.thought or "(tool call)"})
            history.append(
                {"role": "user", "content": f"Observation: {_truncate_for_history(observation)}"}
            )

            if observation.startswith("BLOCKED"):
                break

        return trajectory

    def _emit(self, step: TrajectoryStep) -> None:
        if self.on_step is not None:
            self.on_step(step)
