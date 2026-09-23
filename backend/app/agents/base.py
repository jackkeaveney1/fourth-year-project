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
from app.tools.base import ToolRegistry

StepCallback = Callable[[TrajectoryStep], None]
"""Invoked after each step, e.g. to push it onto a WebSocket for live viewing."""


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
                response = self.llm.next_step(self.system_prompt, history, self.tools.specs())
            except Exception as exc:  # noqa: BLE001 - surfaced as a terminal trajectory step
                trajectory.append(
                    TrajectoryStep(
                        step=step_number,
                        role=self.role,
                        thought=f"LLM call failed: {exc}",
                        tool_call=None,
                        observation=None,
                    )
                )
                break

            if response.tool_call is None:
                step = TrajectoryStep(
                    step=step_number,
                    role=self.role,
                    thought=response.thought or "(goal reached, no further action)",
                    tool_call=None,
                    observation=None,
                )
                trajectory.append(step)
                self._emit(step)
                break

            tool_call = ToolCall(name=response.tool_call.name, arguments=response.tool_call.arguments)

            try:
                url = tool_call.arguments.get("url")
                self.guardrails.before_tool_call(tool_call.name, url=url)
                result = self.tools.get(tool_call.name).run(**tool_call.arguments)
                observation = result.output if result.ok else f"ERROR: {result.error}"
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
            history.append({"role": "user", "content": f"Observation: {observation}"})

            if observation.startswith("BLOCKED"):
                break

        return trajectory

    def _emit(self, step: TrajectoryStep) -> None:
        if self.on_step is not None:
            self.on_step(step)
