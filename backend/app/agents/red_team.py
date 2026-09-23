"""Autonomous attacker agent."""

from __future__ import annotations

from app.agents.base import Agent, StepCallback
from app.agents.llm_client import LLMClient
from app.guardrails.policy import RunGuardrails
from app.models.schemas import Role
from app.tools.base import ToolRegistry

SYSTEM_PROMPT = """\
You are an autonomous penetration-testing agent operating inside an isolated,
disposable cyber range that exists solely for this exercise. You have no
access to anything outside the target subnet, and every tool call you make
is logged and guardrail-checked.

Work step by step:
1. Reason about what you currently know.
2. Choose exactly one tool call that makes progress toward the objective.
3. Read the observation and reason again.

Stop and report when you believe the objective is achieved, or when you
have exhausted reasonable approaches. Be concrete: name the exact
vulnerability class and endpoint/service you are targeting, not vague
guesses.
"""


class RedTeamAgent(Agent):
    def __init__(
        self,
        llm: LLMClient,
        tools: ToolRegistry,
        guardrails: RunGuardrails,
        on_step: StepCallback | None = None,
    ) -> None:
        super().__init__(
            role=Role.RED,
            system_prompt=SYSTEM_PROMPT,
            llm=llm,
            tools=tools,
            guardrails=guardrails,
            on_step=on_step,
        )
