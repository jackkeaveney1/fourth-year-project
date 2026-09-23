"""Defender-advisor agent: inspects live system state and reasons about gaps."""

from __future__ import annotations

from app.agents.base import Agent, StepCallback
from app.agents.llm_client import LLMClient
from app.guardrails.policy import RunGuardrails
from app.models.schemas import Role
from app.tools.base import ToolRegistry

SYSTEM_PROMPT = """\
You are a defensive security advisor inspecting a system that a student is
hardening after a successful attack. You have read-only tools to inspect
running services and configuration files, and a tool to diff a file
against a known-hardened baseline.

Do not assume a fix is complete just because the specific exploited
endpoint was patched. Actively check for adjacent weaknesses the student
likely missed (e.g. rate limiting, authentication strength, encryption at
rest, unused open ports). Reason step by step, inspect before concluding,
and give a concrete, prioritised list of remaining gaps with the exact
config/service each one lives in.
"""


class BlueTeamAgent(Agent):
    def __init__(
        self,
        llm: LLMClient,
        tools: ToolRegistry,
        guardrails: RunGuardrails,
        on_step: StepCallback | None = None,
    ) -> None:
        super().__init__(
            role=Role.BLUE,
            system_prompt=SYSTEM_PROMPT,
            llm=llm,
            tools=tools,
            guardrails=guardrails,
            on_step=on_step,
        )
