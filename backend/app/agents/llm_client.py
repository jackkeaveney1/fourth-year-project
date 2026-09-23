"""Thin abstraction over an LLM tool-calling API.

The agent loop in `base.py` depends only on this `LLMClient` protocol, not
on any specific vendor SDK. Swap in a different implementation (OpenAI,
local model, a scripted stub for tests) without touching agent logic.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from typing import Any, Protocol

from app.tools.base import ToolSpec


@dataclass
class LLMToolCall:
    name: str
    arguments: dict[str, Any]


@dataclass
class LLMResponse:
    """One turn of the agent's reasoning, as produced by the model."""

    thought: str
    tool_call: LLMToolCall | None
    done: bool = False
    """True when the model believes the goal is achieved and no further tool call is needed."""


class LLMClient(Protocol):
    def next_step(
        self,
        system_prompt: str,
        history: list[dict[str, Any]],
        tools: list[ToolSpec],
    ) -> LLMResponse:
        """Given the conversation so far, decide the next thought + tool call."""
        ...


class AnthropicLLMClient:
    """Default LLMClient backed by the Anthropic Messages API's tool use."""

    def __init__(self, model: str = "claude-sonnet-4-5", api_key: str | None = None) -> None:
        import anthropic  # imported lazily so the rest of the app works without the SDK installed

        self._client = anthropic.Anthropic(api_key=api_key or os.environ.get("ANTHROPIC_API_KEY"))
        self.model = model

    def next_step(
        self,
        system_prompt: str,
        history: list[dict[str, Any]],
        tools: list[ToolSpec],
    ) -> LLMResponse:
        anthropic_tools = [
            {"name": t.name, "description": t.description, "input_schema": t.parameters}
            for t in tools
        ]

        message = self._client.messages.create(
            model=self.model,
            max_tokens=1024,
            system=system_prompt,
            messages=history,
            tools=anthropic_tools,
        )

        thought_parts = [block.text for block in message.content if block.type == "text"]
        tool_use = next((block for block in message.content if block.type == "tool_use"), None)

        tool_call = (
            LLMToolCall(name=tool_use.name, arguments=tool_use.input) if tool_use is not None else None
        )
        return LLMResponse(
            thought="\n".join(thought_parts).strip(),
            tool_call=tool_call,
            done=tool_use is None,
        )


class ScriptedLLMClient:
    """Deterministic stand-in for the LLM, used in tests and offline demos.

    Plays back a fixed list of (thought, tool_name, arguments) steps
    regardless of the conversation history, so the orchestrator/guardrail
    logic can be exercised without an API key or network access.
    """

    def __init__(self, script: list[tuple[str, str | None, dict[str, Any] | None]]) -> None:
        self._script = script
        self._index = 0

    def next_step(
        self,
        system_prompt: str,
        history: list[dict[str, Any]],
        tools: list[ToolSpec],
    ) -> LLMResponse:
        if self._index >= len(self._script):
            return LLMResponse(thought="No more scripted steps.", tool_call=None, done=True)

        thought, tool_name, arguments = self._script[self._index]
        self._index += 1

        if tool_name is None:
            return LLMResponse(thought=thought, tool_call=None, done=True)
        return LLMResponse(
            thought=thought,
            tool_call=LLMToolCall(name=tool_name, arguments=arguments or {}),
        )


def dump_tool_result_for_history(observation: str) -> str:
    """Anthropic expects tool results as plain strings; keep this in one place."""
    return json.dumps(observation) if not isinstance(observation, str) else observation
