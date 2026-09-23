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
            # Forces a tool call every turn (the agent loop always includes a
            # "conclude" tool for signalling done) so a model can't narrate a
            # plan without attaching a call the loop would then mistake for "done".
            tool_choice={"type": "any"},
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


class GroqLLMClient:
    """LLMClient backed by Groq's OpenAI-compatible chat completions API.

    Groq's free tier supports real tool/function calling, which is all the
    ReAct loop needs — this is a drop-in alternative to AnthropicLLMClient
    for anyone who doesn't want to pay for API access while testing the
    agent loop. Groq's available model lineup changes over time (models get
    decommissioned); `openai/gpt-oss-20b` is confirmed working with tool
    calling as of this writing — check https://console.groq.com/docs/models
    if it stops working.
    """

    def __init__(self, model: str = "openai/gpt-oss-20b", api_key: str | None = None) -> None:
        import groq  # imported lazily so the rest of the app works without the SDK installed

        self._client = groq.Groq(api_key=api_key or os.environ.get("GROQ_API_KEY"))
        self.model = model

    def next_step(
        self,
        system_prompt: str,
        history: list[dict[str, Any]],
        tools: list[ToolSpec],
    ) -> LLMResponse:
        openai_tools = [
            {
                "type": "function",
                "function": {"name": t.name, "description": t.description, "parameters": t.parameters},
            }
            for t in tools
        ]
        messages = [{"role": "system", "content": system_prompt}, *history]

        response = self._client.chat.completions.create(
            model=self.model,
            # Some free-tier Groq models cap output-tokens-per-minute as low as
            # 1000 (separate from the daily quota) — 1024 alone blew past that
            # limit and 429'd every call. Stay comfortably under it.
            max_tokens=800,
            messages=messages,
            tools=openai_tools,
            # Forces a tool call every turn — without this, smaller/chattier
            # models can respond with plain narration text and no call, which
            # the agent loop would otherwise mistake for "I'm done".
            tool_choice="required",
        )

        message = response.choices[0].message
        # Reasoning models (e.g. gpt-oss) put their actual thinking in a
        # separate `reasoning` field and often leave `content` empty,
        # especially on a turn that ends in a tool call.
        thought = message.content or getattr(message, "reasoning", None) or ""
        tool_calls = message.tool_calls or []

        tool_call = None
        if tool_calls:
            first = tool_calls[0]
            try:
                arguments = json.loads(first.function.arguments)
            except json.JSONDecodeError:
                arguments = {}
            tool_call = LLMToolCall(name=first.function.name, arguments=arguments)

        return LLMResponse(thought=thought.strip(), tool_call=tool_call, done=tool_call is None)


class AionLabsLLMClient:
    """LLMClient backed by Aion Labs' OpenAI-compatible chat completions API.

    https://api.aionlabs.ai/v1 is drop-in compatible with the OpenAI Chat
    Completions schema, so this talks to it directly over `requests`
    (already a project dependency) instead of pulling in the `openai` SDK.
    """

    def __init__(self, model: str = "aion-labs/aion-2.0", api_key: str | None = None) -> None:
        self._api_key = api_key or os.environ.get("AIONLABS_API_KEY")
        self.model = model
        self._base_url = "https://api.aionlabs.ai/v1"

    def next_step(
        self,
        system_prompt: str,
        history: list[dict[str, Any]],
        tools: list[ToolSpec],
    ) -> LLMResponse:
        import requests

        openai_tools = [
            {
                "type": "function",
                "function": {"name": t.name, "description": t.description, "parameters": t.parameters},
            }
            for t in tools
        ]
        messages = [{"role": "system", "content": system_prompt}, *history]

        response = requests.post(
            f"{self._base_url}/chat/completions",
            headers={"Authorization": f"Bearer {self._api_key}"},
            json={
                "model": self.model,
                # This model burns ~350-400 tokens of visible <think> reasoning
                # before it ever emits the tool_calls block — 800 (fine for
                # Groq) truncates mid-reasoning and the call never appears.
                "max_tokens": 1500,
                "messages": messages,
                "tools": openai_tools,
                # Forces a tool call every turn — see GroqLLMClient.next_step.
                "tool_choice": "required",
            },
            timeout=60,
        )
        response.raise_for_status()
        message = response.json()["choices"][0]["message"]

        thought = message.get("content") or ""
        tool_calls = message.get("tool_calls") or []

        tool_call = None
        if tool_calls:
            first = tool_calls[0]["function"]
            try:
                arguments = json.loads(first["arguments"])
            except json.JSONDecodeError:
                arguments = {}
            tool_call = LLMToolCall(name=first["name"], arguments=arguments)

        return LLMResponse(thought=thought.strip(), tool_call=tool_call, done=tool_call is None)


class GeminiLLMClient:
    """LLMClient backed by Google's Gemini API (function calling).

    Gemini Flash has a generous free tier and supports real tool/function
    calling, making it another no-cost option alongside GroqLLMClient.
    """

    def __init__(self, model: str = "gemini-3.6-flash", api_key: str | None = None) -> None:
        from google import genai  # imported lazily so the rest of the app works without the SDK installed
        from google.genai import types

        self._genai = genai
        self._client = genai.Client(
            api_key=api_key or os.environ.get("GEMINI_API_KEY"),
            # The SDK's default retry policy is "never retry", and with no
            # timeout set a request can hang indefinitely when Gemini reports
            # itself as overloaded (503) instead of failing fast — confirmed
            # live, a stuck call blocked an entire run for 240s+ with no
            # error surfaced. Bound it so `next_step`'s own try/except in
            # base.py Agent.run always gets a chance to catch a real failure.
            http_options=types.HttpOptions(timeout=45_000),
        )
        self.model = model

    def next_step(
        self,
        system_prompt: str,
        history: list[dict[str, Any]],
        tools: list[ToolSpec],
    ) -> LLMResponse:
        from google.genai import types

        function_declarations = [
            types.FunctionDeclaration(
                name=t.name, description=t.description, parameters=t.parameters
            )
            for t in tools
        ]
        gemini_tools = [types.Tool(function_declarations=function_declarations)] if tools else None

        contents = [
            types.Content(
                role="model" if turn["role"] == "assistant" else "user",
                parts=[types.Part.from_text(text=str(turn["content"]))],
            )
            for turn in history
        ]

        response = self._client.models.generate_content(
            model=self.model,
            contents=contents,
            config=types.GenerateContentConfig(
                system_instruction=system_prompt,
                tools=gemini_tools,
                # Forces a function call every turn, for the same reason as the
                # other clients' tool_choice — see GroqLLMClient.next_step.
                tool_config=types.ToolConfig(
                    function_calling_config=types.FunctionCallingConfig(mode="ANY")
                ),
            ),
        )

        candidate = response.candidates[0] if response.candidates else None
        parts = candidate.content.parts if candidate is not None and candidate.content else []

        text_parts = [p.text for p in parts if getattr(p, "text", None)]
        function_call = next((p.function_call for p in parts if getattr(p, "function_call", None)), None)

        tool_call = (
            LLMToolCall(name=function_call.name, arguments=dict(function_call.args or {}))
            if function_call is not None
            else None
        )
        return LLMResponse(
            thought="\n".join(text_parts).strip(),
            tool_call=tool_call,
            done=tool_call is None,
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
