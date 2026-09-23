"""Tool interface exposed to agents.

Every tool declares a JSON-schema-compatible spec so it can be handed
straight to an LLM tool-calling API, and implements `run()` with a plain
Python signature the orchestrator calls after guardrail checks pass.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any

from app.models.schemas import ToolResult


@dataclass(frozen=True)
class ToolSpec:
    name: str
    description: str
    parameters: dict[str, Any]
    """JSON schema for the tool's arguments, passed to the LLM function-calling API."""


class Tool(ABC):
    spec: ToolSpec

    @abstractmethod
    def run(self, **kwargs: Any) -> ToolResult:
        """Execute the tool and return its observation."""


class ToolRegistry:
    def __init__(self) -> None:
        self._tools: dict[str, Tool] = {}

    def register(self, tool: Tool) -> None:
        self._tools[tool.spec.name] = tool

    def get(self, name: str) -> Tool:
        if name not in self._tools:
            raise KeyError(f"Unknown tool: {name}")
        return self._tools[name]

    def specs(self) -> list[ToolSpec]:
        return [t.spec for t in self._tools.values()]

    def names(self) -> set[str]:
        return set(self._tools.keys())
