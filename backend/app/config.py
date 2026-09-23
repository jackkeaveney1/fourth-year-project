"""Application settings, read from environment variables (see `.env.example`)."""

from __future__ import annotations

import os
from dataclasses import dataclass


@dataclass(frozen=True)
class Settings:
    anthropic_api_key: str | None
    anthropic_model: str
    use_scripted_llm: bool
    """Forces the deterministic ScriptedLLMClient stub — for CI/tests/demos without an API key."""

    @classmethod
    def from_env(cls) -> "Settings":
        api_key = os.environ.get("ANTHROPIC_API_KEY")
        return cls(
            anthropic_api_key=api_key,
            anthropic_model=os.environ.get("ANTHROPIC_MODEL", "claude-sonnet-4-5"),
            use_scripted_llm=os.environ.get("USE_SCRIPTED_LLM", "").lower() in {"1", "true", "yes"}
            or api_key is None,
        )


settings = Settings.from_env()
