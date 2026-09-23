"""Application settings, read from environment variables (see `.env.example`)."""

from __future__ import annotations

import os
from dataclasses import dataclass

from dotenv import load_dotenv

load_dotenv()


@dataclass(frozen=True)
class Settings:
    aionlabs_api_key: str | None
    aionlabs_model: str
    anthropic_api_key: str | None
    anthropic_model: str
    groq_api_key: str | None
    groq_model: str
    groq_blue_model: str
    """A different Groq model for the blue-team agent — Groq's rate limits are
    per-model, so this keeps the blue-team assessment from competing with the
    red-team run for the same daily token budget."""
    gemini_api_key: str | None
    gemini_model: str
    use_scripted_llm: bool
    """Forces the deterministic ScriptedLLMClient stub — for CI/tests/demos without an API key."""

    @classmethod
    def from_env(cls) -> "Settings":
        aionlabs_key = os.environ.get("AIONLABS_API_KEY", "").strip() or None
        anthropic_key = os.environ.get("ANTHROPIC_API_KEY", "").strip() or None
        groq_key = os.environ.get("GROQ_API_KEY", "").strip() or None
        gemini_key = os.environ.get("GEMINI_API_KEY", "").strip() or None
        return cls(
            aionlabs_api_key=aionlabs_key,
            aionlabs_model=os.environ.get("AIONLABS_MODEL", "aion-labs/aion-2.0"),
            anthropic_api_key=anthropic_key,
            anthropic_model=os.environ.get("ANTHROPIC_MODEL", "claude-sonnet-4-5"),
            groq_api_key=groq_key,
            groq_model=os.environ.get("GROQ_MODEL", "qwen/qwen3.8-27b"),
            groq_blue_model=os.environ.get("GROQ_BLUE_MODEL", "openai/gpt-oss-120b"),
            gemini_api_key=gemini_key,
            gemini_model=os.environ.get("GEMINI_MODEL", "gemini-3.6-flash"),
            use_scripted_llm=os.environ.get("USE_SCRIPTED_LLM", "").lower() in {"1", "true", "yes"}
            or (
                aionlabs_key is None
                and anthropic_key is None
                and groq_key is None
                and gemini_key is None
            ),
        )


settings = Settings.from_env()
