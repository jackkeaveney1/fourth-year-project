"""Credential-attack tool: tries a small wordlist against a login endpoint.

Bounded by design — a fixed, short candidate list and a hard attempt cap —
so a misbehaving agent can't turn this into a real brute-force flood even
inside the isolated range.
"""

from __future__ import annotations

from typing import Any

import requests

from app.guardrails.policy import GuardrailViolation, NetworkAllowlist
from app.models.schemas import ToolResult
from app.tools.base import Tool, ToolSpec

MAX_ATTEMPTS = 25

DEFAULT_CREDENTIALS = [
    ("admin", "admin"),
    ("admin", "password"),
    ("admin", "123456"),
    ("root", "root"),
    ("user", "user"),
]


class CredentialStuffTool(Tool):
    def __init__(self, network: NetworkAllowlist, timeout_s: float = 5.0) -> None:
        self.network = network
        self.timeout_s = timeout_s
        self.spec = ToolSpec(
            name="try_credentials",
            description=(
                "Attempt a small, fixed set of common username/password pairs "
                f"(max {MAX_ATTEMPTS}) against a login endpoint in the target range."
            ),
            parameters={
                "type": "object",
                "properties": {
                    "url": {"type": "string"},
                    "username_field": {"type": "string", "default": "username"},
                    "password_field": {"type": "string", "default": "password"},
                    "success_marker": {
                        "type": "string",
                        "description": "Substring expected in the response body on success",
                    },
                },
                "required": ["url", "success_marker"],
            },
        )

    def run(self, **kwargs: Any) -> ToolResult:
        url: str = kwargs["url"]
        user_field: str = kwargs.get("username_field", "username")
        pass_field: str = kwargs.get("password_field", "password")
        success_marker: str = kwargs["success_marker"]

        try:
            self.network.check_url(url)
        except GuardrailViolation as exc:
            return ToolResult(ok=False, output="", error=str(exc))

        attempts = 0
        for username, password in DEFAULT_CREDENTIALS[:MAX_ATTEMPTS]:
            attempts += 1
            try:
                response = requests.post(
                    url,
                    data={user_field: username, pass_field: password},
                    timeout=self.timeout_s,
                )
            except requests.RequestException as exc:
                return ToolResult(ok=False, output="", error=f"Request failed: {exc}")

            if success_marker in response.text:
                return ToolResult(
                    ok=True,
                    output=f"Success after {attempts} attempts: {username}:{password}",
                )

        return ToolResult(ok=False, output=f"No valid credentials found in {attempts} attempts")
