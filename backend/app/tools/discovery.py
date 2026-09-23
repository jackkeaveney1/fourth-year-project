"""Content-discovery tool: probe a wordlist of common paths against a host.

Mirrors real pentesting tools like gobuster/ffuf/dirb. Without this, an
agent that finds an auth bypass but doesn't know the app's actual routes
is reduced to guessing endpoint names one `http_request` at a time — this
turns that into a proper recon step instead.
"""

from __future__ import annotations

from typing import Any

from app.models.schemas import ToolResult
from app.tools.base import Tool, ToolSpec
from app.tools.container_exec import ContainerExecError, exec_in_container

COMMON_PATHS = [
    "/",
    "/login",
    "/logout",
    "/admin",
    "/admin/",
    "/admin/login",
    "/admin/users",
    "/admin/customers",
    "/api",
    "/api/users",
    "/api/customers",
    "/users",
    "/customers",
    "/export",
    "/dashboard",
    "/data",
    "/db",
    "/config",
    "/health",
    "/status",
    "/backup",
]


class DiscoverPathsTool(Tool):
    def __init__(self, docker_client, attacker_container_name: str, timeout_s: int = 5) -> None:
        self.docker_client = docker_client
        self.attacker_container_name = attacker_container_name
        self.timeout_s = timeout_s
        self.spec = ToolSpec(
            name="discover_paths",
            description=(
                "Probe a wordlist of common paths against a base URL and report "
                "which ones respond with something other than 404 (content "
                "discovery, like gobuster/ffuf). Use this instead of guessing "
                "endpoint names one http_request at a time."
            ),
            parameters={
                "type": "object",
                "properties": {
                    "base_url": {
                        "type": "string",
                        "description": "e.g. http://web:8080 — no trailing path",
                    },
                },
                "required": ["base_url"],
            },
        )

    def run(self, **kwargs: Any) -> ToolResult:
        base_url: str = kwargs["base_url"].rstrip("/")

        found: list[tuple[str, str]] = []
        for path in COMMON_PATHS:
            argv = [
                "curl",
                "-s",
                "-o",
                "/dev/null",
                "-w",
                "%{http_code}",
                "--max-time",
                str(self.timeout_s),
                f"{base_url}{path}",
            ]
            try:
                exit_code, output = exec_in_container(self.docker_client, self.attacker_container_name, argv)
            except ContainerExecError as exc:
                return ToolResult(ok=False, output="", error=str(exc))

            status = output.strip()
            if exit_code == 0 and status not in ("404", "000"):
                found.append((path, status))

        summary = (
            "\n".join(f"{status} {path}" for path, status in found)
            if found
            else "No non-404 paths found among the common wordlist"
        )
        return ToolResult(ok=True, output=summary)
