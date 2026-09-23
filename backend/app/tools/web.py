"""HTTP tool: issue requests from inside the attacker container.

Runs via `curl` inside the attacker container (through `exec_in_container`)
rather than from the orchestrator's own process, for the same reason as
`recon.py`: the range network is internal-only, so only a process
actually attached to it can reach range hosts.
"""

from __future__ import annotations

import json
from typing import Any

from app.models.schemas import ToolResult
from app.tools.base import Tool, ToolSpec
from app.tools.container_exec import ContainerExecError, exec_in_container

MAX_RESPONSE_CHARS = 4000
STATUS_MARKER = "\n---HTTP_STATUS:"


def _coerce_object_arg(value: Any) -> dict[str, Any]:
    if isinstance(value, dict):
        return value
    if isinstance(value, str) and value.strip():
        try:
            parsed = json.loads(value)
        except json.JSONDecodeError:
            return {}
        return parsed if isinstance(parsed, dict) else {}
    return {}


class HttpRequestTool(Tool):
    def __init__(self, docker_client, attacker_container_name: str, timeout_s: int = 5) -> None:
        self.docker_client = docker_client
        self.attacker_container_name = attacker_container_name
        self.timeout_s = timeout_s
        self.spec = ToolSpec(
            name="http_request",
            description="Send an HTTP request to a service inside the target range.",
            parameters={
                "type": "object",
                "properties": {
                    "method": {"type": "string", "enum": ["GET", "POST", "PUT", "DELETE"]},
                    "url": {"type": "string", "description": "URL of an in-range service"},
                    "headers": {"type": "object"},
                    "data": {"type": "object", "description": "Form fields to send (application/x-www-form-urlencoded)"},
                },
                "required": ["method", "url"],
            },
        )

    def run(self, **kwargs: Any) -> ToolResult:
        method: str = kwargs["method"].upper()
        url: str = kwargs["url"]
        # Some models emit a JSON string for an object-typed parameter instead
        # of an actual object, despite the declared schema — tolerate that
        # rather than crashing the whole run on a malformed tool call.
        headers = _coerce_object_arg(kwargs.get("headers"))
        data = _coerce_object_arg(kwargs.get("data"))

        argv = [
            "curl",
            "-s",
            "-X",
            method,
            "--max-time",
            str(self.timeout_s),
            "-w",
            f"{STATUS_MARKER}%{{http_code}}",
        ]
        for key, value in (headers or {}).items():
            argv += ["-H", f"{key}: {value}"]
        for key, value in (data or {}).items():
            argv += ["--data-urlencode", f"{key}={value}"]
        argv.append(url)

        try:
            exit_code, output = exec_in_container(self.docker_client, self.attacker_container_name, argv)
        except ContainerExecError as exc:
            return ToolResult(ok=False, output="", error=str(exc))

        if exit_code != 0:
            return ToolResult(ok=False, output="", error=f"curl exited {exit_code}: {output[:500]}")

        body, _, status = output.partition(STATUS_MARKER)
        status_code = status.strip() or "?"
        summary = f"HTTP {status_code}\n{body[:MAX_RESPONSE_CHARS]}"
        # ok reflects whether the *request itself* completed, not whether the
        # status code was a "success" one — a 401/403/404 is information the
        # agent needs to see, not a tool failure to hide behind an error.
        return ToolResult(ok=True, output=summary)
