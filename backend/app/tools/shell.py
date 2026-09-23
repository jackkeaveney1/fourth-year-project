"""Shell access inside the attacker's own sandboxed container.

This never touches the host or the target containers directly: the
orchestrator runs the agent itself inside a disposable "attacker" Docker
container on the range's internal network, and this tool execs commands
inside *that* container via the Docker SDK. A binary allowlist keeps the
blast radius small even if the agent is steered into misuse.
"""

from __future__ import annotations

import shlex
from typing import Any

import docker
from docker.errors import APIError, NotFound

from app.models.schemas import ToolResult
from app.tools.base import Tool, ToolSpec

ALLOWED_BINARIES = {"curl", "cat", "ls", "id", "whoami", "echo", "python3", "nc"}


class RunCommandTool(Tool):
    def __init__(self, docker_client: docker.DockerClient, attacker_container_name: str) -> None:
        self.docker_client = docker_client
        self.attacker_container_name = attacker_container_name
        self.spec = ToolSpec(
            name="run_shell",
            description=(
                "Run a shell command inside the attacker's own sandboxed "
                "container (not the target or the host)."
            ),
            parameters={
                "type": "object",
                "properties": {
                    "command": {"type": "string", "description": "Shell command to execute"},
                },
                "required": ["command"],
            },
        )

    def run(self, **kwargs: Any) -> ToolResult:
        command: str = kwargs["command"]

        try:
            argv = shlex.split(command)
        except ValueError as exc:
            return ToolResult(ok=False, output="", error=f"Could not parse command: {exc}")

        if not argv or argv[0] not in ALLOWED_BINARIES:
            return ToolResult(
                ok=False,
                output="",
                error=f"Binary '{argv[0] if argv else ''}' is not on the allowlist {sorted(ALLOWED_BINARIES)}",
            )

        try:
            container = self.docker_client.containers.get(self.attacker_container_name)
        except NotFound:
            return ToolResult(
                ok=False, output="", error=f"Attacker container '{self.attacker_container_name}' not running"
            )

        try:
            exit_code, output = container.exec_run(argv, demux=False)
        except APIError as exc:
            return ToolResult(ok=False, output="", error=f"Docker exec failed: {exc}")

        text = output.decode(errors="replace") if isinstance(output, bytes) else str(output)
        return ToolResult(ok=exit_code == 0, output=text)
