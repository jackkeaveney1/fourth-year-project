"""Defender-side tools: inspect live system state inside the target range.

Unlike the red-team tools, these are allowed to read configuration and
service state directly from the target containers — that's exactly what a
defender is meant to do. They still never leave the range: every call
takes a container name that must belong to the current scenario.
"""

from __future__ import annotations

import hashlib
from typing import Any

import docker
from docker.errors import APIError, NotFound

from app.models.schemas import ToolResult
from app.tools.base import Tool, ToolSpec

MAX_RESPONSE_CHARS = 2000


def _strip_noise(text: str) -> str:
    """Drop full-line comments and blank lines from a config file.

    Stock config files (postgresql.conf, pg_hba.conf, ...) are 90%+ comments
    — keeping them verbatim in the trajectory burns tokens on every
    subsequent LLM call for no signal, since the agent history resends the
    full tool output each turn.
    """
    lines = [
        line for line in text.splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]
    return "\n".join(lines)


class ReadConfigTool(Tool):
    def __init__(self, docker_client: docker.DockerClient, allowed_containers: set[str]) -> None:
        self.docker_client = docker_client
        self.allowed_containers = allowed_containers
        self.spec = ToolSpec(
            name="read_config",
            description="Read a configuration file from a service container in the current scenario.",
            parameters={
                "type": "object",
                "properties": {
                    "container": {"type": "string"},
                    "path": {"type": "string"},
                },
                "required": ["container", "path"],
            },
        )

    def run(self, **kwargs: Any) -> ToolResult:
        container_name: str = kwargs["container"]
        path: str = kwargs["path"]

        if container_name not in self.allowed_containers:
            return ToolResult(ok=False, output="", error=f"'{container_name}' is not part of this scenario")

        try:
            container = self.docker_client.containers.get(container_name)
            exit_code, output = container.exec_run(["cat", path])
        except (NotFound, APIError) as exc:
            return ToolResult(ok=False, output="", error=str(exc))

        text = output.decode(errors="replace") if isinstance(output, bytes) else str(output)
        stripped = _strip_noise(text)
        truncated = stripped[:MAX_RESPONSE_CHARS]
        if len(stripped) > MAX_RESPONSE_CHARS:
            truncated += f"\n...[truncated, {len(stripped) - MAX_RESPONSE_CHARS} more chars of non-comment lines]"
        return ToolResult(ok=exit_code == 0, output=truncated)


class ListServicesTool(Tool):
    def __init__(self, docker_client: docker.DockerClient, scenario_label: str) -> None:
        self.docker_client = docker_client
        self.scenario_label = scenario_label
        self.spec = ToolSpec(
            name="list_services",
            description="List running containers and exposed ports for the current scenario.",
            parameters={"type": "object", "properties": {}},
        )

    def run(self, **kwargs: Any) -> ToolResult:
        containers = self.docker_client.containers.list(
            filters={"label": f"cyber_range.scenario={self.scenario_label}"}
        )
        lines = [
            f"{c.name}: {c.status}, ports={list((c.attrs.get('NetworkSettings', {}).get('Ports') or {}).keys())}"
            for c in containers
        ]
        return ToolResult(ok=True, output="\n".join(lines) or "No containers found for this scenario")


class DiffBaselineTool(Tool):
    """Compares a live config file's hash against a known-hardened baseline."""

    def __init__(self, docker_client: docker.DockerClient, baselines: dict[str, str]) -> None:
        self.docker_client = docker_client
        self.baselines = baselines
        """Maps 'container:path' -> sha256 hex digest of the hardened reference file."""
        self.spec = ToolSpec(
            name="diff_baseline",
            description="Check whether a live config file matches the hardened baseline for this scenario.",
            parameters={
                "type": "object",
                "properties": {
                    "container": {"type": "string"},
                    "path": {"type": "string"},
                },
                "required": ["container", "path"],
            },
        )

    def run(self, **kwargs: Any) -> ToolResult:
        container_name: str = kwargs["container"]
        path: str = kwargs["path"]
        key = f"{container_name}:{path}"

        expected = self.baselines.get(key)
        if expected is None:
            return ToolResult(ok=False, output="", error=f"No baseline registered for {key}")

        try:
            container = self.docker_client.containers.get(container_name)
            exit_code, output = container.exec_run(["cat", path])
        except (NotFound, APIError) as exc:
            return ToolResult(ok=False, output="", error=str(exc))

        if exit_code != 0:
            return ToolResult(ok=False, output="", error=f"Could not read {path} in {container_name}")

        actual = hashlib.sha256(output).hexdigest()
        matches = actual == expected
        verdict = "matches hardened baseline" if matches else "DIFFERS from hardened baseline"
        return ToolResult(ok=True, output=f"{key}: {verdict}")
