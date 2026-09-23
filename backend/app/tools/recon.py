"""Reconnaissance tools: TCP connect-scan against the target range only."""

from __future__ import annotations

from typing import Any

from app.models.schemas import ToolResult
from app.tools.base import Tool, ToolSpec
from app.tools.container_exec import ContainerExecError, exec_in_container

COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3306, 5432, 6379, 8080]


class ScanPortsTool(Tool):
    """Connect-scan a host from inside the attacker container.

    Uses `nc -z` (already in the agent-runtime image) rather than shelling
    out from the orchestrator's own process: the range network is
    internal-only, so only the attacker container — which is actually
    attached to it — can resolve or reach range hostnames at all.
    """

    def __init__(self, docker_client, attacker_container_name: str, timeout_s: float = 1.0) -> None:
        self.docker_client = docker_client
        self.attacker_container_name = attacker_container_name
        self.timeout_s = timeout_s
        self.spec = ToolSpec(
            name="scan_ports",
            description="TCP connect-scan a host inside the target range and report which common ports are open.",
            parameters={
                "type": "object",
                "properties": {
                    "host": {"type": "string", "description": "Hostname or IP within the target subnet"},
                    "ports": {
                        "type": "array",
                        "items": {"type": "integer"},
                        "description": "Ports to check; defaults to a common-service list",
                    },
                },
                "required": ["host"],
            },
        )

    def run(self, **kwargs: Any) -> ToolResult:
        host: str = kwargs["host"]
        ports: list[int] = kwargs.get("ports") or COMMON_PORTS

        open_ports: list[int] = []
        for port in ports:
            argv = ["nc", "-z", "-w", str(max(1, int(self.timeout_s))), host, str(port)]
            try:
                exit_code, _ = exec_in_container(self.docker_client, self.attacker_container_name, argv)
            except ContainerExecError as exc:
                return ToolResult(ok=False, output="", error=str(exc))
            if exit_code == 0:
                open_ports.append(port)

        summary = f"Open ports on {host}: {open_ports}" if open_ports else f"No open ports found on {host}"
        return ToolResult(ok=True, output=summary)
