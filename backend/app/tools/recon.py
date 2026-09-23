"""Reconnaissance tools: TCP connect-scan against the target range only."""

from __future__ import annotations

import ipaddress
import socket
from typing import Any

from app.models.schemas import ToolResult
from app.tools.base import Tool, ToolSpec

COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3306, 5432, 6379, 8080]


class ScanPortsTool(Tool):
    """Connect-scan a host within the range's subnet.

    Deliberately implemented as a plain TCP connect scan rather than
    shelling out to nmap: it needs no extra binary in the agent's
    container image, and its behaviour (and blast radius) is easy to
    reason about for the guardrail review.
    """

    def __init__(self, allowed_subnet: ipaddress.IPv4Network, timeout_s: float = 0.5) -> None:
        self.allowed_subnet = allowed_subnet
        self.timeout_s = timeout_s
        self.spec = ToolSpec(
            name="scan_ports",
            description=(
                "TCP connect-scan a host inside the target range's subnet "
                "and report which common ports are open."
            ),
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

        try:
            resolved = socket.gethostbyname(host)
            addr = ipaddress.ip_address(resolved)
        except (socket.gaierror, ValueError) as exc:
            return ToolResult(ok=False, output="", error=f"Could not resolve '{host}': {exc}")

        if addr not in self.allowed_subnet:
            return ToolResult(
                ok=False,
                output="",
                error=f"Refused: {resolved} is outside the target subnet {self.allowed_subnet}",
            )

        open_ports: list[int] = []
        for port in ports:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(self.timeout_s)
                if sock.connect_ex((resolved, port)) == 0:
                    open_ports.append(port)

        summary = f"Open ports on {host} ({resolved}): {open_ports}" if open_ports else f"No open ports found on {host} ({resolved})"
        return ToolResult(ok=True, output=summary)
