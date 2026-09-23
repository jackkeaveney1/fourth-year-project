"""Safety guardrails for autonomous agent runs.

These are the enforcement points referenced in the project design doc:
step/cost budgets, a tool allowlist, network confinement, and a kill switch.
Every guardrail here fails closed: if a check cannot prove an action is safe,
the action is rejected.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from urllib.parse import urlparse


class GuardrailViolation(Exception):
    """Raised when an agent action would violate a safety guardrail."""


@dataclass
class StepBudget:
    max_steps: int
    steps_taken: int = 0

    def consume(self) -> None:
        if self.steps_taken >= self.max_steps:
            raise GuardrailViolation(
                f"Step budget exhausted ({self.steps_taken}/{self.max_steps})"
            )
        self.steps_taken += 1

    @property
    def remaining(self) -> int:
        return max(0, self.max_steps - self.steps_taken)


@dataclass
class CostBudget:
    max_cost_usd: float
    spent_usd: float = 0.0

    def charge(self, amount_usd: float) -> None:
        if self.spent_usd + amount_usd > self.max_cost_usd:
            raise GuardrailViolation(
                f"Cost budget exceeded (${self.spent_usd:.4f} + "
                f"${amount_usd:.4f} > ${self.max_cost_usd:.4f})"
            )
        self.spent_usd += amount_usd


@dataclass
class ToolAllowlist:
    """Restricts an agent to a fixed, named set of tools."""

    allowed: set[str] = field(default_factory=set)

    def check(self, tool_name: str) -> None:
        if tool_name not in self.allowed:
            raise GuardrailViolation(
                f"Tool '{tool_name}' is not in the allowlist {sorted(self.allowed)}"
            )


@dataclass
class NetworkAllowlist:
    """Confines outbound network actions to the target range's subnet.

    This is the core responsible-design control: an autonomous agent with
    HTTP/shell tools must never be able to reach anything outside the
    disposable target network, including the real internet.
    """

    allowed_subnet: ipaddress.IPv4Network | ipaddress.IPv6Network
    allowed_hostnames: set[str] = field(default_factory=set)

    def check_url(self, url: str) -> None:
        parsed = urlparse(url)
        host = parsed.hostname
        if host is None:
            raise GuardrailViolation(f"Could not parse host from URL: {url!r}")

        if host in self.allowed_hostnames:
            return

        try:
            addr = ipaddress.ip_address(host)
        except ValueError:
            raise GuardrailViolation(
                f"Host '{host}' is not an allowlisted in-range hostname and "
                "is not a literal IP that can be range-checked. Denying by default."
            ) from None

        if addr not in self.allowed_subnet:
            raise GuardrailViolation(
                f"Address {addr} is outside the target subnet "
                f"{self.allowed_subnet}. Egress denied."
            )


class KillSwitch:
    """Orchestrator-side flag an operator can raise to halt a run instantly."""

    def __init__(self) -> None:
        self._killed = False

    def trip(self) -> None:
        self._killed = True

    @property
    def is_tripped(self) -> bool:
        return self._killed

    def check(self) -> None:
        if self._killed:
            raise GuardrailViolation("Run was killed by the kill switch")


@dataclass
class RunGuardrails:
    """Bundles every guardrail a single agent run must pass through."""

    steps: StepBudget
    cost: CostBudget
    tools: ToolAllowlist
    network: NetworkAllowlist
    kill_switch: KillSwitch = field(default_factory=KillSwitch)

    def before_tool_call(self, tool_name: str, url: str | None = None) -> None:
        """Call before executing any agent tool call. Raises on violation."""
        self.kill_switch.check()
        self.steps.consume()
        self.tools.check(tool_name)
        if url is not None:
            self.network.check_url(url)
