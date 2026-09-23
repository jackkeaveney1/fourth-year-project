import ipaddress

import pytest

from app.guardrails.policy import (
    CostBudget,
    GuardrailViolation,
    KillSwitch,
    NetworkAllowlist,
    RunGuardrails,
    StepBudget,
    ToolAllowlist,
)


def test_step_budget_exhausts():
    budget = StepBudget(max_steps=2)
    budget.consume()
    budget.consume()
    with pytest.raises(GuardrailViolation):
        budget.consume()


def test_cost_budget_rejects_overspend():
    budget = CostBudget(max_cost_usd=0.10)
    budget.charge(0.05)
    with pytest.raises(GuardrailViolation):
        budget.charge(0.10)


def test_tool_allowlist_blocks_unknown_tool():
    allowlist = ToolAllowlist(allowed={"scan_ports"})
    allowlist.check("scan_ports")
    with pytest.raises(GuardrailViolation):
        allowlist.check("run_shell")


def test_network_allowlist_blocks_external_ip():
    network = NetworkAllowlist(allowed_subnet=ipaddress.ip_network("172.30.5.0/24"))
    network.check_url("http://172.30.5.20/login")
    with pytest.raises(GuardrailViolation):
        network.check_url("http://8.8.8.8/")


def test_network_allowlist_denies_unresolvable_hostname_by_default():
    network = NetworkAllowlist(allowed_subnet=ipaddress.ip_network("172.30.5.0/24"))
    with pytest.raises(GuardrailViolation):
        network.check_url("http://evil.example.com/")


def test_network_allowlist_permits_known_in_range_hostname():
    network = NetworkAllowlist(
        allowed_subnet=ipaddress.ip_network("172.30.5.0/24"),
        allowed_hostnames={"web"},
    )
    network.check_url("http://web/login")


def test_kill_switch_stops_further_calls():
    switch = KillSwitch()
    switch.check()
    switch.trip()
    with pytest.raises(GuardrailViolation):
        switch.check()


def test_run_guardrails_before_tool_call_enforces_all_checks():
    guardrails = RunGuardrails(
        steps=StepBudget(max_steps=1),
        cost=CostBudget(max_cost_usd=1.0),
        tools=ToolAllowlist(allowed={"http_request"}),
        network=NetworkAllowlist(allowed_subnet=ipaddress.ip_network("172.30.5.0/24")),
    )
    guardrails.before_tool_call("http_request", url="http://172.30.5.20/login")

    with pytest.raises(GuardrailViolation):
        guardrails.before_tool_call("http_request", url="http://172.30.5.20/login")
