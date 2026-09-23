"""Deterministic post-hardening scoring.

Kept separate from the blue-team agent's qualitative advice on purpose:
the number a student is graded on should not depend on LLM output, only
on checks the scenario engine / inspection tools can verify directly.
The blue-team agent's commentary is presented alongside this scorecard,
not folded into it.
"""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass

from app.models.schemas import Scenario, ScoreCard, ScoreEntry, TrajectoryStep


@dataclass
class PostureCheck:
    """Boolean facts about the range's state after the student's hardening pass."""

    red_team_still_compromised_goal: bool
    database_encrypted_at_rest: bool
    firewall_correctly_configured: bool
    password_policy_enforced: bool
    https_enabled: bool
    unused_ports_closed: bool


SCORING_TABLE: list[tuple[str, int, str]] = [
    ("red_team_still_compromised_goal", -20, "Agent still compromised the objective"),
    ("database_encrypted_at_rest", 20, "Database encrypted at rest"),
    ("firewall_correctly_configured", 10, "Firewall correctly configured"),
    ("password_policy_enforced", 10, "Password policy enforced"),
    ("https_enabled", 10, "HTTPS enabled"),
    ("unused_ports_closed", 5, "Unused ports closed"),
]


def compute_scorecard(posture: PostureCheck) -> ScoreCard:
    entries: list[ScoreEntry] = []
    total = 0
    max_points = 0

    for field_name, points, label in SCORING_TABLE:
        achieved = bool(getattr(posture, field_name))
        entries.append(ScoreEntry(label=label, points=points, achieved=achieved))

        if points > 0:
            max_points += points
            if achieved:
                total += points
        else:
            # Penalty entries only subtract when triggered; they don't
            # inflate the achievable maximum.
            if achieved:
                total += points

    total = max(0, total)
    return ScoreCard(entries=entries, total_points=total, max_points=max_points)


_OPEN_PORTS_RE = re.compile(r"Open ports on \S+: (\[.*\])")


def derive_posture(scenario: Scenario, goal_achieved: bool, red_trajectory: list[TrajectoryStep]) -> PostureCheck:
    """Build a PostureCheck from facts we can actually verify, not guesses.

    There's no interactive "student hardens the range" step in this build
    (see README's next-steps list), so this reflects the range's state as
    provisioned — every check here is a real fact about the scenario
    definition or the range's own infrastructure, not a placeholder. Once a
    hardening step exists, `database_encrypted_at_rest` /
    `password_policy_enforced` should instead check the *post-hardening*
    config rather than the scenario's declared vulnerability list.
    """
    vuln_ids = {v.id for service in scenario.services for v in service.vulnerabilities}

    unused_ports_closed = True
    for step in red_trajectory:
        if step.tool_call is None or step.tool_call.name != "scan_ports" or step.observation is None:
            continue
        match = _OPEN_PORTS_RE.search(step.observation)
        if not match:
            continue
        try:
            ports = ast.literal_eval(match.group(1))
        except (ValueError, SyntaxError):
            continue
        if len(ports) > 1:
            unused_ports_closed = False
            break

    return PostureCheck(
        red_team_still_compromised_goal=goal_achieved,
        database_encrypted_at_rest="unencrypted_db" not in vuln_ids,
        # The range's network is provisioned `internal: true` for every run —
        # a real, always-enforced fact about this platform's own infra.
        firewall_correctly_configured=True,
        password_policy_enforced="weak_creds" not in vuln_ids,
        # The target app only ever serves plain HTTP — verifiably true.
        https_enabled=False,
        unused_ports_closed=unused_ports_closed,
    )
