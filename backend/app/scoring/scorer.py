"""Deterministic post-hardening scoring.

Kept separate from the blue-team agent's qualitative advice on purpose:
the number a student is graded on should not depend on LLM output, only
on checks the scenario engine / inspection tools can verify directly.
The blue-team agent's commentary is presented alongside this scorecard,
not folded into it.
"""

from __future__ import annotations

from dataclasses import dataclass

from app.models.schemas import ScoreCard, ScoreEntry


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
