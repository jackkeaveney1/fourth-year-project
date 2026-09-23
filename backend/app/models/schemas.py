"""Shared data contracts between the scenario engine, agents, and API layer."""

from __future__ import annotations

from datetime import UTC, datetime
from enum import Enum
from typing import Any, Literal

from pydantic import BaseModel, Field


class Difficulty(str, Enum):
    EASY = "easy"
    MEDIUM = "medium"
    HARD = "hard"
    EXPERT = "expert"


class RunStatus(str, Enum):
    PENDING = "pending"
    PROVISIONING = "provisioning"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    KILLED = "killed"
    TORN_DOWN = "torn_down"


class Role(str, Enum):
    RED = "red"
    BLUE = "blue"
    GENERATOR = "generator"


class ToolCall(BaseModel):
    """A single tool invocation an agent chose to make."""

    name: str
    arguments: dict[str, Any] = Field(default_factory=dict)


class ToolResult(BaseModel):
    ok: bool
    output: str
    error: str | None = None


class TrajectoryStep(BaseModel):
    """One iteration of the agent's reason -> act -> observe loop."""

    step: int
    role: Role
    thought: str
    tool_call: ToolCall | None = None
    observation: str | None = None
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))


class Vulnerability(BaseModel):
    id: str
    name: str
    description: str
    cwe: str | None = None
    remediation: list[str] = Field(default_factory=list)


class ScenarioService(BaseModel):
    name: str
    image: str
    internal_hostname: str
    vulnerabilities: list[Vulnerability] = Field(default_factory=list)
    exposed_to: list[str] = Field(default_factory=list)
    """Names of other services this one is reachable from (defines topology edges)."""


class Scenario(BaseModel):
    id: str
    title: str
    difficulty: Difficulty
    objective: str
    """The goal statement handed to the red-team agent, e.g. 'Exfiltrate the customer database'."""
    services: list[ScenarioService]
    compose_path: str
    """Path to the rendered docker-compose file for this scenario instance."""


class ScoreEntry(BaseModel):
    label: str
    points: int
    achieved: bool


class ScoreCard(BaseModel):
    entries: list[ScoreEntry]
    total_points: int
    max_points: int

    @property
    def percentage(self) -> float:
        if self.max_points == 0:
            return 0.0
        return round(100 * self.total_points / self.max_points, 1)


class AttackAttempt(BaseModel):
    """One tool-calling step from the red-team trajectory, reframed as an
    attack action with a plain success/failure/blocked verdict."""

    step: int
    action: str
    """Human-readable action, e.g. 'try_credentials(http://web:8080/login)'."""
    target: str | None = None
    outcome: Literal["succeeded", "failed", "blocked"]
    detail: str
    """Short excerpt of the observation explaining the outcome."""


class AttackReport(BaseModel):
    """A narrative summary of the red-team run: what was tried, what worked,
    what didn't, whether the objective was ultimately breached, and how the
    target could be hardened against what was seen."""

    breached: bool
    summary: str
    attempts: list[AttackAttempt]
    successful_attempts: list[AttackAttempt]
    failed_attempts: list[AttackAttempt]
    blocked_attempts: list[AttackAttempt]
    recommendations: list[str]


class RunReport(BaseModel):
    run_id: str
    scenario_id: str
    status: RunStatus
    objective: str
    goal_achieved: bool
    trajectory: list[TrajectoryStep]
    vulnerabilities_exploited: list[str]
    privilege_escalation: bool
    detected_by_blue_team: bool
    time_to_compromise_seconds: float | None
    agent_step_count: int
    started_at: datetime
    ended_at: datetime | None = None
    scorecard: ScoreCard | None = None
    blue_team_trajectory: list[TrajectoryStep] = Field(default_factory=list)
    blue_team_summary: str | None = None
    """The blue-team agent's final assessment thought, surfaced separately for a quick read."""
    blue_team_error: str | None = None
    """Set when the blue-team assessment stopped early on an LLM/tool error rather than
    reaching a real conclusion (e.g. a provider rate limit) — kept separate from
    `blue_team_summary` so a crash message is never mistaken for a genuine finding."""
    attack_report: AttackReport | None = None


class LaunchRunRequest(BaseModel):
    scenario_id: str
    mode: Literal["agentic", "scripted_baseline"] = "agentic"
    max_steps: int = Field(default=40, ge=1, le=200)
    max_cost_usd: float = Field(default=1.0, gt=0)
