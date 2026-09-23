"""Turns a raw red-team trajectory into a plain-English attack report:
what was tried, what worked, what didn't, whether the target was actually
breached, and what to fix.

This is deterministic, not a second LLM call — the trajectory already
contains every tool call and its observation, so the outcome of each
attempt can be read straight off the tool's own response text instead of
asking a model to re-summarize it (cheaper, faster, and never hallucinates
a step that didn't happen).
"""

from __future__ import annotations

import re

from app.models.schemas import AttackAttempt, AttackReport, Scenario, TrajectoryStep

_HTTP_STATUS_RE = re.compile(r"HTTP (\d{3})")


def _target_for(step: TrajectoryStep) -> str | None:
    if step.tool_call is None:
        return None
    args = step.tool_call.arguments
    if "url" in args:
        return str(args["url"])
    if "base_url" in args:
        return str(args["base_url"])
    if "host" in args:
        return str(args["host"])
    if "container" in args:
        return f"{args['container']}:{args.get('path', '')}"
    if "command" in args:
        return str(args["command"])
    return None


def _describe(step: TrajectoryStep) -> str:
    assert step.tool_call is not None
    target = _target_for(step)
    return f"{step.tool_call.name}({target})" if target else step.tool_call.name


def _classify(step: TrajectoryStep) -> tuple[str, str]:
    """Returns (outcome, detail) for one tool-calling trajectory step."""
    assert step.tool_call is not None
    observation = step.observation or ""

    if observation.startswith("BLOCKED:"):
        return "blocked", observation
    if observation.startswith("ERROR:"):
        return "failed", observation

    name = step.tool_call.name
    if name == "try_credentials":
        return ("succeeded" if observation.startswith("Success after") else "failed"), observation
    if name == "discover_paths":
        return (
            "failed" if "No non-404 paths found" in observation else "succeeded"
        ), observation
    if name == "scan_ports":
        return ("failed" if "No open ports found" in observation else "succeeded"), observation
    if name == "http_request":
        match = _HTTP_STATUS_RE.search(observation)
        if match and match.group(1)[0] in "45":
            return "failed", observation
        return "succeeded", observation
    # run_shell, extract_records, and anything else: the tool ran and
    # returned a real result (no ERROR/BLOCKED prefix), count it as progress.
    return "succeeded", observation


def build_attack_report(
    trajectory: list[TrajectoryStep],
    goal_achieved: bool,
    scenario: Scenario,
    vulnerabilities_exploited: list[str],
) -> AttackReport:
    attempts: list[AttackAttempt] = []
    for step in trajectory:
        if step.tool_call is None:
            continue
        outcome, detail = _classify(step)
        attempts.append(
            AttackAttempt(
                step=step.step,
                action=_describe(step),
                target=_target_for(step),
                outcome=outcome,  # type: ignore[arg-type]
                detail=detail[:300],
            )
        )

    succeeded = [a for a in attempts if a.outcome == "succeeded"]
    failed = [a for a in attempts if a.outcome == "failed"]
    blocked = [a for a in attempts if a.outcome == "blocked"]

    exploited_ids = set(vulnerabilities_exploited)
    exploited_vulns = [
        v for s in scenario.services for v in s.vulnerabilities if v.id in exploited_ids
    ]
    # No confirmed exploit this run still means every seeded weakness is a
    # real gap — surface all of them rather than an empty recommendations list.
    source_vulns = exploited_vulns or [v for s in scenario.services for v in s.vulnerabilities]

    recommendations: list[str] = []
    seen: set[str] = set()
    for vuln in source_vulns:
        for fix in vuln.remediation:
            if fix not in seen:
                seen.add(fix)
                recommendations.append(fix)

    if goal_achieved:
        summary = (
            f'The agent breached the target — objective achieved: "{scenario.objective}". '
            f"{len(succeeded)} of {len(attempts)} actions succeeded"
            + (f", {len(failed)} failed" if failed else "")
            + (f", {len(blocked)} blocked by guardrails" if blocked else "")
            + "."
        )
    elif attempts:
        summary = (
            f'The agent did NOT breach the target — objective not achieved: "{scenario.objective}". '
            f"{len(succeeded)} of {len(attempts)} actions succeeded, {len(failed)} failed"
            + (f", {len(blocked)} blocked by guardrails" if blocked else "")
            + " before the step budget ran out."
        )
    else:
        summary = "The agent took no actions before concluding — treat this run as inconclusive, not as a pass."

    return AttackReport(
        breached=goal_achieved,
        summary=summary,
        attempts=attempts,
        successful_attempts=succeeded,
        failed_attempts=failed,
        blocked_attempts=blocked,
        recommendations=recommendations,
    )
