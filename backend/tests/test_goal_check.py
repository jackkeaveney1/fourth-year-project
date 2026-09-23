from app.agents.goal_check import check_goal_achieved, check_privilege_escalation
from app.models.schemas import Role, ToolCall, TrajectoryStep


def _step(step, thought, observation=None, tool_name=None, args=None):
    return TrajectoryStep(
        step=step,
        role=Role.RED,
        thought=thought,
        tool_call=ToolCall(name=tool_name, arguments=args or {}) if tool_name else None,
        observation=observation,
    )


def test_goal_not_achieved_without_marker():
    trajectory = [_step(1, "scanning", observation="Open ports: [80]")]
    assert check_goal_achieved(trajectory, ["FLAG-abc123"]) is False


def test_goal_achieved_when_marker_appears_in_observation():
    trajectory = [
        _step(1, "scanning", observation="Open ports: [80]"),
        _step(2, "dumping table", observation="Row 1: FLAG-abc123, Row 2: ..."),
    ]
    assert check_goal_achieved(trajectory, ["FLAG-abc123"]) is True


def test_privilege_escalation_detected_from_observation():
    trajectory = [_step(1, "checking id", observation="uid=0(root) gid=0(root)")]
    assert check_privilege_escalation(trajectory) is True


def test_privilege_escalation_not_flagged_for_normal_run():
    trajectory = [_step(1, "logging in", observation="HTTP 200 Logged in as admin")]
    assert check_privilege_escalation(trajectory) is False
