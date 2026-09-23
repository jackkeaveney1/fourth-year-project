from app.models.schemas import Difficulty, Role, Scenario, ScenarioService, ToolCall, TrajectoryStep, Vulnerability
from app.scoring.scorer import PostureCheck, compute_scorecard, derive_posture


def _scenario(vuln_ids: list[str]) -> Scenario:
    return Scenario(
        id="easy-test",
        title="Test scenario",
        difficulty=Difficulty.EASY,
        objective="Exfiltrate the customer database",
        services=[
            ScenarioService(
                name="web",
                image="cyber-range/web-vuln:latest",
                internal_hostname="web",
                vulnerabilities=[
                    Vulnerability(id=vid, name=vid, description=vid) for vid in vuln_ids
                ],
            )
        ],
        compose_path="targets/generated/easy-test/docker-compose.yml",
    )


def _scan_step(step: int, host: str, ports: list[int]) -> TrajectoryStep:
    return TrajectoryStep(
        step=step,
        role=Role.RED,
        thought="scanning",
        tool_call=ToolCall(name="scan_ports", arguments={"host": host}),
        observation=f"Open ports on {host}: {ports}",
    )


def test_full_hardening_scores_max_points():
    posture = PostureCheck(
        red_team_still_compromised_goal=False,
        database_encrypted_at_rest=True,
        firewall_correctly_configured=True,
        password_policy_enforced=True,
        https_enabled=True,
        unused_ports_closed=True,
    )
    card = compute_scorecard(posture)
    assert card.total_points == card.max_points == 55
    assert card.percentage == 100.0


def test_still_compromised_applies_penalty_and_floors_at_zero():
    posture = PostureCheck(
        red_team_still_compromised_goal=True,
        database_encrypted_at_rest=False,
        firewall_correctly_configured=False,
        password_policy_enforced=False,
        https_enabled=False,
        unused_ports_closed=False,
    )
    card = compute_scorecard(posture)
    assert card.total_points == 0  # -20 floored at 0
    assert card.max_points == 55


def test_partial_hardening_matches_doc_example():
    posture = PostureCheck(
        red_team_still_compromised_goal=False,
        database_encrypted_at_rest=True,
        firewall_correctly_configured=True,
        password_policy_enforced=True,
        https_enabled=True,
        unused_ports_closed=False,
    )
    card = compute_scorecard(posture)
    assert card.total_points == 50
    assert card.max_points == 55


def test_derive_posture_reflects_unmitigated_vulnerabilities():
    scenario = _scenario(["unencrypted_db", "weak_creds"])
    posture = derive_posture(scenario, goal_achieved=True, red_trajectory=[])
    assert posture.red_team_still_compromised_goal is True
    assert posture.database_encrypted_at_rest is False
    assert posture.password_policy_enforced is False
    assert posture.https_enabled is False
    assert posture.firewall_correctly_configured is True  # always true: range network is internal-only


def test_derive_posture_credits_absent_vulnerabilities():
    scenario = _scenario([])  # no declared weak-creds/unencrypted-db vulns
    posture = derive_posture(scenario, goal_achieved=False, red_trajectory=[])
    assert posture.red_team_still_compromised_goal is False
    assert posture.database_encrypted_at_rest is True
    assert posture.password_policy_enforced is True


def test_derive_posture_flags_unused_open_ports_from_recon():
    scenario = _scenario([])
    trajectory = [_scan_step(1, "web", [8080, 22, 3306])]
    posture = derive_posture(scenario, goal_achieved=False, red_trajectory=trajectory)
    assert posture.unused_ports_closed is False


def test_derive_posture_credits_minimal_open_ports():
    scenario = _scenario([])
    trajectory = [_scan_step(1, "web", [8080])]
    posture = derive_posture(scenario, goal_achieved=False, red_trajectory=trajectory)
    assert posture.unused_ports_closed is True
