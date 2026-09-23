from app.scoring.scorer import PostureCheck, compute_scorecard


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
