from app.agents.scenario_generator import generate_scenario
from app.models.schemas import Difficulty


def test_easy_scenario_has_single_clear_path():
    scenario = generate_scenario(Difficulty.EASY, seed=1)
    assert scenario.difficulty == Difficulty.EASY
    assert len(scenario.services) == 2
    service_names = {s.name for s in scenario.services}
    assert service_names == {"web", "db"}


def test_expert_scenario_requires_pivoting_through_multiple_hosts():
    scenario = generate_scenario(Difficulty.EXPERT, seed=1)
    assert len(scenario.services) == 4
    fileserver = next(s for s in scenario.services if s.name == "fileserver")
    assert fileserver.exposed_to == ["employee_pc"]  # not reachable directly from web


def test_scenario_ids_differ_across_seeds():
    a = generate_scenario(Difficulty.EASY, seed=1)
    b = generate_scenario(Difficulty.EASY, seed=2)
    assert a.id != b.id


def test_difficulty_scales_vulnerability_count():
    easy = generate_scenario(Difficulty.EASY, seed=1)
    hard = generate_scenario(Difficulty.HARD, seed=1)
    easy_vulns = sum(len(s.vulnerabilities) for s in easy.services)
    hard_vulns = sum(len(s.vulnerabilities) for s in hard.services)
    assert hard_vulns > easy_vulns
