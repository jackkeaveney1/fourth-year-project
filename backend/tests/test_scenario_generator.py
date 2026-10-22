import pytest

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


def test_build_custom_scenario_forces_web_and_db_names():
    from app.agents.scenario_generator import CustomServiceInput, build_custom_scenario

    scenario = build_custom_scenario(
        title="My range",
        objective="Get the flag",
        services=[
            CustomServiceInput(name="entry", role="web", vulnerability_ids=["sqli_login"], exposed_to=["internet"]),
            CustomServiceInput(name="database", role="db", vulnerability_ids=[], exposed_to=["web"]),
            CustomServiceInput(name="fileserver", role="internal", vulnerability_ids=[], exposed_to=["web"]),
        ],
    )
    names = {s.name for s in scenario.services}
    assert names == {"web", "db", "fileserver"}


def test_build_custom_scenario_requires_exactly_one_web_service():
    from app.agents.scenario_generator import CustomScenarioError, CustomServiceInput, build_custom_scenario

    with pytest.raises(CustomScenarioError):
        build_custom_scenario(
            title="x",
            objective="y",
            services=[CustomServiceInput(name="a", role="internal", vulnerability_ids=[], exposed_to=[])],
        )


def test_build_custom_scenario_rejects_unknown_vulnerability_id():
    from app.agents.scenario_generator import CustomScenarioError, CustomServiceInput, build_custom_scenario

    with pytest.raises(CustomScenarioError):
        build_custom_scenario(
            title="x",
            objective="y",
            services=[CustomServiceInput(name="a", role="web", vulnerability_ids=["nope"], exposed_to=[])],
        )


def test_build_imported_scenario_uses_image_as_web_entry_point():
    from app.agents.scenario_generator import build_imported_scenario

    scenario = build_imported_scenario(
        title="My app",
        objective="Steal the secret",
        image="cyber-range/imported-abc123:latest",
    )
    web = next(s for s in scenario.services if s.name == "web")
    assert web.image == "cyber-range/imported-abc123:latest"
    assert web.exposed_to == ["internet"]
    assert web.vulnerabilities == []  # unknown app, no catalog vulns asserted
    assert scenario.id.startswith("imported-")
    # Only the web service by default (no db attached).
    assert {s.name for s in scenario.services} == {"web"}


def test_build_imported_scenario_appends_port_hint_and_optional_db():
    from app.agents.scenario_generator import build_imported_scenario

    scenario = build_imported_scenario(
        title="My app",
        objective="Steal the secret",
        image="cyber-range/imported-abc123:latest",
        app_port=3000,
        include_db=True,
    )
    assert "port 3000" in scenario.objective
    assert {s.name for s in scenario.services} == {"web", "db"}
    db = next(s for s in scenario.services if s.name == "db")
    assert db.exposed_to == ["web"]
