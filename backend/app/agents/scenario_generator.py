"""Scenario-generator agent: designs a range from a difficulty + objective.

Implemented as a deterministic, catalog-driven generator (not a raw LLM
call) so scenario generation is unit-testable and reproducible without an
API key. An LLM can still be layered on top later to write the flavour
text / objective narrative — the structural decisions (topology, which
vulnerabilities, in what order) stay rule-based on purpose, per the "what
stays deterministic" design principle in the project doc.
"""

from __future__ import annotations

import random
import uuid
from dataclasses import dataclass
from typing import Literal

from app.models.schemas import Difficulty, Scenario, ScenarioService, Vulnerability

VULN_SQLI_LOGIN = Vulnerability(
    id="sqli_login",
    name="SQL Injection on /login",
    description="The login form concatenates user input directly into a SQL query.",
    cwe="CWE-89",
    remediation=["Parameterized queries", "Prepared statements", "WAF rule for SQLi payloads"],
)

VULN_WEAK_CREDS = Vulnerability(
    id="weak_creds",
    name="Default/weak admin credentials",
    description="The admin account uses a common default password with no lockout policy.",
    cwe="CWE-521",
    remediation=["Strong password policy", "Account lockout", "Multi-factor authentication"],
)

VULN_UNENCRYPTED_DB = Vulnerability(
    id="unencrypted_db",
    name="Database not encrypted at rest",
    description="Customer records are stored in plaintext columns with no encryption at rest.",
    cwe="CWE-311",
    remediation=["Encrypt sensitive columns at rest", "Restrict DB network access to app tier only"],
)

VULN_OPEN_INTERNAL_PORT = Vulnerability(
    id="open_internal_port",
    name="Unnecessary internal service exposure",
    description="An internal file-sharing service is reachable from the web tier with no auth.",
    cwe="CWE-284",
    remediation=["Network segmentation", "Close unused ports", "Require auth on internal services"],
)

VULNERABILITY_CATALOG: dict[str, Vulnerability] = {
    v.id: v
    for v in (VULN_SQLI_LOGIN, VULN_WEAK_CREDS, VULN_UNENCRYPTED_DB, VULN_OPEN_INTERNAL_PORT)
}
"""Every vulnerability a scenario can be built from — shared with the custom
scenario builder (`build_custom_scenario`) so the API can validate and label
user-picked vulnerability ids against the same catalog the templates use."""

WEB_VULN_IMAGE = "cyber-range/web-vuln:latest"
DB_IMAGE = "postgres:16-alpine"
"""The engine's docker-compose template (scenario_engine/templates/docker-compose.yml.j2)
only special-cases services literally named "web" (gets SUCCESS_MARKER + DB_HOST env,
making it the goal-checkable entry point) and "db" (gets Postgres credentials) — every
other service just runs WEB_VULN_IMAGE with no extra config, exactly like the
"employee_pc"/"fileserver" hops in the built-in hard/expert templates. A custom scenario
must follow the same convention to actually be attackable/goal-checkable."""


@dataclass(frozen=True)
class TopologyTemplate:
    difficulty: Difficulty
    objective: str
    build_services: "list[ServiceBlueprint]"


@dataclass(frozen=True)
class ServiceBlueprint:
    name: str
    image: str
    internal_hostname: str
    vulnerabilities: list[Vulnerability]
    exposed_to: list[str]


TEMPLATES: dict[Difficulty, TopologyTemplate] = {
    Difficulty.EASY: TopologyTemplate(
        difficulty=Difficulty.EASY,
        objective="Exfiltrate the customer database",
        build_services=[
            ServiceBlueprint("web", "cyber-range/web-vuln:latest", "web", [VULN_SQLI_LOGIN], ["internet"]),
            ServiceBlueprint("db", "postgres:16-alpine", "db", [VULN_UNENCRYPTED_DB], ["web"]),
        ],
    ),
    Difficulty.MEDIUM: TopologyTemplate(
        difficulty=Difficulty.MEDIUM,
        objective="Exfiltrate the customer database using valid admin credentials",
        build_services=[
            ServiceBlueprint(
                "web", "cyber-range/web-vuln:latest", "web", [VULN_SQLI_LOGIN, VULN_WEAK_CREDS], ["internet"]
            ),
            ServiceBlueprint("db", "postgres:16-alpine", "db", [VULN_UNENCRYPTED_DB], ["web"]),
        ],
    ),
    Difficulty.HARD: TopologyTemplate(
        difficulty=Difficulty.HARD,
        objective="Pivot from the web tier to the internal file server and exfiltrate its contents",
        build_services=[
            ServiceBlueprint(
                "web", "cyber-range/web-vuln:latest", "web", [VULN_SQLI_LOGIN, VULN_WEAK_CREDS], ["internet"]
            ),
            ServiceBlueprint("db", "postgres:16-alpine", "db", [VULN_UNENCRYPTED_DB], ["web"]),
            ServiceBlueprint(
                "fileserver", "cyber-range/web-vuln:latest", "fileserver", [VULN_OPEN_INTERNAL_PORT], ["web"]
            ),
        ],
    ),
    Difficulty.EXPERT: TopologyTemplate(
        difficulty=Difficulty.EXPERT,
        objective="Compromise the employee workstation and pivot to exfiltrate the file server",
        build_services=[
            ServiceBlueprint(
                "web", "cyber-range/web-vuln:latest", "web", [VULN_SQLI_LOGIN, VULN_WEAK_CREDS], ["internet"]
            ),
            ServiceBlueprint("db", "postgres:16-alpine", "db", [VULN_UNENCRYPTED_DB], ["web"]),
            ServiceBlueprint(
                "employee_pc", "cyber-range/web-vuln:latest", "employee_pc", [VULN_WEAK_CREDS], ["web"]
            ),
            ServiceBlueprint(
                "fileserver",
                "cyber-range/web-vuln:latest",
                "fileserver",
                [VULN_OPEN_INTERNAL_PORT],
                ["employee_pc"],
            ),
        ],
    ),
}


def generate_scenario(difficulty: Difficulty, seed: int | None = None) -> Scenario:
    """Pick a topology for the given difficulty and instantiate a concrete scenario.

    `seed` only affects cosmetic choices (scenario id, per-run success
    marker) — the structural topology per difficulty is fixed, which is
    what makes cross-run comparisons at a given difficulty meaningful.
    """
    rng = random.Random(seed)
    template = TEMPLATES[difficulty]
    scenario_id = f"{difficulty.value}-{uuid.UUID(int=rng.getrandbits(128))}"

    services = [
        ScenarioService(
            name=bp.name,
            image=bp.image,
            internal_hostname=bp.internal_hostname,
            vulnerabilities=bp.vulnerabilities,
            exposed_to=bp.exposed_to,
        )
        for bp in template.build_services
    ]

    return Scenario(
        id=scenario_id,
        title=f"{difficulty.value.title()} range: {template.objective}",
        difficulty=difficulty,
        objective=template.objective,
        services=services,
        compose_path=f"targets/generated/{scenario_id}/docker-compose.yml",
    )


class CustomScenarioError(ValueError):
    """A user-submitted custom scenario failed validation."""


@dataclass(frozen=True)
class CustomServiceInput:
    name: str
    role: Literal["web", "db", "internal"]
    """"web" and "db" are forced to those exact compose service names (see
    WEB_VULN_IMAGE/DB_IMAGE docstring above) — "internal" keeps the given name
    and is just another WEB_VULN_IMAGE hop, like "employee_pc"/"fileserver"."""
    vulnerability_ids: list[str]
    exposed_to: list[str]


def build_custom_scenario(
    title: str, objective: str, services: list[CustomServiceInput]
) -> Scenario:
    """Build a Scenario from user-picked services/vulnerabilities/topology.

    Deliberately reuses the exact same building blocks (VULNERABILITY_CATALOG,
    WEB_VULN_IMAGE, DB_IMAGE) and "web"/"db" naming convention as the built-in
    difficulty templates, so a custom scenario is fully goal-checkable and
    scoreable through the same, unmodified engine/orchestrator/scoring code —
    no new attack surface (no arbitrary images or compose content).
    """
    if not services:
        raise CustomScenarioError("A scenario needs at least one service")

    web_services = [s for s in services if s.role == "web"]
    if len(web_services) != 1:
        raise CustomScenarioError(
            "Exactly one service must have role='web' — it's the entry point "
            "that receives the goal-check success marker"
        )
    db_services = [s for s in services if s.role == "db"]
    if len(db_services) > 1:
        raise CustomScenarioError("At most one service may have role='db'")

    resolved_names: list[str] = []
    for s in services:
        forced_name = {"web": "web", "db": "db"}.get(s.role, s.name.strip())
        if not forced_name:
            raise CustomScenarioError(f"Service with role '{s.role}' needs a non-empty name")
        if s.role == "internal" and forced_name in {"web", "db"}:
            raise CustomScenarioError(
                f"'{forced_name}' is reserved for the web/db roles — pick a different name"
            )
        resolved_names.append(forced_name)
    if len(resolved_names) != len(set(resolved_names)):
        raise CustomScenarioError("Service names must be unique")

    valid_names = set(resolved_names)
    scenario_services: list[ScenarioService] = []
    for s, name in zip(services, resolved_names):
        unknown_vulns = set(s.vulnerability_ids) - VULNERABILITY_CATALOG.keys()
        if unknown_vulns:
            raise CustomScenarioError(f"Unknown vulnerability id(s): {sorted(unknown_vulns)}")
        unknown_edges = set(s.exposed_to) - valid_names - {"internet"}
        if unknown_edges:
            raise CustomScenarioError(
                f"'{name}' is exposed_to unknown service(s): {sorted(unknown_edges)}"
            )
        scenario_services.append(
            ScenarioService(
                name=name,
                image=DB_IMAGE if s.role == "db" else WEB_VULN_IMAGE,
                internal_hostname=name,
                vulnerabilities=[VULNERABILITY_CATALOG[v] for v in s.vulnerability_ids],
                exposed_to=s.exposed_to,
            )
        )

    scenario_id = f"custom-{uuid.uuid4().hex}"
    return Scenario(
        id=scenario_id,
        title=title.strip() or "Custom range",
        difficulty=Difficulty.EXPERT,
        objective=objective.strip() or "Compromise the target and achieve the stated goal",
        services=scenario_services,
        compose_path=f"targets/generated/{scenario_id}/docker-compose.yml",
    )


def build_imported_scenario(
    title: str,
    objective: str,
    image: str,
    app_port: int = 8080,
    include_db: bool = False,
) -> Scenario:
    """Build a Scenario whose `web` entry point is a user-imported image.

    The imported image takes the exact role the built-in `web-vuln` image has:
    it's the service named "web", so the compose template injects the per-run
    `SUCCESS_MARKER` (and DB_* env) into it, and goal-checking/scoring run
    through the same unmodified path. For a win to be detectable the imported
    app must read `SUCCESS_MARKER` from its environment and surface it somewhere
    only reachable once compromised — that's the same contract the built-in
    target follows (see targets/web-vuln/app.py).

    `vulnerabilities` is left empty: we don't know the imported app's specific
    weaknesses, and scoring already degrades gracefully to network-level facts
    when the catalog vulns are absent (see scoring.derive_posture).
    """
    services = [
        ScenarioService(
            name="web",
            image=image,
            internal_hostname="web",
            vulnerabilities=[],
            exposed_to=["internet"],
        )
    ]
    if include_db:
        services.append(
            ScenarioService(
                name="db",
                image=DB_IMAGE,
                internal_hostname="db",
                vulnerabilities=[],
                exposed_to=["web"],
            )
        )

    # The agent's default port scan covers 8080 but not every port; naming the
    # port in the objective lets it go straight there when the app listens
    # somewhere non-standard, without touching the orchestrator's briefing.
    port_hint = f" The target web app listens on port {app_port}."
    scenario_id = f"imported-{uuid.uuid4().hex}"
    return Scenario(
        id=scenario_id,
        title=title.strip() or "Imported range",
        difficulty=Difficulty.EXPERT,
        objective=(objective.strip() or "Compromise the imported target and exfiltrate its secret")
        + port_hint,
        services=services,
        compose_path=f"targets/generated/{scenario_id}/docker-compose.yml",
    )
