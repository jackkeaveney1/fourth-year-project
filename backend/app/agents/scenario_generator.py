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
