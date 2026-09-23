"""Deterministic infrastructure layer: turns a Scenario into running containers.

No LLM calls happen anywhere in this file, on purpose (see "What Stays
Deterministic" in the project design doc). It renders a docker-compose
file from the scenario, brings it up on an isolated internal network, and
tears it down again. Every run gets its own project name, subnet, and
random success marker so runs never collide and goal-checking never leaks
between them.
"""

from __future__ import annotations

import re
import secrets
import subprocess
import uuid
from dataclasses import dataclass
from pathlib import Path

from jinja2 import Environment, FileSystemLoader

from app.models.schemas import Scenario

TEMPLATES_DIR = Path(__file__).parent / "templates"
GENERATED_DIR = Path(__file__).resolve().parents[3] / "targets" / "generated"


class ProvisioningError(Exception):
    pass


@dataclass
class ProvisionedRange:
    run_id: str
    scenario_id: str
    compose_path: Path
    project_name: str
    attacker_container_name: str
    subnet_base: str
    success_marker: str


class ScenarioEngine:
    def __init__(self, templates_dir: Path = TEMPLATES_DIR, generated_dir: Path = GENERATED_DIR) -> None:
        self._env = Environment(loader=FileSystemLoader(str(templates_dir)), autoescape=False)
        self._generated_dir = generated_dir
        self._subnet_counter = 0

    def _next_subnet_base(self) -> str:
        # 172.30.<n>.0/24 -- stays well clear of common host/default-bridge ranges.
        # The in-memory counter alone isn't enough: a process restart resets
        # it to 1 even though a network from a previous run's failed
        # teardown might still hold that exact subnet, so cross-check
        # against what Docker actually has allocated right now.
        used = self._used_subnet_indices()
        for _ in range(200):
            self._subnet_counter = (self._subnet_counter % 200) + 1
            if self._subnet_counter not in used:
                return f"172.30.{self._subnet_counter}"
        raise ProvisioningError("No free 172.30.<n>.0/24 subnet available for a new range")

    @staticmethod
    def _used_subnet_indices() -> set[int]:
        try:
            ids = subprocess.run(
                ["docker", "network", "ls", "-q"], capture_output=True, text=True, timeout=15
            )
            if ids.returncode != 0:
                return set()
            network_ids = ids.stdout.split()
            if not network_ids:
                return set()
            inspected = subprocess.run(
                ["docker", "network", "inspect", "--format", "{{range .IPAM.Config}}{{.Subnet}} {{end}}", *network_ids],
                capture_output=True,
                text=True,
                timeout=15,
            )
        except (subprocess.SubprocessError, OSError):
            return set()

        indices = set()
        for match in re.finditer(r"172\.30\.(\d+)\.0/24", inspected.stdout):
            indices.add(int(match.group(1)))
        return indices

    def render_compose(self, scenario: Scenario, run_id: str) -> ProvisionedRange:
        template = self._env.get_template("docker-compose.yml.j2")
        success_marker = f"FLAG-{secrets.token_hex(8)}"
        subnet_base = self._next_subnet_base()

        rendered = template.render(
            run_id=run_id,
            scenario_id=scenario.id,
            services=scenario.services,
            subnet_base=subnet_base,
            success_marker=success_marker,
        )

        out_dir = self._generated_dir / run_id
        out_dir.mkdir(parents=True, exist_ok=True)
        compose_path = out_dir / "docker-compose.yml"
        compose_path.write_text(rendered)

        return ProvisionedRange(
            run_id=run_id,
            scenario_id=scenario.id,
            compose_path=compose_path,
            project_name=f"cyber-range-{run_id}",
            attacker_container_name=f"{run_id}-attacker",
            subnet_base=subnet_base,
            success_marker=success_marker,
        )

    def up(self, provisioned: ProvisionedRange) -> None:
        self._compose(provisioned, ["up", "-d", "--wait"])

    def down(self, provisioned: ProvisionedRange) -> None:
        self._compose(provisioned, ["down", "-v", "--remove-orphans"])

    def _compose(self, provisioned: ProvisionedRange, args: list[str]) -> None:
        cmd = [
            "docker",
            "compose",
            "-f",
            str(provisioned.compose_path),
            "-p",
            provisioned.project_name,
            *args,
        ]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
        if result.returncode != 0:
            raise ProvisioningError(
                f"`{' '.join(cmd)}` failed (exit {result.returncode}):\n{result.stderr}"
            )


def new_run_id() -> str:
    return uuid.uuid4().hex[:12]
