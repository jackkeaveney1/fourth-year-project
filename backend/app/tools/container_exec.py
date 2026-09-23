"""Shared helper: run a tool action inside the range's attacker container.

Recon/HTTP/credential tools must execute from *inside* the attacker
container, not from the orchestrator's own host process. The range's
Docker network is `internal: true` (no route out, including to the
host), so only a process actually attached to that network can resolve
service names like `web`/`db` or reach them at all — the host can't.

This is also the real safety boundary: confinement comes from the
Docker network topology itself (the attacker container has no route to
anything but the range), not from an app-level IP allowlist trying to
guess what a hostname will resolve to from a process that isn't even on
the network.
"""

from __future__ import annotations

import docker
from docker.errors import APIError, NotFound


class ContainerExecError(Exception):
    pass


def exec_in_container(
    docker_client: docker.DockerClient, container_name: str, argv: list[str]
) -> tuple[int, str]:
    try:
        container = docker_client.containers.get(container_name)
    except NotFound as exc:
        raise ContainerExecError(f"Container '{container_name}' not running") from exc

    try:
        exit_code, output = container.exec_run(argv, demux=False)
    except APIError as exc:
        raise ContainerExecError(f"Docker exec failed: {exc}") from exc

    text = output.decode(errors="replace") if isinstance(output, bytes) else str(output)
    return exit_code, text
