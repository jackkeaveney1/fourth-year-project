"""Builds a Docker image from a user-supplied build context (a folder with a
Dockerfile), so a scenario can target the user's *own* system instead of only
the built-in `web-vuln` image.

This is the one place the platform turns user-controlled content into a
runnable image. Two deliberate boundaries:

- The context is a **local directory path** the user names, holding a
  `Dockerfile` — we never fetch a remote URL or git repo here. Building it runs
  that Dockerfile's build-time `RUN` steps on the host Docker daemon, exactly
  as if the user ran `docker build` themselves; that's the trust model (a local
  dev/research tool operating the user's own Docker), and it's why there's no
  "build from arbitrary URL" affordance.
- At *run* time the built image is still confined like every other target: it
  joins the scenario's `internal: true`, no-egress network (see the compose
  template), so it can't reach the host or the internet once provisioned.
"""

from __future__ import annotations

import uuid
from pathlib import Path

import docker
from docker.errors import APIError, BuildError, DockerException


class ImageBuildError(Exception):
    """A user-supplied build context failed validation or `docker build`."""


def build_image_from_context(context_dir: str, docker_client: docker.DockerClient) -> str:
    """Validate a local build context and build it into a tagged image.

    Returns the image tag to hand to `build_imported_scenario`. Raises
    `ImageBuildError` (never a raw Docker exception) so the API can surface a
    clean 400 with the build log tail instead of a 500.
    """
    if not context_dir or not context_dir.strip():
        raise ImageBuildError("No build context path provided")

    path = Path(context_dir).expanduser()
    try:
        path = path.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise ImageBuildError(f"Path does not exist: {context_dir}") from exc

    if not path.is_dir():
        raise ImageBuildError(f"Not a directory: {path}")
    if not (path / "Dockerfile").is_file():
        raise ImageBuildError(
            f"No 'Dockerfile' found in {path} — point this at the folder that "
            "contains your app's Dockerfile"
        )

    tag = f"cyber-range/imported-{uuid.uuid4().hex[:12]}:latest"
    try:
        docker_client.images.build(path=str(path), tag=tag, rm=True, forcerm=True)
    except BuildError as exc:
        # BuildError carries the structured build log — surface its tail so the
        # user sees *why* their Dockerfile failed, not just that it did.
        tail = _build_log_tail(exc)
        raise ImageBuildError(f"docker build failed:\n{tail}") from exc
    except (APIError, DockerException) as exc:
        raise ImageBuildError(f"Docker error during build: {exc}") from exc

    return tag


def _build_log_tail(exc: BuildError, max_lines: int = 20) -> str:
    lines: list[str] = []
    try:
        for entry in exc.build_log:
            text = entry.get("stream") or entry.get("error") or ""
            text = text.strip()
            if text:
                lines.append(text)
    except (AttributeError, TypeError):
        return str(exc)
    return "\n".join(lines[-max_lines:]) or str(exc)
