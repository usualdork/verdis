"""Docker backend (rootless Docker, or rootful Docker with the same flags)."""

from __future__ import annotations

from .container import ContainerBackend, resolve_binary

__all__ = ["DockerBackend"]


class DockerBackend(ContainerBackend):
    """Docker with the same hardening flags as the Podman backend."""

    runtime = "docker"
    name = "docker"

    def __init__(self, binary: str | None = None) -> None:
        super().__init__(binary or resolve_binary(("docker",)))

    def _unused(self) -> None:  # pragma: no cover
        raise NotImplementedError
