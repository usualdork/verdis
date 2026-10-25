"""Rootless Podman backend (the default runtime of PRD 11.2)."""

from __future__ import annotations

from .base import SandboxBackend
from .container import ContainerBackend, resolve_binary

__all__ = ["PodmanBackend"]


class PodmanBackend(ContainerBackend):
    """Podman, preferring rootless mode."""

    runtime = "podman"
    name = "podman"

    def __init__(self, binary: str | None = None) -> None:
        super().__init__(binary or resolve_binary(("podman", "podman-remote")))

    def _unused(self) -> None:  # pragma: no cover
        raise NotImplementedError


_ = SandboxBackend
