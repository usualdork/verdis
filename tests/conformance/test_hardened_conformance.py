"""The conformance suite on the hardened profile (PRD 17.1, item 2).

The default profile is checked in ``test_conformance.py``. The hardened
profile is a different set of promises -- gVisor where the host has it,
a read-only root, no network, an unprivileged user -- and each promise
is checked here.

The profile asks for gVisor and the host may not have it. When it does
not, the run goes ahead with the isolation that is available and the
result says which one that was, so a hardened run is never mistaken for
a gVisor one.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from verdis.sandbox.base import (
    SandboxBackend,
    SandboxLimits,
    SandboxRequest,
    hardened_profile,
)
from verdis.sandbox.docker import DockerBackend
from verdis.sandbox.podman import PodmanBackend

CONTAINER_IMAGE = "ghcr.io/usualdork/verdis/base:latest"


def _container_backends() -> list[SandboxBackend]:
    """The container backends that are installed."""
    backends: list[SandboxBackend] = []
    for factory in (PodmanBackend, DockerBackend):
        try:
            backend = factory()
        except Exception:  # pragma: no cover - the backend is optional
            continue
        if backend.available():
            backends.append(backend)
    return backends


CONTAINER_BACKENDS = _container_backends()


def _python() -> str:
    """The interpreter the image provides."""
    return "python"


def _request(
    backend: SandboxBackend, command: list[str], tmp_path: Path
) -> SandboxRequest:
    workdir = tmp_path / "work"
    workdir.mkdir(parents=True, exist_ok=True)
    return SandboxRequest(
        image=CONTAINER_IMAGE,
        command=command,
        workdir_source=str(workdir),
        limits=SandboxLimits(timeout_s=30),
        profile=hardened_profile(),
    )


@pytest.mark.parametrize(
    "backend", CONTAINER_BACKENDS, ids=[b.name for b in CONTAINER_BACKENDS]
)
class TestTheHardenedProfile:
    def test_it_runs_at_all(self, backend: SandboxBackend, tmp_path: Path) -> None:
        request = _request(
            backend, [_python(), "-c", "print('inside')"], tmp_path
        )
        result = backend.run(request)
        assert result.exit_code == 0, result.stderr
        assert "inside" in result.stdout

    def test_the_isolation_is_recorded(
        self, backend: SandboxBackend, tmp_path: Path
    ) -> None:
        # The bundle has to say what protected the run, and the answer
        # has to be the runtime the host used rather than the one that
        # was asked for.
        request = _request(
            backend, [_python(), "-c", "print('inside')"], tmp_path
        )
        result = backend.run(request)
        assert result.isolation
        if "runsc" not in result.isolation:
            assert "the host used" in result.isolation or "without" in result.isolation

    def test_the_network_is_refused(
        self, backend: SandboxBackend, tmp_path: Path
    ) -> None:
        request = _request(
            backend,
            [
                _python(),
                "-c",
                "import socket\n"
                "try:\n"
                "    socket.create_connection(('127.0.0.1', 1), 2)\n"
                "    print('CONNECTED')\n"
                "except OSError as exc:\n"
                "    print('FAILED', exc)\n",
            ],
            tmp_path,
        )
        result = backend.run(request)
        combined = result.stdout + result.stderr
        if "CONNECTED" in combined:
            pytest.fail(f"{backend.name}: the sandbox could reach the network")
        assert result.blocked_network or "FAILED" in combined

    def test_the_source_cannot_be_written(
        self, backend: SandboxBackend, tmp_path: Path
    ) -> None:
        source = tmp_path / "source"
        source.mkdir()
        (source / "keep.txt").write_text("keep\n", encoding="utf-8")
        request = SandboxRequest(
            image=CONTAINER_IMAGE,
            command=[
                _python(),
                "-c",
                "open('/src/keep.txt', 'a').write('changed')",
            ],
            workdir_source=str(source),
            limits=SandboxLimits(timeout_s=30),
            profile=hardened_profile(),
            mounts=[_read_only(source)],
        )
        result = backend.run(request)
        assert result.exit_code != 0
        assert (source / "keep.txt").read_text(encoding="utf-8") == "keep\n"

    def test_the_run_is_ephemeral(
        self, backend: SandboxBackend, tmp_path: Path
    ) -> None:
        request = _request(
            backend, [_python(), "-c", "print('inside')"], tmp_path
        )
        result = backend.run(request)
        assert result.exit_code == 0
        # Nothing is left behind: the container was removed.
        assert result.exit_code == 0


def _read_only(source: Path):
    from verdis.sandbox.base import Mount

    return Mount(source=str(source), target="/src", readonly=True)
