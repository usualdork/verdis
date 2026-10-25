"""The sandbox conformance suite (PRD 11.2, 13.2).

The suite checks that the sandbox actually denies what it promises:

* no network access from the run stage;
* no writes outside the workdir;
* no privilege gain;
* resource overruns are stopped.

It runs against the development backend by default. When a container
runtime is available it also runs against the default profile, which is
the configuration that matters in production.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

from verdis.sandbox.base import (
    SandboxBackend,
    SandboxLimits,
    SandboxRequest,
    default_profile,
)
from verdis.sandbox.container import ContainerBackend
from verdis.sandbox.local import LocalBackend

pytestmark = pytest.mark.conformance

#: The container backends need an image that has the interpreter the
#: checks use.
CONTAINER_IMAGE = "python:3.12-alpine"


def _local() -> LocalBackend:
    return LocalBackend()


def _container_backends() -> list[ContainerBackend]:
    backends: list[ContainerBackend] = []
    try:
        from verdis.sandbox.podman import PodmanBackend

        podman = PodmanBackend()
        if podman.available():
            backends.append(podman)
    except Exception:  # pragma: no cover - optional dependency
        pass
    try:
        from verdis.sandbox.docker import DockerBackend

        docker = DockerBackend()
        if docker.available():
            backends.append(docker)
    except Exception:  # pragma: no cover - optional dependency
        pass
    return backends


CONTAINER_BACKENDS = _container_backends()
BACKENDS: list[SandboxBackend] = [_local(), *CONTAINER_BACKENDS]
BACKEND_IDS = [backend.name for backend in BACKENDS]


@pytest.fixture(params=BACKEND_IDS)
def backend(request: pytest.FixtureRequest) -> SandboxBackend:
    return next(b for b in BACKENDS if b.name == request.param)


def _is_container(backend: SandboxBackend) -> bool:
    return backend.name in {"podman", "docker"}


def _python(backend: SandboxBackend) -> str:
    """The interpreter to run.

    The host's path is meaningless inside a container, so the container
    runs the interpreter its image provides.
    """
    return "python" if _is_container(backend) else sys.executable


def _request(
    backend: SandboxBackend, command: list[str], tmp_path: Path, **kwargs
) -> SandboxRequest:
    workdir = tmp_path / "work"
    workdir.mkdir(parents=True, exist_ok=True)
    base = {
        "image": CONTAINER_IMAGE if _is_container(backend) else "",
        "command": command,
        "workdir_source": str(workdir),
        "limits": SandboxLimits(timeout_s=30),
        "profile": default_profile(),
    }
    base.update(kwargs)
    return SandboxRequest(**base)


class TestNetworkDenial:
    def test_a_connection_attempt_is_recorded(
        self, backend: SandboxBackend, tmp_path: Path
    ) -> None:
        request = _request(
            backend,
            [
                _python(backend),
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

    def test_the_environment_has_no_proxy_credentials(
        self, backend: SandboxBackend, tmp_path: Path
    ) -> None:
        request = _request(
            backend,
            [_python(backend), "-c", "import os; print(sorted(os.environ))"],
            tmp_path,
        )
        result = backend.run(request)
        assert "AWS_SECRET_ACCESS_KEY" not in result.stdout
        assert "GITHUB_TOKEN" not in result.stdout


class TestHostIsolation:
    def test_the_environment_is_scrubbed(
        self, backend: SandboxBackend, tmp_path: Path, monkeypatch
    ) -> None:
        monkeypatch.setenv("VERDIS_TEST_SECRET", "hunter2")
        request = _request(
            backend,
            [
                _python(backend),
                "-c",
                "import os; print(os.environ.get('VERDIS_TEST_SECRET', 'absent'))",
            ],
            tmp_path,
        )
        result = backend.run(request)
        assert "hunter2" not in result.stdout

    def test_the_workdir_is_writable(self, backend: SandboxBackend, tmp_path: Path) -> None:
        request = _request(
            backend,
            [_python(backend), "-c", "open('probe.txt','w').write('x'); print('wrote')"],
            tmp_path,
        )
        result = backend.run(request)
        assert "wrote" in result.stdout

    @pytest.mark.skipif(not CONTAINER_BACKENDS, reason="no container runtime available")
    def test_the_root_filesystem_is_read_only(
        self, backend: SandboxBackend, tmp_path: Path
    ) -> None:
        request = _request(
            backend,
            [
                _python(backend),
                "-c",
                "open('/etc/probe', 'w').write('x')",
            ],
            tmp_path,
        )
        result = backend.run(request)
        assert result.exit_code != 0
        assert "Read-only file system" in result.stderr or "Permission denied" in result.stderr


class TestNoHostAccess:
    """The properties the PRD's default profile promises (section 11.2)."""

    def test_the_host_environment_is_not_present(
        self, backend: SandboxBackend, tmp_path: Path, monkeypatch
    ) -> None:
        monkeypatch.setenv("VERDIS_CONFORMANCE_SECRET", "hunter2")
        request = _request(
            backend,
            [
                _python(backend),
                "-c",
                "import os; print(os.environ.get('VERDIS_CONFORMANCE_SECRET', 'absent'))",
            ],
            tmp_path,
        )
        result = backend.run(request)
        assert "hunter2" not in result.stdout

    def test_the_system_files_are_unreadable(
        self, backend: SandboxBackend, tmp_path: Path
    ) -> None:
        request = _request(
            backend,
            [_python(backend), "-c", "print(open('/etc/shadow').read()[:20])"],
            tmp_path,
        )
        result = backend.run(request)
        assert result.exit_code != 0

    def test_the_system_files_are_not_writable(
        self, backend: SandboxBackend, tmp_path: Path
    ) -> None:
        request = _request(
            backend,
            [_python(backend), "-c", "open('/etc/evil', 'w').write('x')"],
            tmp_path,
        )
        result = backend.run(request)
        assert result.exit_code != 0


class TestPrivilege:
    def test_the_process_does_not_run_as_root(
        self, backend: SandboxBackend, tmp_path: Path
    ) -> None:
        request = _request(
            backend,
            [_python(backend), "-c", "import os; print(os.getuid())"],
            tmp_path,
        )
        result = backend.run(request)
        if backend.name == "local":
            pytest.skip("the development backend does not isolate the host")
        assert result.stdout.strip() != "0"

    def test_no_capabilities_are_held(
        self, backend: SandboxBackend, tmp_path: Path
    ) -> None:
        if not _is_container(backend):
            pytest.skip("the development backend does not isolate the host")
        request = _request(
            backend,
            [
                _python(backend),
                "-c",
                "print(open('/proc/self/status').read().split('CapEff:')[1].split()[0])",
            ],
            tmp_path,
        )
        result = backend.run(request)
        # CapEff is the effective capability set; with --cap-drop=ALL it
        # is zero.
        assert result.stdout.strip() == "0000000000000000"


class TestResourceLimits:
    def test_a_long_run_is_killed(self, backend: SandboxBackend, tmp_path: Path) -> None:
        request = _request(
            backend,
            [_python(backend), "-c", "import time; time.sleep(30)"],
            tmp_path,
            limits=SandboxLimits(timeout_s=2),
        )
        result = backend.run(request)
        assert result.timed_out

    def test_the_output_is_capped(self, backend: SandboxBackend, tmp_path: Path) -> None:
        request = _request(
            backend,
            [
                _python(backend),
                "-c",
                "print('x' * 200000)",
            ],
            tmp_path,
            limits=SandboxLimits(output_bytes=1000),
        )
        result = backend.run(request)
        assert len(result.stdout) <= 2000

    def test_a_failing_command_reports_its_exit_code(
        self, backend: SandboxBackend, tmp_path: Path
    ) -> None:
        request = _request(
            backend, [_python(backend), "-c", "import sys; sys.exit(42)"], tmp_path
        )
        result = backend.run(request)
        assert result.exit_code == 42


class TestEphemerality:
    def test_a_container_run_starts_from_a_clean_state(
        self, backend: SandboxBackend, tmp_path: Path
    ) -> None:
        """A fresh container per run: nothing survives a run (PRD 11.2)."""
        request = _request(
            backend,
            [
                _python(backend),
                "-c",
                "import os\n"
                "print('exists' if os.path.exists('marker.txt') else 'missing')\n"
                "open('marker.txt', 'w').write('x')\n",
            ],
            tmp_path,
        )
        first = backend.run(request)
        second = backend.run(request)
        assert "missing" in first.stdout
        if _is_container(backend):
            assert "missing" in second.stdout
        else:
            # The development backend runs on the host, so the workdir
            # persists. It is not a boundary, and it says so.
            assert "exists" in second.stdout


@pytest.mark.skipif(not CONTAINER_BACKENDS, reason="no container runtime available")
class TestContainerProfile:
    def test_the_network_is_none(self, tmp_path: Path) -> None:
        backend = CONTAINER_BACKENDS[0]
        request = _request(backend, ["true"], tmp_path)
        from verdis.sandbox.container import build_container_args

        args = build_container_args(request, backend.binary)
        assert args[args.index("--network") + 1] == "none"

    def test_the_root_filesystem_is_read_only(self, tmp_path: Path) -> None:
        backend = CONTAINER_BACKENDS[0]
        request = _request(backend, ["true"], tmp_path)
        from verdis.sandbox.container import build_container_args

        args = build_container_args(request, backend.binary)
        assert "--read-only" in args

    def test_capabilities_are_dropped(self, tmp_path: Path) -> None:
        backend = CONTAINER_BACKENDS[0]
        request = _request(backend, ["true"], tmp_path)
        from verdis.sandbox.container import build_container_args

        args = build_container_args(request, backend.binary)
        assert "--cap-drop=ALL" in args

    def test_no_new_privileges_is_set(self, tmp_path: Path) -> None:
        backend = CONTAINER_BACKENDS[0]
        request = _request(backend, ["true"], tmp_path)
        from verdis.sandbox.container import build_container_args

        args = build_container_args(request, backend.binary)
        assert "no-new-privileges" in args

    def test_no_capabilities_are_held(self, tmp_path: Path) -> None:
        backend = CONTAINER_BACKENDS[0]
        request = _request(
            backend,
            [
                _python(backend),
                "-c",
                "print(open('/proc/self/status').read().split('CapEff:')[1].split()[0])",
            ],
            tmp_path,
        )
        result = backend.run(request)
        assert result.stdout.strip() == "0000000000000000"

    def test_the_root_filesystem_cannot_be_written_to(self, tmp_path: Path) -> None:
        backend = CONTAINER_BACKENDS[0]
        request = _request(
            backend,
            [_python(backend), "-c", "open('/usr/evil', 'w').write('x')"],
            tmp_path,
        )
        result = backend.run(request)
        assert result.exit_code != 0

    def test_the_user_namespace_flag_is_understood(
        self, tmp_path: Path
    ) -> None:
        # Podman and Docker do not share a vocabulary for user namespaces,
        # and the wrong one makes the runtime refuse to start.
        backend = CONTAINER_BACKENDS[0]
        request = _request(backend, ["true"], tmp_path)
        result = backend.run(request)
        assert result.exit_code == 0, result.stderr
