"""Tests for the container sandbox path.

The container path has its own failure modes — the flags, the mount
syntax, the user namespaces, the tmpfs ownership — and none of them show
up until a container runtime is present. These tests run against whatever
runtime is available and skip when there is none.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from verdis.config import Config
from verdis.pipeline.orchestrator import Orchestrator
from verdis.sandbox.base import (
    Mount,
    SandboxBackend,
    SandboxLimits,
    SandboxProfile,
    SandboxRequest,
    default_profile,
)
from verdis.sandbox.container import build_container_args
from verdis.storage.db import Store
from verdis.storage.evidence import EvidenceStore

pytestmark = pytest.mark.slow


def _container_backend() -> SandboxBackend | None:
    from verdis.build.builder import DEFAULT_IMAGE

    for factory in (
        "verdis.sandbox.podman:PodmanBackend",
        "verdis.sandbox.docker:DockerBackend",
    ):
        module_name, class_name = factory.split(":")
        try:
            module = __import__(module_name, fromlist=[class_name])
            backend = getattr(module, class_name)()
        except Exception:  # pragma: no cover - optional dependency
            continue
        # A runtime that lacks the images these tests run is left out.
        if backend.available() and not backend.missing_images(
            ("python:3.12-alpine", DEFAULT_IMAGE)
        ):
            return backend
    return None


CONTAINER = _container_backend()
needs_container = pytest.mark.skipif(
    CONTAINER is None, reason="no container runtime available"
)


class TestRuntimeVocabulary:
    """Podman and Docker do not share a vocabulary for every flag."""

    def test_the_user_namespace_flag_is_translated(self) -> None:
        for runtime in ("podman", "docker"):
            args = build_container_args(
                SandboxRequest(image="alpine", command=["true"]), runtime
            )
            assert "--userns" in args
            mode = args[args.index("--userns") + 1]
            if runtime == "podman":
                assert mode == "keep-id"
            else:
                assert mode in {"host", "private"}

    def test_the_seccomp_flag_is_translated(self) -> None:
        # Neither runtime accepts a seccomp name: both want a path, and
        # both apply their own default profile when the option is absent.
        for runtime in ("podman", "docker"):
            args = build_container_args(
                SandboxRequest(image="alpine", command=["true"]), runtime
            )
            assert not any("seccomp=" in arg for arg in args)

    def test_the_builtin_profile_is_named_only_where_it_exists(self) -> None:
        profile = SandboxProfile(seccomp="builtin")
        podman = build_container_args(
            SandboxRequest(image="alpine", command=["true"], profile=profile), "podman"
        )
        docker = build_container_args(
            SandboxRequest(image="alpine", command=["true"], profile=profile), "docker"
        )
        assert not any("seccomp=" in arg for arg in podman)
        assert "seccomp=builtin" in docker

    def test_a_custom_seccomp_profile_is_a_path(self) -> None:
        for runtime in ("podman", "docker"):
            profile = SandboxProfile(seccomp="/etc/seccomp/verdis.json")
            args = build_container_args(
                SandboxRequest(image="alpine", command=["true"], profile=profile), runtime
            )
            assert "seccomp=/etc/seccomp/verdis.json" in args

    def test_the_mount_uses_the_key_value_syntax(self) -> None:
        args = build_container_args(
            SandboxRequest(
                image="alpine",
                command=["true"],
                mounts=[Mount(source="/host", target="/src", readonly=True)],
            ),
            "docker",
        )
        mounts = [args[i + 1] for i, arg in enumerate(args) if arg == "--mount"]
        assert mounts == ["type=bind,source=/host,target=/src,readonly"]

    def test_the_scratch_is_not_the_working_directory(self) -> None:
        # A tmpfs on the same path as a bind mount would hide the mount.
        args = build_container_args(
            SandboxRequest(
                image="alpine",
                command=["true"],
                workdir="/src",
                scratch="/work",
                mounts=[Mount(source="/host", target="/src", readonly=True)],
            ),
            "docker",
        )
        tmpfs = [args[i + 1] for i, arg in enumerate(args) if arg == "--tmpfs"]
        assert any(entry.startswith("/work:") for entry in tmpfs)
        assert not any(entry.startswith("/src:") for entry in tmpfs)


@needs_container
class TestContainerRuns:
    def test_a_command_runs(self, tmp_path: Path) -> None:
        request = SandboxRequest(
            image="python:3.12-alpine",
            command=["python", "-c", "print('hello from the sandbox')"],
            workdir="/work",
            scratch="/work",
            limits=SandboxLimits(timeout_s=60),
            profile=default_profile(),
        )
        result = CONTAINER.run(request)
        assert result.exit_code == 0
        assert "hello from the sandbox" in result.stdout

    def test_the_workdir_is_writable_by_the_unprivileged_user(self, tmp_path: Path) -> None:
        request = SandboxRequest(
            image="python:3.12-alpine",
            command=["python", "-c", "open('probe.txt','w').write('x'); print('wrote')"],
            workdir="/work",
            scratch="/work",
            limits=SandboxLimits(timeout_s=60),
            profile=default_profile(),
        )
        result = CONTAINER.run(request)
        assert result.exit_code == 0
        assert "wrote" in result.stdout

    def test_the_network_is_translated_per_runtime(self) -> None:
        from verdis.sandbox.base import SandboxProfile
        from verdis.sandbox.container import _network_args

        profile = SandboxProfile(network="mirror")
        # Podman 5 and later use pasta; Docker names its bridge.
        assert _network_args(profile, "podman") == ["--network", "pasta"]
        assert _network_args(profile, "docker") == ["--network", "bridge"]

    def test_the_source_is_read_only(self, tmp_path: Path) -> None:
        source = tmp_path / "src"
        source.mkdir()
        (source / "keep.txt").write_text("data", encoding="utf-8")
        request = SandboxRequest(
            image="python:3.12-alpine",
            command=["python", "-c", "open('/src/keep.txt','w').write('x')"],
            workdir="/src",
            scratch="/work",
            mounts=[Mount(source=str(source), target="/src", readonly=True)],
            limits=SandboxLimits(timeout_s=60),
            profile=default_profile(),
        )
        result = CONTAINER.run(request)
        assert result.exit_code != 0
        assert (source / "keep.txt").read_text(encoding="utf-8") == "data"

    def test_the_image_digest_is_recorded(self) -> None:
        request = SandboxRequest(
            image="python:3.12-alpine",
            command=["python", "-c", "pass"],
            workdir="/work",
            scratch="/work",
            limits=SandboxLimits(timeout_s=60),
            profile=default_profile(),
        )
        result = CONTAINER.run(request)
        assert result.image_digest
        assert result.image_digest.startswith("sha256:")


@needs_container
class TestWorkDirectory:
    def test_the_scratch_lands_in_the_work_directory(self, tmp_path: Path) -> None:
        work = tmp_path / "work"
        work.mkdir()
        config = Config(sandbox="default", work_dir=str(work))
        orchestrator = Orchestrator(
            config=config,
            store=Store(tmp_path / "store"),
            evidence=EvidenceStore(tmp_path / "evidence"),
            backend=CONTAINER,
        )
        assert orchestrator._work_root() == work
        scratch = orchestrator._temp_dir("probe-")
        assert work in scratch.parents
