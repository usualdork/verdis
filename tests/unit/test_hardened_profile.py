"""Tests for the hardened profile and the isolation the run actually had."""

from __future__ import annotations

import subprocess

from verdis.sandbox.base import (
    SandboxRequest,
    default_profile,
    hardened_profile,
)
from verdis.sandbox.container import ContainerBackend, build_container_args


class _Concrete(ContainerBackend):
    runtime = "fake"
    name = "fake"

    def _unused(self) -> None:  # pragma: no cover - the abstract marker
        raise NotImplementedError


class TestHardenedProfile:
    def test_it_asks_for_gvisor(self) -> None:
        assert hardened_profile().runtime == "runsc"

    def test_the_default_profile_does_not(self) -> None:
        assert default_profile().runtime == ""

    def test_the_build_stage_gets_no_network_of_its_own(self) -> None:
        assert hardened_profile().allow_host_network_in_build is False

    def test_docker_is_asked_for_the_runtime(self) -> None:
        request = SandboxRequest(
            image="alpine",
            command=["true"],
            profile=hardened_profile(),
        )
        args = build_container_args(request, "docker")
        assert args[args.index("--runtime") + 1] == "runsc"

    def test_podman_is_not_asked_for_a_runtime_it_cannot_select(self) -> None:
        # Podman chooses its runtime per machine, not per container, and
        # there is no flag for it. Asking would make the run fail.
        request = SandboxRequest(
            image="alpine",
            command=["true"],
            profile=hardened_profile(),
        )
        args = build_container_args(request, "podman")
        assert "--runtime" not in args

    def test_the_default_profile_asks_for_no_runtime(self) -> None:
        request = SandboxRequest(image="alpine", command=["true"])
        args = build_container_args(request, "podman")
        assert "--runtime" not in args


class TestIsolationInUse:
    def test_the_isolation_is_the_one_the_host_used(self, monkeypatch) -> None:
        backend = _Concrete(binary="fake")
        monkeypatch.setattr(
            backend, "_read_oci_runtime", lambda: "runsc", raising=False
        )
        assert backend._isolation_in_use(hardened_profile()) == "runsc"

    def test_a_different_runtime_is_admitted(self, monkeypatch) -> None:
        backend = _Concrete(binary="fake")
        monkeypatch.setattr(
            backend, "_read_oci_runtime", lambda: "crun", raising=False
        )
        isolation = backend._isolation_in_use(hardened_profile())
        assert "the host used crun" in isolation

    def test_a_missing_runtime_is_admitted(self, monkeypatch) -> None:
        backend = _Concrete(binary="fake")
        monkeypatch.setattr(
            backend, "_read_oci_runtime", lambda: "", raising=False
        )
        isolation = backend._isolation_in_use(hardened_profile())
        assert "without runsc" in isolation

    def test_the_default_profile_is_recorded(self) -> None:
        backend = _Concrete(binary="fake")
        assert backend._isolation_in_use(default_profile()) == "default"

    def test_a_runtime_that_cannot_be_queried(self, monkeypatch) -> None:
        import verdis.sandbox.container as container_module

        backend = _Concrete(binary="fake")

        def broken(*args, **kwargs):
            raise OSError("no runtime")

        monkeypatch.setattr(container_module.subprocess, "run", broken)
        assert backend._runtime_available("runsc") is False

    def test_a_runtime_that_answers(self, monkeypatch) -> None:
        import verdis.sandbox.container as container_module

        def handler(*args, **kwargs):
            return subprocess.CompletedProcess(
                args, 0, "crun\n", ""
            )

        monkeypatch.setattr(container_module.subprocess, "run", handler)
        backend = _Concrete(binary="fake")
        assert backend._runtime_available("crun") is True
        assert not backend._runtime_available("runsc")

    def test_a_runtime_that_fails(self, monkeypatch) -> None:
        import verdis.sandbox.container as container_module

        def handler(*args, **kwargs):
            return subprocess.CompletedProcess(args, 1, "", "no")

        monkeypatch.setattr(container_module.subprocess, "run", handler)
        backend = _Concrete(binary="fake")
        assert backend._runtime_available("runsc") is False


class TestTheOciRuntimeIsRead:
    """The isolation is what the host actually used."""

    def test_a_runtime_that_cannot_be_queried_is_unknown(self, monkeypatch) -> None:
        import subprocess as _subprocess

        backend = _Concrete(binary="fake")

        def broken(*args, **kwargs):
            raise _subprocess.TimeoutExpired(cmd="podman", timeout=1)

        monkeypatch.setattr(
            "verdis.sandbox.container.subprocess.run", broken
        )
        assert backend._read_oci_runtime() == ""

    def test_a_runtime_that_fails_is_unknown(self, monkeypatch) -> None:
        import subprocess as _subprocess

        backend = _Concrete(binary="fake")

        def failing(*args, **kwargs):
            return _subprocess.CompletedProcess(args, 1, "", "no")

        monkeypatch.setattr(
            "verdis.sandbox.container.subprocess.run", failing
        )
        assert backend._read_oci_runtime() == ""
