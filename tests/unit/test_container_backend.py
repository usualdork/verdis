"""Tests for the container backend's plumbing.

The backend talks to a runtime through a command line, so the tests drive
it with a stand-in binary and check what it asks the runtime to do.
"""

from __future__ import annotations

import json
import stat
import subprocess
from pathlib import Path

from verdis.sandbox.base import (
    SandboxProfile,
)
from verdis.sandbox.container import (
    ContainerBackend,
    _seccomp_args,
    _userns_args,
    mount_for,
    resolve_binary,
)


class _FakeRuntime:
    """A stand-in for a container runtime.

    It records what it was asked to do and answers with a scripted
    response.
    """

    def __init__(self, directory: Path, responses: dict[str, tuple[int, str]] | None = None) -> None:
        self.directory = directory
        self.responses = responses or {}
        self.calls: list[list[str]] = []
        script = directory / "fake-runtime"
        script.write_text(
            "#!/bin/sh\n"
            'printf "%s\\n" "$@" >> ' + str(directory / "calls.log") + "\n"
            'case "$1" in\n'
            '  version) echo "29.5.2" ;;\n'
            '  info) echo \'{"SecurityOptions": ["name=seccomp,profile=builtin", '
            '"name=apparmor"]}\' ;;\n'
            '  image) echo "sha256:deadbeef" ;;\n'
            '  run) exit 0 ;;\n'
            'esac\n'
            "exit 0\n",
            encoding="utf-8",
        )
        script.chmod(script.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)

    def calls_log(self) -> list[str]:
        path = self.directory / "calls.log"
        if not path.is_file():
            return []
        return path.read_text(encoding="utf-8").splitlines()


class TestUsernsTranslation:
    def test_podman_keeps_its_own_vocabulary(self) -> None:
        profile = SandboxProfile(userns="keep-id")
        assert _userns_args(profile, "podman") == ["--userns", "keep-id"]

    def test_docker_gets_its_own_vocabulary(self) -> None:
        profile = SandboxProfile(userns="keep-id")
        assert _userns_args(profile, "docker") == ["--userns", "host"]

    def test_a_private_namespace_is_understood_by_both(self) -> None:
        profile = SandboxProfile(userns="private")
        assert _userns_args(profile, "podman") == ["--userns", "private"]
        assert _userns_args(profile, "docker") == ["--userns", "private"]

    def test_no_namespace_means_no_flag(self) -> None:
        profile = SandboxProfile(userns="none")
        assert _userns_args(profile, "podman") == []
        assert _userns_args(profile, "docker") == []

    def test_an_unknown_mode_falls_back_to_the_default(self) -> None:
        profile = SandboxProfile(userns="something-else")
        assert _userns_args(profile, "docker") == ["--userns", "host"]


class TestSeccompTranslation:
    def test_the_default_profile_is_left_to_the_runtime(self) -> None:
        profile = SandboxProfile(seccomp="default")
        assert _seccomp_args(profile, "podman") == []
        assert _seccomp_args(profile, "docker") == []

    def test_no_profile_means_no_flag(self) -> None:
        profile = SandboxProfile(seccomp="none")
        assert _seccomp_args(profile, "podman") == []

    def test_the_builtin_profile_is_named_only_where_it_exists(self) -> None:
        profile = SandboxProfile(seccomp="builtin")
        assert _seccomp_args(profile, "podman") == []
        assert _seccomp_args(profile, "docker") == ["--security-opt", "seccomp=builtin"]

    def test_a_path_is_passed_through(self) -> None:
        profile = SandboxProfile(seccomp="/etc/seccomp/verdis.json")
        for runtime in ("podman", "docker"):
            assert _seccomp_args(profile, runtime) == [
                "--security-opt",
                "seccomp=/etc/seccomp/verdis.json",
            ]


class _Concrete(ContainerBackend):
    """A backend that talks to whatever binary it is given."""

    runtime = "fake"
    name = "fake"

    def _unused(self) -> None:  # pragma: no cover - the abstract marker
        raise NotImplementedError


class TestRuntimeInteraction:
    def _backend(self, tmp_path: Path) -> ContainerBackend:
        runtime = _FakeRuntime(tmp_path)
        backend = _Concrete(binary=str(runtime.directory / "fake-runtime"))
        backend._available = None
        return backend

    def test_the_runtime_is_found(self, tmp_path: Path) -> None:
        backend = self._backend(tmp_path)
        assert backend.available()

    def test_a_missing_binary_is_reported(self, tmp_path: Path) -> None:
        backend = _Concrete(binary=str(tmp_path / "not-there"))
        assert not backend.available()
        assert "not on PATH" in backend.doctor()[0]

    def test_the_server_version_is_read(self, tmp_path: Path, monkeypatch) -> None:
        backend = self._backend(tmp_path)
        monkeypatch.setattr(
            "verdis.sandbox.container.shutil.which", lambda name: "/fake"
        )
        assert backend.server_version() == "29.5.2"
        assert backend.available()

    def test_the_availability_is_cached(self, tmp_path: Path, monkeypatch) -> None:
        backend = self._backend(tmp_path)
        monkeypatch.setattr(
            "verdis.sandbox.container.shutil.which", lambda name: "/fake"
        )
        assert backend.available()
        # The second call is answered from the cache.
        backend.server_version = lambda: ""  # type: ignore[method-assign]
        assert backend.available()

    def test_the_availability_can_be_refreshed(self, tmp_path: Path, monkeypatch) -> None:
        backend = self._backend(tmp_path)
        monkeypatch.setattr(
            "verdis.sandbox.container.shutil.which", lambda name: "/fake"
        )
        assert backend.available()
        backend.server_version = lambda: ""  # type: ignore[method-assign]
        assert not backend.available(refresh=True)

    def test_the_isolation_notes_are_read(self, tmp_path: Path, monkeypatch) -> None:
        backend = self._backend(tmp_path)
        monkeypatch.setattr(
            "verdis.sandbox.container.shutil.which", lambda name: "/fake"
        )
        notes = backend.doctor()
        assert any("seccomp" in note for note in notes)
        assert any("apparmor" in note for note in notes)
        assert any("rootful" in note for note in notes)

    def test_a_podman_style_info_is_read(self, tmp_path: Path, monkeypatch) -> None:
        backend = self._backend(tmp_path)
        monkeypatch.setattr(
            "verdis.sandbox.container.shutil.which", lambda name: "/fake"
        )
        monkeypatch.setattr(
            "verdis.sandbox.container.subprocess.run",
            lambda *args, **kwargs: subprocess.CompletedProcess(
                args=args,
                returncode=0,
                stdout=json.dumps({"host": {"security": {"rootless": True}}}),
                stderr="",
            ),
        )
        notes = backend.doctor()
        assert any("rootless" in note for note in notes)

    def test_a_runtime_that_is_not_running_is_reported(
        self, tmp_path: Path, monkeypatch
    ) -> None:
        backend = self._backend(tmp_path)
        monkeypatch.setattr(
            "verdis.sandbox.container.shutil.which", lambda name: "/fake"
        )
        monkeypatch.setattr(
            "verdis.sandbox.container.subprocess.run",
            lambda *args, **kwargs: subprocess.CompletedProcess(
                args=args, returncode=1, stdout="", stderr="cannot connect"
            ),
        )
        notes = backend.doctor()
        assert any("not responding" in note for note in notes)

    def test_the_image_digest_is_read(self, tmp_path: Path, monkeypatch) -> None:
        backend = self._backend(tmp_path)
        monkeypatch.setattr(
            "verdis.sandbox.container.shutil.which", lambda name: "/fake"
        )
        assert backend._image_digest("python:3.12") == "sha256:deadbeef"

    def test_a_pinned_image_is_its_own_digest(self, tmp_path: Path) -> None:
        backend = self._backend(tmp_path)
        assert backend._image_digest("x@sha256:abc") == "abc"

    def test_an_unknown_image_has_no_digest(self, tmp_path: Path, monkeypatch) -> None:
        backend = self._backend(tmp_path)
        monkeypatch.setattr(
            "verdis.sandbox.container.subprocess.run",
            lambda *args, **kwargs: subprocess.CompletedProcess(
                args=args, returncode=1, stdout="", stderr="no such image"
            ),
        )
        assert backend._image_digest("nope:1") == ""

    def test_a_missing_image_is_reported(self, tmp_path: Path, monkeypatch) -> None:
        backend = self._backend(tmp_path)
        monkeypatch.setattr(
            "verdis.sandbox.container.subprocess.run",
            lambda *args, **kwargs: subprocess.CompletedProcess(
                args=args, returncode=1, stdout="", stderr="no such image"
            ),
        )
        assert backend.image_present("nope:1") is False

    def test_a_present_image_is_not_reported(self, tmp_path: Path, monkeypatch) -> None:
        backend = self._backend(tmp_path)
        monkeypatch.setattr(
            "verdis.sandbox.container.shutil.which", lambda name: "/fake"
        )
        assert backend.image_present("python:3.12") is True

    def test_an_empty_image_is_always_present(self, tmp_path: Path) -> None:
        backend = self._backend(tmp_path)
        assert backend.image_present("") is True

    def test_the_missing_images_are_listed(self, tmp_path: Path, monkeypatch) -> None:
        backend = self._backend(tmp_path)
        monkeypatch.setattr(
            "verdis.sandbox.container.subprocess.run",
            lambda *args, **kwargs: subprocess.CompletedProcess(
                args=args, returncode=1, stdout="", stderr="no such image"
            ),
        )
        assert backend.missing_images(("a:1", "b:2")) == ["a:1", "b:2"]


class TestHelpers:
    def test_a_binary_on_the_path_is_resolved(self) -> None:
        assert resolve_binary(("sh",)) == "sh"

    def test_an_absent_binary_falls_back_to_the_first(self) -> None:
        assert (
            resolve_binary(("definitely-not-here", "also-not-here"))
            == "definitely-not-here"
        )

    def test_a_mount_is_built(self, tmp_path: Path) -> None:
        mount = mount_for(tmp_path, "/src", readonly=True)
        assert mount.source == str(tmp_path)
        assert mount.target == "/src"
        assert mount.readonly is True
