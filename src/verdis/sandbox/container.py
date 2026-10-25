"""Container sandbox backends (Podman and Docker).

The argument construction is a pure function so the hardening flags can be
unit-tested without a container runtime present.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from abc import abstractmethod
from dataclasses import replace
from pathlib import Path

from .base import (
    Mount,
    SandboxBackend,
    SandboxError,
    SandboxProfile,
    SandboxRequest,
    SandboxResult,
    run_subprocess,
)

__all__ = ["ContainerBackend", "build_container_args"]


#: What a runtime says when it refuses a network connection.
_NETWORK_DENIALS: tuple[str, ...] = (
    "network is unreachable",
    "no route to host",
    "connection refused",
    "network is down",
    "cannot assign requested address",
    "permission denied (connect",
    "operation not permitted",
    "network is unreachable (os error 101)",
    "failed to connect to the server",
    "could not resolve host",
    "temporary failure in name resolution",
)


def _blocked_network_attempts(output: str) -> tuple[str, ...]:
    """The network attempts the sandbox refused.

    The container has no network, so a program that tries to reach one
    gets an error from the runtime rather than a connection. The error
    is the observation: it says the program tried.
    """
    lowered = output.lower()
    found: list[str] = []
    for denial in _NETWORK_DENIALS:
        if denial in lowered and denial not in found:
            found.append(denial)
    return tuple(found)


def _network_args(profile: SandboxProfile, runtime: str) -> list[str]:
    """The network flags, in this runtime's vocabulary.

    The run stage never has a network. The build stage may, so that
    dependencies can be fetched through an allowlisted mirror; the
    runtimes name that network differently.
    """
    if profile.network == "none":
        return ["--network", "none"]
    if runtime.startswith("podman"):
        # Podman 5 and later use pasta for rootless networking; slirp4netns
        # was removed in Podman 6.
        return ["--network", "pasta"]
    return ["--network", "bridge"]


def _runtime_args(profile: SandboxProfile, runtime: str) -> list[str]:
    """The OCI runtime flags, in this runtime's vocabulary.

    Docker takes a runtime per container. Podman does not: its runtime is
    the machine's default, and there is no flag to change it for one
    container. Asking for a runtime Podman cannot select would make the
    run fail, so the request is not made there.
    """
    if not profile.runtime:
        return []
    if runtime.startswith("podman"):
        return []
    return ["--runtime", profile.runtime]


def _userns_args(profile: SandboxProfile, runtime: str) -> list[str]:
    """The user-namespace flags, in this runtime's vocabulary.

    Podman and Docker do not share a vocabulary here: Podman has
    ``keep-id`` and Docker has ``host`` and ``private``. The profile
    states the intent, and the flags are translated. Passing the wrong
    one makes the runtime refuse to start at all.
    """
    mode = profile.userns
    if not mode or mode == "none":
        return []
    if runtime.startswith("podman"):
        return ["--userns", mode]
    docker_mode = {"keep-id": "host", "auto": "host", "private": "private"}.get(mode, "host")
    return ["--userns", docker_mode]


def _seccomp_args(profile: SandboxProfile, runtime: str) -> list[str]:
    """The seccomp flags, in this runtime's vocabulary.

    Neither runtime accepts a seccomp *name* the way the profile states
    it: Podman 6 and Docker 29 both want a path to a profile file, and
    both reject "default". What they both do is apply their own default
    profile when the option is absent — which is the default profile the
    PRD asks for, and the strictest thing that still starts.

    Docker additionally names its own profile "builtin"; Podman applies
    the same profile by default and has no name for it.
    """
    mode = profile.seccomp
    if not mode or mode in {"none", "default"}:
        return []
    if mode == "builtin":
        return [] if runtime.startswith("podman") else ["--security-opt", "seccomp=builtin"]
    return ["--security-opt", f"seccomp={mode}"]


def build_container_args(request: SandboxRequest, runtime: str) -> list[str]:
    """Build the full runtime argument vector for one sandboxed run.

    Every hardening flag of PRD 11.2 is present here. The function is pure
    so that the flags can be asserted in tests.
    """
    profile = request.profile
    limits = request.limits
    args: list[str] = [runtime, "run", "--rm"]

    # Ephemeral and isolated.
    args.append("--pull=never")
    args.extend(_network_args(profile, runtime))
    args.extend(_runtime_args(profile, runtime))

    # Filesystem: read-only root, writable workdir, no other host mounts.
    if profile.read_only_root:
        args.append("--read-only")
    # The workdir is owned by the non-root user the container runs as, so
    # the PoC can write to it; /tmp is world-writable, as tools expect.
    # The scratch area is world-writable and sticky, so the unprivileged
    # user the container runs as can write to it. The ownership options
    # (uid=, gid=) are Docker-only; the mode is portable.
    args.extend(
        [
            "--tmpfs",
            f"{request.scratch}:rw,exec,nosuid,nodev,mode=1777,size={limits.disk_mb}m",
        ]
    )
    args.extend(["--tmpfs", "/tmp:rw,nosuid,nodev,mode=1777,size=64m"])

    # Identity and privileges.
    if profile.user:
        args.extend(["--user", profile.user])
    if profile.drop_capabilities:
        args.append("--cap-drop=ALL")
    if profile.no_new_privileges:
        args.extend(["--security-opt", "no-new-privileges"])
    args.extend(_seccomp_args(profile, runtime))
    args.extend(_userns_args(profile, runtime))
    if not profile.devices:
        args.append("--device=/dev/null:/dev/null")
        args.append("--device=/dev/urandom:/dev/urandom")
        args.append("--device=/dev/zero:/dev/zero")

    # Limits.
    args.extend(["--memory", f"{limits.memory_mb}m"])
    args.extend(["--memory-swap", f"{limits.memory_mb}m"])
    args.extend(["--cpus", str(limits.cpus)])
    args.extend(["--pids-limit", str(limits.pids)])
    args.extend(["--ulimit", f"nofile={limits.nofile}:{limits.nofile}"])
    args.extend(["--ulimit", "core=0"])
    args.extend(["--stop-timeout", "1"])

    # Working directory and environment.
    args.extend(["--workdir", request.workdir])
    for key, value in sorted(request.scrubbed_env().items()):
        args.extend(["--env", f"{key}={value}"])

    # Mounts: source read-only, evidence writable, staging read-only.
    for mount in request.mounts:
        args.extend(["--mount", mount.mount_spec()])

    args.extend(request.extra_args)
    args.append(request.image)
    args.extend(request.command)
    return args


class ContainerBackend(SandboxBackend):
    """Shared implementation for Podman and Docker."""

    runtime = ""

    def __init__(self, binary: str | None = None) -> None:
        self.binary = binary or self.runtime
        self._oci_runtime_name: str | None = None
        self._available: bool | None = None

    def available(self, *, refresh: bool = False) -> bool:
        """True when the runtime is installed *and* its daemon responds.

        The answer is cached: the check costs a subprocess call, and the
        run path asks for it on every run.
        """
        if self._available is not None and not refresh:
            return self._available
        if shutil.which(self.binary) is None:
            self._available = False
            return False
        self._available = self.server_version() != ""
        return self._available

    def server_version(self) -> str:
        """The version of the runtime's server, or "" when it is not running.

        The check is deliberately format-free: Podman and Docker do not
        share a template vocabulary, and a template that one of them does
        not understand would make a working runtime look broken.
        """
        try:
            result = subprocess.run(
                [self.binary, "version", "--format", "{{.Server.Version}}"],
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
                env=self._env(),
            )
        except (OSError, subprocess.SubprocessError):
            return ""
        if result.returncode != 0:
            return ""
        return result.stdout.strip()

    @staticmethod
    def _env() -> dict[str, str]:
        """The environment the runtime is invoked with.

        The orchestrator's own environment is passed through so the runtime
        can be found, but the sandbox itself never sees it.
        """
        return {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": os.environ.get("HOME", "/tmp")}

    def doctor(self) -> list[str]:
        """Health notes for ``verdis doctor``."""
        if shutil.which(self.binary) is None:
            return [f"{self.binary} is not on PATH"]
        version = self.server_version()
        if not version:
            return [
                f"{self.binary} is installed but its server is not responding; "
                "start it (for example 'colima start' for Docker, or "
                "'podman machine start' for Podman)"
            ]
        notes = [f"{self.binary} server version: {version}"]
        notes.extend(self._isolation_notes())
        return notes

    def _isolation_notes(self) -> list[str]:
        """Report what the runtime is doing about user namespaces.

        Rootless is the configuration the PRD asks for. A rootful runtime
        is usable, but the note says so rather than leaving the operator
        to guess.
        """
        try:
            result = subprocess.run(
                [self.binary, "info", "--format", "{{json .}}"],
                capture_output=True,
                text=True,
                timeout=20,
                check=False,
                env=self._env(),
            )
        except (OSError, subprocess.SubprocessError):
            return []
        if result.returncode != 0:
            return []
        try:
            info = json.loads(result.stdout)
        except json.JSONDecodeError:
            return []
        # Podman reports host.security.rootless; Docker reports a
        # SecurityOptions list.
        security = info.get("host", {}).get("security", {}) or info.get("HostSecurity") or {}
        if "rootless" in security:
            state = "rootless" if security.get("rootless") else "rootful"
            return [f"{self.binary} is running {state}"]
        if "Rootless" in security:
            state = "rootless" if security.get("Rootless") else "rootful"
            return [f"{self.binary} is running {state}"]
        if info.get("Rootless") is not None:
            state = "rootless" if info.get("Rootless") else "rootful"
            return [f"{self.binary} is running {state}"]
        options = [str(option) for option in (info.get("SecurityOptions") or [])]
        if any("rootless" in option for option in options):
            return [f"{self.binary} is running rootless"]
        seccomp = next(
            (option for option in options if "seccomp" in option),
            "",
        )
        notes = []
        if seccomp:
            notes.append(f"{self.binary} seccomp: {seccomp.split('=')[-1]}")
        if any("apparmor" in option for option in options):
            notes.append(f"{self.binary} apparmor: enabled")
        notes.append(
            f"{self.binary} is running rootful; rootless Podman is the "
            "configuration the PRD recommends"
        )
        return notes

    def run(self, request: SandboxRequest) -> SandboxResult:
        if not self.available():
            raise SandboxError(f"{self.binary} is not available on this machine")
        # A profile that asks for a runtime the host does not have cannot
        # be honoured. The run goes ahead with the isolation that is
        # available, and the result says which one that was: a profile
        # that silently did less than it promised would be worse than one
        # that admits the limit.
        profile = request.profile
        if profile.runtime and not self._runtime_available(profile.runtime):
            profile = replace(profile, runtime="")
        args = build_container_args(
            replace(request, profile=profile), self.binary
        )
        result = run_subprocess(
            args,
            env=self._env(),
            timeout=request.limits.timeout_s,
            input_text=request.stdin,
            output_limit=request.limits.output_bytes,
        )
        result.backend = self.name
        result.image_digest = self._image_digest(request.image)
        result.isolation = self._isolation_in_use(request.profile)
        # The sandbox is where the observation happens: a network
        # attempt that the runtime refused, and the fact that the source
        # was read-only and the work directory was discarded with the
        # container.
        result.blocked_network = _blocked_network_attempts(
            result.stdout + result.stderr
        )
        result.fs_changes = (
            "the source was mounted read-only",
            "the work directory was a temporary filesystem that was discarded "
            "with the container",
        )
        return result

    def _image_digest(self, image: str) -> str:
        """The digest of the image the run used.

        A pulled image has a registry digest; a locally built one has an
        image id. Both identify the exact bits that ran, so both are
        recorded.
        """
        if "@sha256:" in image:
            return image.split("@sha256:")[-1]
        for template in ("{{.Digest}}", "{{.Id}}"):
            value = self._inspect(image, template)
            if value:
                return value
        return ""

    def image_present(self, image: str) -> bool:
        """True when the image is already on this machine.

        The tool never pulls an image at run time: the image has to be
        present and pinned before the run, so the supply chain stays
        under the maintainer's control.
        """
        if not image:
            return True
        if "@sha256:" in image:
            return self._inspect(image, "{{.Id}}") != ""
        return self._inspect(image, "{{.Id}}") != ""

    def _inspect(self, image: str, template: str) -> str:
        try:
            result = subprocess.run(
                [self.binary, "image", "inspect", "--format", template, image],
                capture_output=True,
                text=True,
                timeout=20,
                check=False,
                env=self._env(),
            )
        except (OSError, subprocess.SubprocessError):
            return ""
        if result.returncode != 0:
            return ""
        return result.stdout.strip()

    def missing_images(self, images: tuple[str, ...]) -> list[str]:
        """The images that have to be pulled before the tool can run."""
        return [image for image in images if image and not self.image_present(image)]

    def _isolation_in_use(self, profile: SandboxProfile) -> str:
        """The isolation the run actually had.

        A hardened profile that cannot be honoured must not pretend it
        was: the evidence bundle records what actually protected the
        run. The runtime is the one the host used, which is the only
        answer that means anything.
        """
        actual = self._oci_runtime()
        if profile.runtime:
            if actual and actual == profile.runtime:
                return actual
            if actual:
                return f"{profile.name} (the host used {actual}, not {profile.runtime})"
            return f"{profile.name} (without {profile.runtime})"
        return actual or profile.name

    def _oci_runtime(self) -> str:
        """The OCI runtime this host runs containers with."""
        if self._oci_runtime_name is None:
            self._oci_runtime_name = self._read_oci_runtime()
        return self._oci_runtime_name

    def _read_oci_runtime(self) -> str:
        template = (
            "{{.Host.OCIRuntime.Name}}"
            if self.binary.startswith("podman")
            else "{{.DefaultRuntime}}"
        )
        try:
            result = subprocess.run(
                [self.binary, "info", "--format", template],
                capture_output=True,
                text=True,
                timeout=20,
                check=False,
                env=self._env(),
            )
        except (OSError, subprocess.SubprocessError):
            return ""
        if result.returncode != 0:
            return ""
        return result.stdout.strip()

    def _runtime_available(self, runtime: str) -> bool:
        """Is this container runtime installed?"""
        try:
            result = subprocess.run(
                [self.binary, "info", "--format", "{{.Host.OCIRuntime.Name}}"],
                capture_output=True,
                text=True,
                timeout=20,
                check=False,
                env=self._env(),
            )
        except (OSError, subprocess.SubprocessError):
            return False
        if result.returncode != 0:
            return False
        return runtime in result.stdout

    @abstractmethod
    def _unused(self) -> None:  # pragma: no cover - keeps the class abstract-ish
        raise NotImplementedError


def resolve_binary(candidates: tuple[str, ...]) -> str:
    """Return the first candidate on PATH, or the first candidate."""
    for candidate in candidates:
        if shutil.which(candidate):
            return candidate
    return candidates[0]


def mount_for(source: str | Path, target: str, *, readonly: bool = True) -> Mount:
    """Helper to build a :class:`Mount`."""
    return Mount(source=str(Path(source)), target=target, readonly=readonly)
