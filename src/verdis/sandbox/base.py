"""Sandbox backend interface (PRD section 11.2).

The orchestrator never executes anything directly. It hands a
:class:`SandboxRequest` to a backend and receives a :class:`SandboxResult`.

The default profile is: rootless container runtime, non-root user, user
namespaces on, no network, read-only root filesystem, writable tmpfs
workdir, source mounted read-only, evidence directory write-only from
inside, all capabilities dropped, no-new-privileges, default seccomp or
stricter, no devices, no other host mounts, and hard limits on CPU,
memory, process count, disk, open files and wall-clock time.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path

__all__ = [
    "CONTAINER_BACKENDS",
    "Mount",
    "SandboxBackend",
    "SandboxError",
    "SandboxLimits",
    "SandboxProfile",
    "SandboxRequest",
    "SandboxResult",
    "default_profile",
    "hardened_profile",
    "share_with_sandbox",
]


class SandboxError(RuntimeError):
    """Raised when a sandbox cannot be created or run."""


#: The backends that run the command inside a container. The development
#: backend is deliberately not one of them.
CONTAINER_BACKENDS = frozenset({"podman", "docker"})


@dataclass(frozen=True)
class SandboxLimits:
    """Hard limits applied to every run (FR-8.6)."""

    timeout_s: int = 60
    memory_mb: int = 2048
    cpus: float = 2.0
    pids: int = 256
    disk_mb: int = 4096
    nofile: int = 1024
    output_bytes: int = 1_000_000

    def to_cli(self) -> dict[str, str]:
        return {
            "--memory": f"{self.memory_mb}m",
            "--cpus": str(self.cpus),
            "--pids-limit": str(self.pids),
            "--ulimit": f"nofile={self.nofile}",
        }


@dataclass(frozen=True)
class SandboxProfile:
    """A named hardening profile."""

    name: str = "default"
    network: str = "none"
    read_only_root: bool = True
    drop_capabilities: bool = True
    no_new_privileges: bool = True
    user: str = "65534:65534"
    seccomp: str = "default"
    ephemeral: bool = True
    devices: bool = False
    userns: str = "keep-id"
    runtime: str = ""
    """The container runtime to use, e.g. "runsc" for gVisor."""
    allow_host_network_in_build: bool = False

    @property
    def hardened(self) -> bool:
        return self.name == "hardened"


def default_profile() -> SandboxProfile:
    """The default profile of PRD 11.2."""
    return SandboxProfile(name="default")


def hardened_profile() -> SandboxProfile:
    """The hardened profile of PRD 11.3.

    The difference is enforced by the backend, not by these flags: the
    profile asks for gVisor (``runsc``), and the build stage gets no
    network of its own, so the two phases cannot reach each other.

    When the runtime cannot provide gVisor the backend records the
    isolation it actually used, and the evidence bundle says so. A profile
    that claims more than it delivers would be worse than one that admits
    the limit.
    """
    return SandboxProfile(
        name="hardened",
        seccomp="default",
        user="65534:65534",
        runtime="runsc",
        allow_host_network_in_build=False,
    )


@dataclass(frozen=True)
class Mount:
    """A host path exposed to the sandbox."""

    source: str
    target: str
    readonly: bool = True

    def spec(self) -> str:
        """The ``-v`` form of the mount.

        The ``--mount`` form is different: it takes key=value pairs, and
        a bare "ro" or "rw" is rejected.
        """
        suffix = ":ro" if self.readonly else ":rw"
        return f"{self.source}:{self.target}{suffix}"

    def mount_spec(self) -> str:
        """The ``--mount`` form of the mount."""
        spec = f"type=bind,source={self.source},target={self.target}"
        if self.readonly:
            spec += ",readonly"
        return spec


def _widen(path: Path, *, directory: bool, writable: bool) -> None:
    """Add the permission bits the sandbox user needs to one path."""
    if path.is_symlink():
        return
    try:
        mode = path.stat().st_mode & 0o7777
        wanted = mode | 0o444
        if directory or mode & 0o100:
            wanted |= 0o111
        if writable:
            wanted |= 0o222
        if wanted != mode:
            path.chmod(wanted)
    except OSError:
        # A path that cannot be changed is left as it is. The sandbox then
        # fails loudly on that path instead of this call failing quietly.
        pass


def share_with_sandbox(path: str | Path, *, writable: bool = False) -> None:
    """Let the sandbox's unprivileged user reach a tree this tool made.

    The sandbox runs as an unprivileged user that is not the invoking
    user. A container runtime on macOS hides that difference. On Linux a
    bind mount keeps the host's owner and mode, so a private copy of a
    repository cannot be read from inside, and a build directory cannot be
    written. This widens the modes of ``path`` and of everything under it.

    Call it only on a tree the tool created itself, inside a private
    parent directory: other local users can reach the tree only through
    that parent. Symbolic links are left alone.
    """
    root = Path(path)
    if root.is_symlink() or not root.is_dir():
        return
    for current, _dirnames, filenames in os.walk(root):
        _widen(Path(current), directory=True, writable=writable)
        for name in filenames:
            _widen(Path(current) / name, directory=False, writable=writable)


@dataclass
class SandboxRequest:
    """Everything a backend needs to run one command."""

    image: str
    command: list[str] = field(default_factory=list)
    workdir: str = "/work"
    scratch: str = "/work"
    """The writable scratch area.

    It is a tmpfs, and it must not be the same path as a bind mount, or
    the mount would hide it.
    """
    env: dict[str, str] = field(default_factory=dict)
    mounts: list[Mount] = field(default_factory=list)
    limits: SandboxLimits = field(default_factory=SandboxLimits)
    profile: SandboxProfile = field(default_factory=default_profile)
    stdin: str = ""
    workdir_source: str = ""
    evidence_dir: str = ""
    shell: bool = False
    extra_args: list[str] = field(default_factory=list)

    def scrubbed_env(self) -> dict[str, str]:
        """Environment handed to the sandbox: only what was explicitly asked for."""
        return dict(self.env)


@dataclass
class SandboxResult:
    """What came back from the sandbox."""

    exit_code: int | None = None
    stdout: str = ""
    stderr: str = ""
    duration_ms: int = 0
    timed_out: bool = False
    truncated: bool = False
    blocked_network: tuple[str, ...] = ()
    canary_hits: tuple[str, ...] = ()
    fs_changes: tuple[str, ...] = ()
    image_digest: str = ""
    backend: str = ""
    isolation: str = ""
    """The isolation the run actually had, as the runtime reports it."""
    cpu_ms: int = 0
    max_rss_kb: int = 0
    error: str = ""

    @property
    def signal(self) -> int | None:
        """POSIX signal number, when the process died from a signal."""
        if self.exit_code is None or self.exit_code >= 0:
            return None
        return -self.exit_code

    @property
    def crashed(self) -> bool:
        return self.signal is not None


class SandboxBackend(ABC):
    """The interface every sandbox implementation provides."""

    name: str = "abstract"

    @abstractmethod
    def available(self) -> bool:
        """True when this backend can actually run right now."""
        ...

    @abstractmethod
    def run(self, request: SandboxRequest) -> SandboxResult:
        """Run one command and return its result."""
        ...

    def doctor(self) -> list[str]:
        """Human-readable health notes for ``verdis doctor``."""
        return []

    # -- shared helpers -------------------------------------------------

    @staticmethod
    def _truncate(text: str, limit: int) -> tuple[str, bool]:
        encoded = text.encode("utf-8", errors="replace")
        if len(encoded) <= limit:
            return text, False
        return encoded[:limit].decode("utf-8", errors="ignore"), True

    @staticmethod
    def _kill_process_group(process: subprocess.Popen[bytes]) -> None:
        """Kill the whole process group; a timeout must not leave orphans."""
        import signal

        try:
            os.killpg(os.getpgid(process.pid), signal.SIGKILL)
        except (ProcessLookupError, PermissionError, OSError):  # pragma: no cover
            try:  # pragma: no cover - the group is usually already gone
                process.kill()
            except OSError:  # pragma: no cover - the process is already gone
                pass


def make_temp_workdir(prefix: str = "verdis-") -> Path:
    """Create a temporary workdir (used by the development backend)."""
    return Path(tempfile.mkdtemp(prefix=prefix))


def remove_tree(path: str | Path) -> None:
    """Remove a directory tree, ignoring errors."""
    shutil.rmtree(path, ignore_errors=True)


def _child_usage() -> tuple[int, int]:
    """What the child process used: ``(cpu_ms, max_rss_kb)``.

    The accounting is per child, so it does not include whatever the
    orchestrator itself did while waiting.
    """
    import resource

    usage = resource.getrusage(resource.RUSAGE_CHILDREN)
    return int((usage.ru_utime + usage.ru_stime) * 1000), int(usage.ru_maxrss)


def run_subprocess(
    command: list[str],
    *,
    cwd: str | Path | None = None,
    env: dict[str, str] | None = None,
    timeout: int = 60,
    input_text: str = "",
    output_limit: int = 1_000_000,
) -> SandboxResult:
    """Run a command with a timeout and a process-group kill.

    Shared by the development backend and by the runtime probes.
    """
    started = time.monotonic()
    try:
        process = subprocess.Popen(
            command,
            cwd=str(cwd) if cwd else None,
            env=env,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
        )
    except OSError as exc:
        return SandboxResult(
            exit_code=None,
            duration_ms=int((time.monotonic() - started) * 1000),
            error=f"failed to start command: {exc}",
        )

    timed_out = False
    try:
        out, err = process.communicate(
            input=input_text.encode("utf-8"), timeout=timeout
        )
    except subprocess.TimeoutExpired:
        timed_out = True
        SandboxBackend._kill_process_group(process)
        try:
            out, err = process.communicate(timeout=5)
        except subprocess.TimeoutExpired:  # pragma: no cover - defensive
            out, err = b"", b""

    duration_ms = int((time.monotonic() - started) * 1000)
    stdout, truncated_out = SandboxBackend._truncate(out.decode("utf-8", "replace"), output_limit)
    stderr, truncated_err = SandboxBackend._truncate(err.decode("utf-8", "replace"), output_limit)
    return SandboxResult(
        exit_code=process.returncode,
        stdout=stdout,
        stderr=stderr,
        duration_ms=duration_ms,
        timed_out=timed_out,
        truncated=truncated_out or truncated_err,
        cpu_ms=_child_usage()[0],
        max_rss_kb=_child_usage()[1],
    )
