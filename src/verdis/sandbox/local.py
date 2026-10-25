"""Development-only backend.

This backend exists so the pipeline can be exercised on a developer laptop
and in CI where no container runtime is available. **It is not a security
boundary.** It does not isolate the host, it cannot block the network, and
it must never be used to run an untrusted PoC.

``verdis doctor`` prints a warning whenever this backend is selected.
"""

from __future__ import annotations

import shutil
import socket
import tempfile
import threading
from pathlib import Path

from .base import (
    SandboxBackend,
    SandboxError,
    SandboxRequest,
    SandboxResult,
    run_subprocess,
)

__all__ = ["WARNING", "LocalBackend"]

WARNING = (
    "the 'local' backend is a development convenience with no isolation; "
    "never point it at an untrusted proof of concept"
)

_NETWORK_ERROR_SIGNATURES = (
    "network is unreachable",
    "connection refused",
    "temporary failure in name resolution",
    "no such host",
    "name or service not known",
    "network is down",
    "cannot assign requested address",
    "connection reset by peer",
    "econnrefused",
    "enotfound",
    "eai_again",
)


class _CanaryListener:
    """A loopback listener that records connection attempts.

    In the container backends the run stage has no network at all; here the
    listener gives the same *attempt* signal, but without isolation.
    """

    def __init__(self) -> None:
        self.hits: list[str] = []
        self._server: socket.socket | None = None
        self._thread: threading.Thread | None = None
        self.port = 0

    def start(self) -> None:
        self._server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._server.bind(("127.0.0.1", 0))
        self._server.listen(8)
        self.port = self._server.getsockname()[1]
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def _serve(self) -> None:
        assert self._server is not None
        while True:
            try:
                conn, addr = self._server.accept()
            except OSError:
                return
            with conn:
                self.hits.append(f"{addr[0]}:{addr[1]}")
                try:
                    conn.sendall(b"verdis-canary\n")
                except OSError:  # pragma: no cover - best effort
                    pass

    def stop(self) -> None:
        if self._server is not None:
            try:
                self._server.close()
            except OSError:  # pragma: no cover
                pass


class LocalBackend(SandboxBackend):
    """Run a command on the host with a scrubbed environment."""

    name = "local"

    def __init__(self, *, allow_network: bool = False) -> None:
        self.allow_network = allow_network
        self.warning = WARNING

    def available(self) -> bool:
        return True

    def doctor(self) -> list[str]:
        return [f"WARNING: {WARNING}"]

    def run(self, request: SandboxRequest) -> SandboxResult:
        workdir = Path(request.workdir_source) if request.workdir_source else Path(
            tempfile.mkdtemp(prefix="verdis-local-")
        )
        workdir.mkdir(parents=True, exist_ok=True)

        listener = _CanaryListener()
        if not self.allow_network:
            listener.start()

        env = self._build_env(request, listener)

        try:
            result = run_subprocess(
                request.command,
                cwd=workdir,
                env=env,
                timeout=request.limits.timeout_s,
                input_text=request.stdin,
                output_limit=request.limits.output_bytes,
            )
        except OSError as exc:  # pragma: no cover - defensive
            raise SandboxError(f"local backend failed to start the command: {exc}") from exc
        finally:
            listener.stop()

        result.backend = self.name
        result.canary_hits = tuple(listener.hits)
        result.blocked_network = self._network_attempts(result)
        result.fs_changes = self._collect_changes(workdir)
        result.isolation = "none (the development backend is not a security boundary)"
        return result

    # -- helpers --------------------------------------------------------

    def _build_env(self, request: SandboxRequest, listener: _CanaryListener) -> dict[str, str]:
        env = {
            "PATH": "/usr/bin:/bin:/usr/local/bin:/opt/homebrew/bin",
            "HOME": str(Path(tempfile.gettempdir()) / "verdis-home"),
            "TMPDIR": "/tmp",
            "LANG": "C.UTF-8",
            "VERDIS_SANDBOX": "local",
        }
        Path(env["HOME"]).mkdir(parents=True, exist_ok=True)
        if not self.allow_network:
            # Point the common proxy variables at a closed port so that a
            # network attempt fails fast instead of reaching the internet.
            env["http_proxy"] = f"http://127.0.0.1:{listener.port}"
            env["https_proxy"] = f"http://127.0.0.1:{listener.port}"
            env["VERDIS_CANARY_PORT"] = str(listener.port)
        env.update(request.scrubbed_env())
        # The request's environment may name a path that exists only
        # inside a container. On the host, HOME has to be a directory
        # that exists, so the backend's own is used.
        env["HOME"] = str(Path(tempfile.gettempdir()) / "verdis-home")
        Path(env["HOME"]).mkdir(parents=True, exist_ok=True)
        return env

    @staticmethod
    def _network_attempts(result: SandboxResult) -> tuple[str, ...]:
        blob = f"{result.stdout}\n{result.stderr}".lower()
        attempts: list[str] = []
        for signature in _NETWORK_ERROR_SIGNATURES:
            if signature in blob:
                attempts.append(signature)
        return tuple(attempts)

    @staticmethod
    def _collect_changes(workdir: Path) -> tuple[str, ...]:
        changes: list[str] = []
        for path in sorted(workdir.rglob("*")):
            if path.is_file():
                changes.append(str(path.relative_to(workdir)))
        return tuple(changes[:500])

    @staticmethod
    def cleanup(path: str | Path) -> None:
        shutil.rmtree(path, ignore_errors=True)
