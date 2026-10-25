"""Plan validation against an allowlist (FR-6.1, FR-6.2, FR-6.3).

The restricted step language cannot express network, host or secret access.
This module is the enforcement point: any plan that tries to smuggle those
in is rejected before it can reach a sandbox.

Three outcomes per plan:

``ALLOWED``
    Safe to run unattended.
``NEEDS_CONFIRMATION``
    Unusual but not forbidden (package install, privilege change, write
    outside the workdir). A human must approve; unattended runs fail closed.
``FORBIDDEN``
    Never runnable.
"""

from __future__ import annotations

import re
import shlex
from dataclasses import dataclass, field
from enum import StrEnum

from ..schemas.plan import (
    BuildStep,
    CheckoutStep,
    CompareStep,
    CopyStep,
    ExpectStep,
    Plan,
    RunStep,
)

__all__ = [
    "WORKDIR",
    "PlanIssue",
    "PlanValidation",
    "PlanValidator",
    "Severity",
]

WORKDIR = "/work"


class Severity(StrEnum):
    WARNING = "warning"
    CONFIRMATION = "confirmation"
    FORBIDDEN = "forbidden"


@dataclass(frozen=True)
class PlanIssue:
    """One finding about a plan."""

    severity: Severity
    code: str
    message: str
    step_index: int | None = None
    detail: str = ""

    def to_dict(self) -> dict[str, object]:
        return {
            "severity": str(self.severity),
            "code": self.code,
            "message": self.message,
            "step_index": self.step_index,
            "detail": self.detail,
        }


@dataclass
class PlanValidation:
    """The outcome of validating a plan."""

    issues: list[PlanIssue] = field(default_factory=list)

    @property
    def forbidden(self) -> list[PlanIssue]:
        return [i for i in self.issues if i.severity is Severity.FORBIDDEN]

    @property
    def needs_confirmation(self) -> list[PlanIssue]:
        return [i for i in self.issues if i.severity is Severity.CONFIRMATION]

    @property
    def ok(self) -> bool:
        """True when the plan may run unattended."""
        return not self.forbidden and not self.needs_confirmation

    @property
    def runnable(self) -> bool:
        """True when the plan is not forbidden (a human may still approve)."""
        return not self.forbidden

    def add(self, issue: PlanIssue) -> None:
        self.issues.append(issue)

    def to_dict(self) -> dict[str, object]:
        return {
            "ok": self.ok,
            "runnable": self.runnable,
            "issues": [i.to_dict() for i in self.issues],
        }


# -- rules --------------------------------------------------------------

#: Package managers. In a build step these are expected (the dependency
#: fetch phase is allowed to reach an allowlisted mirror); in a run step
#: they are unusual and need confirmation.
_PACKAGE_MANAGER_PATTERNS: tuple[re.Pattern[str], ...] = tuple(
    re.compile(pattern, re.IGNORECASE)
    for pattern in (
        r"\b(pip3?|apt|apt-get|yum|dnf|apk|brew|gem)\s+(install|add|update)\b",
        r"\bnpm\s+(install|i)\b",
        r"\bgo\s+(get|install)\b",
        r"\bcargo\s+(install|add)\b",
        r"\b(uv|pdm|poetry)\s+(add|install|sync)\b",
    )
)

#: Programs that reach the network. The run stage has no network at all
#: (PRD 11.2); a plan that tries is refused rather than silently neutered.
#: These are matched against the *program* of the command, not against its
#: arguments: an argument that happens to be called "nc" is not a network
#: call.
_NETWORK_PROGRAMS = frozenset(
    {
        "curl", "wget", "nc", "ncat", "netcat", "telnet", "ftp", "tftp",
        "ssh", "scp", "sftp", "rsync", "ping", "ping6", "traceroute",
        "tracepath", "dig", "host", "nslookup", "whois", "ssh-keyscan",
    }
)

#: Programs that reach the network when given the right subcommand.
_NETWORK_SUBCOMMANDS: dict[str, frozenset[str]] = {
    "git": frozenset({"clone", "fetch", "pull", "push", "remote"}),
    "gh": frozenset({"api", "pr", "issue", "release"}),
    "glab": frozenset({"api", "mr", "issue"}),
}

#: Patterns that reach the network wherever they appear in the command.
_NETWORK_PATTERNS: tuple[re.Pattern[str], ...] = tuple(
    re.compile(pattern, re.IGNORECASE)
    for pattern in (
        r"\bopenssl\s+s_client\b",
        r"\bssh-keygen\b",
        r"(?i)\bpython[0-9.]*\b.*\b(urllib|requests|socket|http\.client|ftplib|smtplib)\b",
        r"(?i)\bnode\b.*\b(require\(['\"]https?['\"]\)|http\.request|https\.request|net\.connect|dns)\b",
        r"(?i)\b(curl|wget)\b[^\n]*\|\s*(ba)?sh",
        r"(?i)https?://[^\s'\"]*",
    )
)

#: Programs that reach the host outside the sandbox.
_HOST_PROGRAMS = frozenset(
    {
        "mount", "umount", "nsenter", "unshare", "chroot", "pivot_root",
        "docker", "podman", "nerdctl", "lima", "colima", "ctr", "crictl",
        "systemctl", "service", "journalctl", "iptables", "nft",
        "firewall-cmd", "kill", "pkill", "killall", "sudo", "doas", "su",
        "setcap", "capsh", "insmod", "rmmod", "modprobe", "mkfs", "fdisk",
        "parted",
    }
)

#: Commands that read credentials or the environment.
_SECRET_PATTERNS: tuple[re.Pattern[str], ...] = tuple(
    re.compile(pattern, re.IGNORECASE)
    for pattern in (
        r"/etc/shadow",
        r"/etc/sudoers",
        r"~/\.ssh",
        r"\$HOME/\.ssh",
        r"/root/\.ssh",
        r"~?/?\.aws",
        r"/proc/self/environ",
        r"/proc/1/environ",
        r"\bprintenv\b",
        r"\$\{?(AWS_SECRET_ACCESS_KEY|AWS_ACCESS_KEY_ID|GITHUB_TOKEN|GH_TOKEN|"
        r"OPENAI_API_KEY|ANTHROPIC_API_KEY|NPM_TOKEN|SECRET_KEY|PASSWORD)\b",
        r"\bcat\b[^\n]*(id_rsa|id_ed25519|\.npmrc|\.pypirc|credentials)",
    )
)
#: Programs that need a human to say yes (FR-6.3).
#:
#: These are matched against the *program* of the command, not against its
#: arguments: an argument that happens to be called "rm" is not a
#: destructive command.
_CONFIRM_PROGRAMS: dict[str, str] = {
    "chmod": "filesystem-permission-change",
    "chown": "filesystem-permission-change",
    "chgrp": "filesystem-permission-change",
    "setfacl": "filesystem-permission-change",
    "rm": "destructive-filesystem-change",
    "unlink": "destructive-filesystem-change",
    "shred": "destructive-filesystem-change",
    "mv": "destructive-filesystem-change",
    "dd": "raw-device-write",
    "mkdir": "write-outside-workdir",
    "touch": "write-outside-workdir",
    "tee": "write-outside-workdir",
    "usermod": "account-change",
    "useradd": "account-change",
    "groupadd": "account-change",
    "passwd": "account-change",
    "crontab": "persistence",
    "systemctl": "persistence",
}

#: Package managers, and the subcommands that install something. Running
#: "go run" is not an installation, so the subcommand decides.
_CONFIRM_SUBCOMMANDS: dict[str, frozenset[str]] = {
    "pip": frozenset({"install"}),
    "pip3": frozenset({"install"}),
    "npm": frozenset({"install", "i", "add"}),
    "npx": frozenset({"install", "i"}),
    "apt": frozenset({"install"}),
    "apt-get": frozenset({"install", "update", "upgrade"}),
    "yum": frozenset({"install", "update"}),
    "dnf": frozenset({"install", "update"}),
    "apk": frozenset({"add"}),
    "brew": frozenset({"install"}),
    "gem": frozenset({"install"}),
    "cargo": frozenset({"install", "add"}),
    "go": frozenset({"get", "install"}),
    "uv": frozenset({"add", "install", "sync"}),
    "pdm": frozenset({"add", "install"}),
    "poetry": frozenset({"add", "install"}),
}

#: Commands that need a human to say yes, whatever they are called.
_CONFIRM_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = tuple(
    (re.compile(pattern, re.IGNORECASE), code)
    for pattern, code in (
        (r"(^|\s)>\s*/(?!work)", "write-outside-workdir"),
        (r"\b(no_proxy|http_proxy|https_proxy)\b", "proxy-configuration"),
    )
)

_SHELL_METACHARACTERS = ("`", "$(", ";", "|", "&", ">", "<", "\n", "\r")


def _normalise_path(path: str) -> str:
    """Resolve the ".." in a path, without touching the filesystem.

    The path may not exist on the machine running the tool: it names
    something inside the sandbox. Resolving it lexically is enough to
    see whether it stays inside the work directory.
    """
    parts: list[str] = []
    for part in path.split("/"):
        if part in ("", "."):
            continue
        if part == "..":
            if parts:
                parts.pop()
            continue
        parts.append(part)
    return "/" + "/".join(parts)

#: ``curl something | sh`` and friends: a download that is executed at once.
_DOWNLOAD_AND_EXECUTE_RE = re.compile(
    r"(?i)\b(curl|wget|fetch)\b[^\n]*\|\s*(sudo\s+)?(ba|z|k)?sh\b"
)
_ALLOWED_INTERPRETERS = {
    "python", "python3", "python3.12", "python3.13",
    "node", "go", "cargo", "ruby", "perl", "php",
    "pytest", "make", "cmake", "bash", "sh",
}
#: Interpreters that run whatever string they are given. The plan
#: language allows them to run a *file*, not to run a command.
_SHELL_INTERPRETERS = {"sh", "bash", "zsh", "dash", "ksh"}
_SAFE_ARG_RE = re.compile(r"^[A-Za-z0-9_@%+=:,./~^-]*$")


def _split(command: str) -> list[str]:
    """The argument vector of a command, or an empty list if it has none."""
    try:
        return shlex.split(command)
    except ValueError:
        return []


def _has_network_subcommand(program: str, argv: list[str]) -> bool:
    """Does this program reach the network with this subcommand?"""
    subcommands = _NETWORK_SUBCOMMANDS.get(program)
    if subcommands is None or len(argv) < 2:
        return False
    return argv[1].lower() in subcommands


class PlanValidator:
    """Validate a plan against the allowlist."""

    def __init__(self, *, workdir: str = WORKDIR) -> None:
        self.workdir = workdir.rstrip("/") or WORKDIR

    # -- entry point ----------------------------------------------------

    def validate(self, plan: Plan) -> PlanValidation:
        validation = PlanValidation()
        for index, step in enumerate(plan.steps):
            if isinstance(step, RunStep):
                self._validate_run(step, index, validation)
            elif isinstance(step, BuildStep):
                self._validate_build(step, index, validation)
            elif isinstance(step, CopyStep):
                self._validate_copy(step, index, validation)
            elif isinstance(step, CompareStep):
                self._validate_ref(step.ref, index, validation, "compare")
            elif isinstance(step, CheckoutStep):
                self._validate_ref(step.ref, index, validation, "checkout")
            elif isinstance(step, ExpectStep):
                self._validate_expect(step, index, validation)
        if not plan.default_config:
            validation.add(
                PlanIssue(
                    severity=Severity.WARNING,
                    code="non-default-configuration",
                    message="plan runs a non-default configuration; policy may exclude this",
                    step_index=None,
                )
            )
        return validation

    # -- individual steps -----------------------------------------------

    def _validate_run(self, step: RunStep, index: int, validation: PlanValidation) -> None:
        command = step.cmd
        argv = _split(command)
        program = argv[0].rsplit("/", 1)[-1].lower() if argv else ""

        if program in _NETWORK_PROGRAMS or _has_network_subcommand(program, argv):
            validation.add(
                PlanIssue(
                    severity=Severity.FORBIDDEN,
                    code="network-access",
                    message=(
                        f"the run command starts {program!r}, which reaches the network; "
                        "the run stage has no network access and the plan language "
                        "cannot express it"
                    ),
                    step_index=index,
                    detail=program,
                )
            )
        for pattern in _NETWORK_PATTERNS:
            if pattern.search(command):
                validation.add(
                    PlanIssue(
                        severity=Severity.FORBIDDEN,
                        code="network-access",
                        message=(
                            "run command appears to reach the network; the run stage has "
                            "no network access and the plan language cannot express it"
                        ),
                        step_index=index,
                        detail=pattern.pattern,
                    )
                )
                break
        if program in _HOST_PROGRAMS:
            validation.add(
                PlanIssue(
                    severity=Severity.FORBIDDEN,
                    code="host-access",
                    message=(
                        f"the run command starts {program!r}, which touches the host; "
                        "the plan language cannot express host access"
                    ),
                    step_index=index,
                    detail=program,
                )
            )
        for pattern in _SECRET_PATTERNS:
            if pattern.search(command):
                validation.add(
                    PlanIssue(
                        severity=Severity.FORBIDDEN,
                        code="secret-access",
                        message=(
                            "run command appears to read credentials or the environment"
                        ),
                        step_index=index,
                        detail=pattern.pattern,
                    )
                )
                break
        if program:
            code = _CONFIRM_PROGRAMS.get(program)
            if code is None:
                subcommands = _CONFIRM_SUBCOMMANDS.get(program)
                if subcommands and len(argv) > 1 and argv[1].lower() in subcommands:
                    code = "package-install"
            if code is not None:
                validation.add(
                    PlanIssue(
                        severity=Severity.CONFIRMATION,
                        code=code,
                        message=(
                            "unusual command requires maintainer confirmation before it "
                            "may run"
                        ),
                        step_index=index,
                        detail=program,
                    )
                )
        for pattern, code in _CONFIRM_PATTERNS:
            if pattern.search(command):
                validation.add(
                    PlanIssue(
                        severity=Severity.CONFIRMATION,
                        code=code,
                        message=(
                            "unusual command requires maintainer confirmation before it "
                            "may run"
                        ),
                        step_index=index,
                        detail=pattern.pattern,
                    )
                )
                break
        self._validate_shell_safety(command, index, validation)
        self._validate_workdir_writes(command, index, validation)

    def _validate_shell_safety(
        self, command: str, index: int, validation: PlanValidation
    ) -> None:
        for meta in _SHELL_METACHARACTERS:
            if meta in command:
                validation.add(
                    PlanIssue(
                        severity=Severity.FORBIDDEN,
                        code="shell-metacharacter",
                        message=(
                            f"run command contains the shell metacharacter {meta!r}; "
                            "commands must be a plain argument vector"
                        ),
                        step_index=index,
                    )
                )
                return
        try:
            argv = shlex.split(command)
        except ValueError as exc:
            validation.add(
                PlanIssue(
                    severity=Severity.FORBIDDEN,
                    code="unparsable-command",
                    message=f"run command cannot be parsed as an argument vector: {exc}",
                    step_index=index,
                )
            )
            return
        if not argv:
            validation.add(
                PlanIssue(
                    severity=Severity.FORBIDDEN,
                    code="empty-command",
                    message="run command is empty",
                    step_index=index,
                )
            )
            return
        program = argv[0]
        if program.startswith("/"):
            program = _normalise_path(program)
        if (
            program.rsplit("/", 1)[-1] in _SHELL_INTERPRETERS
            and len(argv) > 1
            and argv[1] in {"-c", "--command"}
        ):
            # "sh -c anything" is a way to run anything. The plan
            # language allows a shell to run a file, not a string.
            validation.add(
                PlanIssue(
                    severity=Severity.FORBIDDEN,
                    code="shell-command",
                    message=(
                        f"{program!r} may not run a command string; name a file instead"
                    ),
                    step_index=index,
                )
            )
            return
        if program.startswith("/") and not program.startswith(self.workdir):
            validation.add(
                PlanIssue(
                    severity=Severity.CONFIRMATION,
                    code="absolute-path-outside-workdir",
                    message=(
                        f"program {program!r} is outside the workdir {self.workdir!r}"
                    ),
                    step_index=index,
                )
            )
        elif program.startswith("/") and program.startswith(self.workdir):
            pass
        elif program.startswith("./") or program.startswith("../"):
            if ".." in program:
                validation.add(
                    PlanIssue(
                        severity=Severity.FORBIDDEN,
                        code="path-traversal",
                        message="run command escapes the workdir with '..'",
                        step_index=index,
                    )
                )
        elif program not in _ALLOWED_INTERPRETERS and "/" in program:
            validation.add(
                PlanIssue(
                    severity=Severity.CONFIRMATION,
                    code="unusual-program",
                    message=f"program {program!r} is not a known-safe executable",
                    step_index=index,
                )
            )
        for arg in argv[1:]:
            if not _SAFE_ARG_RE.match(arg):
                validation.add(
                    PlanIssue(
                        severity=Severity.CONFIRMATION,
                        code="unusual-argument",
                        message=f"argument {arg!r} contains unusual characters",
                        step_index=index,
                    )
                )
                break

    def _validate_workdir_writes(
        self, command: str, index: int, validation: PlanValidation
    ) -> None:
        for match in re.finditer(r"(?:^|\s)(/[^\s'\"]*)", command):
            path = match.group(1)
            # A path that begins with the workdir can still leave it:
            # "/work/../.ssh/id_rsa" is not inside the workdir.
            path = _normalise_path(path)
            if path.startswith(self.workdir) and path != self.workdir:
                continue
            if path in {"/dev/null", "/dev/stdout", "/dev/stderr"}:
                continue
            if path == "/":
                # The root of the filesystem is not the work directory.
                validation.add(
                    PlanIssue(
                        severity=Severity.CONFIRMATION,
                        code="write-outside-workdir",
                        message=(
                            f"command escapes to the filesystem root, outside the "
                            f"workdir {self.workdir!r}"
                        ),
                        step_index=index,
                    )
                )
                break
            if path.startswith("/tmp/"):
                # The sandbox provides its own /tmp; a PoC may use it.
                continue
            if path.startswith("/usr/") or path.startswith("/bin/") or path.startswith("/sbin/"):
                continue
            if path.startswith("/lib") or path.startswith("/proc/self/cmdline"):
                continue
            validation.add(
                PlanIssue(
                    severity=Severity.CONFIRMATION,
                    code="write-outside-workdir",
                    message=f"command references {path!r} outside the workdir {self.workdir!r}",
                    step_index=index,
                )
            )
            break

    def _validate_build(self, step: BuildStep, index: int, validation: PlanValidation) -> None:
        for command in step.steps:
            if _DOWNLOAD_AND_EXECUTE_RE.search(command):
                validation.add(
                    PlanIssue(
                        severity=Severity.FORBIDDEN,
                        code="build-download-and-execute",
                        message=(
                            "the build step downloads and executes code; a build must "
                            "fetch dependencies through an allowlisted mirror or a "
                            "vendored cache, never straight from the internet"
                        ),
                        step_index=index,
                    )
                )
            for pattern in _NETWORK_PATTERNS:
                if pattern.search(command):
                    validation.add(
                        PlanIssue(
                            severity=Severity.WARNING,
                            code="build-network-access",
                            message=(
                                "build step reaches the network; dependency fetching must go "
                                "through the allowlisted mirror or a vendored cache"
                            ),
                            step_index=index,
                            detail=pattern.pattern,
                        )
                    )
                    break
            for pattern in _PACKAGE_MANAGER_PATTERNS:
                if pattern.search(command):
                    validation.add(
                        PlanIssue(
                            severity=Severity.WARNING,
                            code="build-network-access",
                            message=(
                                "build step installs packages; dependency fetching must go "
                                "through the allowlisted mirror or a vendored cache"
                            ),
                            step_index=index,
                            detail=pattern.pattern,
                        )
                    )
                    break
            build_argv = _split(command)
            build_program = (
                build_argv[0].rsplit("/", 1)[-1].lower() if build_argv else ""
            )
            if build_program in _HOST_PROGRAMS:
                validation.add(
                    PlanIssue(
                        severity=Severity.FORBIDDEN,
                        code="build-host-access",
                        message=(
                            f"the build step starts {build_program!r}, which touches "
                            "the host"
                        ),
                        step_index=index,
                        detail=build_program,
                    )
                )
            for pattern in _SECRET_PATTERNS:
                if pattern.search(command):
                    validation.add(
                        PlanIssue(
                            severity=Severity.FORBIDDEN,
                            code="build-secret-access",
                            message="build step appears to read credentials or the environment",
                            step_index=index,
                            detail=pattern.pattern,
                        )
                    )
                    break

    def _validate_copy(self, step: CopyStep, index: int, validation: PlanValidation) -> None:
        destination = step.to
        if not destination.startswith(self.workdir):
            validation.add(
                PlanIssue(
                    severity=Severity.FORBIDDEN,
                    code="copy-outside-workdir",
                    message=(
                        f"copy destination {destination!r} is outside the workdir "
                        f"{self.workdir!r}"
                    ),
                    step_index=index,
                )
            )
            return
        if ".." in destination:
            validation.add(
                PlanIssue(
                    severity=Severity.FORBIDDEN,
                    code="copy-path-traversal",
                    message="copy destination escapes the workdir with '..'",
                    step_index=index,
                )
            )
            return
        if step.artifact.startswith("/") or ".." in step.artifact:
            validation.add(
                PlanIssue(
                    severity=Severity.FORBIDDEN,
                    code="copy-source-escape",
                    message=f"copy source {step.artifact!r} must be a bare file name",
                    step_index=index,
                )
            )

    def _validate_expect(self, step: ExpectStep, index: int, validation: PlanValidation) -> None:
        if step.regex:
            try:
                re.compile(step.regex)
            except re.error as exc:
                validation.add(
                    PlanIssue(
                        severity=Severity.FORBIDDEN,
                        code="invalid-regex",
                        message=f"expect regex does not compile: {exc}",
                        step_index=index,
                    )
                )

    def _validate_ref(
        self, ref: str, index: int, validation: PlanValidation, kind: str
    ) -> None:
        if not ref:  # pragma: no cover - the model rejects an empty ref
            return
        if ref.startswith("-"):
            validation.add(
                PlanIssue(
                    severity=Severity.FORBIDDEN,
                    code="option-like-ref",
                    message=f"{kind} ref {ref!r} looks like a command-line option",
                    step_index=index,
                )
            )
        if re.search(r"[;&|`$<>]", ref):
            validation.add(
                PlanIssue(
                    severity=Severity.FORBIDDEN,
                    code="unsafe-ref",
                    message=f"{kind} ref {ref!r} contains shell metacharacters",
                    step_index=index,
                )
            )
