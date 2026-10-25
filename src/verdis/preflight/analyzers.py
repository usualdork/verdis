"""Static inspection of attachments (FR-5.1).

Everything here is read-only and offline: file type, archive structure,
script behaviour and binary characteristics. Nothing is executed, ever.
"""

from __future__ import annotations

import re
import stat
import tarfile
import zipfile
from dataclasses import dataclass, field
from pathlib import Path

from ..schemas.preflight import PreflightFinding, RiskLevel
from .elf import parse_elf_imports

__all__ = [
    "ArchiveReport",
    "detect_file_type",
    "inspect_archive",
    "inspect_binary",
    "inspect_script",
]

# -- file types ---------------------------------------------------------

_MAGIC: tuple[tuple[bytes, str], ...] = (
    (b"\x7fELF", "elf"),
    (b"MZ", "pe"),
    (b"\xcf\xfa\xed\xfe", "macho"),
    (b"\xce\xfa\xed\xfe", "macho"),
    (b"\xca\xfe\xba\xbe", "macho"),
    (b"PK\x03\x04", "zip"),
    (b"PK\x05\x06", "zip"),
    (b"\x1f\x8b", "gzip"),
    (b"BZh", "bzip2"),
    (b"\xfd7zXZ\x00", "xz"),
    (b"ustar", "tar"),
    (b"#!", "script"),
    (b"\x89PNG\r\n\x1a\n", "png"),
    (b"GIF8", "gif"),
    (b"\xff\xd8\xff", "jpeg"),
    (b"%PDF", "pdf"),
    (b"SQLite format 3", "sqlite"),
    (b"\xde\xad\xbe\xef", "java-class"),
)


def detect_file_type(path: Path) -> str:
    """Identify a file from its magic bytes and extension."""
    try:
        with path.open("rb") as handle:
            head = handle.read(512)
    except OSError:
        return "unreadable"
    for magic, name in _MAGIC:
        if head.startswith(magic):
            return name
    if head.startswith(b"ustar") or (len(head) > 262 and head[257:262] == b"ustar"):
        return "tar"
    if not head:
        return "empty"
    try:
        head.decode("utf-8")
    except UnicodeDecodeError:
        return "binary"
    lowered = path.name.lower()
    if lowered.endswith((".sh", ".bash", ".zsh", ".py", ".rb", ".pl", ".js", ".ps1")):
        return "script"
    return "text"


# -- archives -----------------------------------------------------------

MAX_ARCHIVE_ENTRIES = 5_000
MAX_ARCHIVE_TOTAL_SIZE = 512 * 1024 * 1024
MAX_COMPRESSION_RATIO = 200


@dataclass
class ArchiveReport:
    """Structural findings about an archive."""

    findings: list[PreflightFinding] = field(default_factory=list)
    entries: int = 0
    uncompressed_size: int = 0
    compressed_size: int = 0
    kind: str = ""

    @property
    def ratio(self) -> float:
        if self.compressed_size <= 0:
            return float("inf") if self.uncompressed_size else 0.0
        return self.uncompressed_size / self.compressed_size


def _is_unsafe_member(name: str) -> bool:
    if not name:
        return True
    normalized = name.replace("\\", "/")
    if normalized.startswith("/"):
        return True
    if re.match(r"^[A-Za-z]:[\\/]", normalized):
        return True
    parts = normalized.split("/")
    return ".." in parts


def inspect_archive(path: Path, *, max_total_size: int = MAX_ARCHIVE_TOTAL_SIZE) -> ArchiveReport:
    """Inspect an archive without extracting it (FR-5.1, section 11.4 item 3)."""
    report = ArchiveReport()
    try:
        if zipfile.is_zipfile(path):
            report.kind = "zip"
            with zipfile.ZipFile(path) as archive:
                infos = archive.infolist()
                report.entries = len(infos)
                for info in infos:
                    report.uncompressed_size += info.file_size
                    report.compressed_size += info.compress_size
                    if _is_unsafe_member(info.filename):
                        report.findings.append(
                            PreflightFinding(
                                code="archive-path-traversal",
                                severity=RiskLevel.HIGH,
                                message=(
                                    f"archive entry {info.filename!r} points outside the "
                                    "extraction directory"
                                ),
                                evidence=info.filename,
                                weight=40,
                            )
                        )
                    mode = (info.external_attr >> 16) & 0xFFFF
                    if mode and stat.S_ISLNK(mode):
                        report.findings.append(
                            PreflightFinding(
                                code="archive-symlink",
                                severity=RiskLevel.MEDIUM,
                                message=f"archive entry {info.filename!r} is a symlink",
                                evidence=info.filename,
                                weight=15,
                            )
                        )
        elif tarfile.is_tarfile(path):
            report.kind = "tar"
            with tarfile.open(path) as archive:
                members = archive.getmembers()
                report.entries = len(members)
                for member in members:
                    report.uncompressed_size += member.size
                    if _is_unsafe_member(member.name):
                        report.findings.append(
                            PreflightFinding(
                                code="archive-path-traversal",
                                severity=RiskLevel.HIGH,
                                message=(
                                    f"archive entry {member.name!r} points outside the "
                                    "extraction directory"
                                ),
                                evidence=member.name,
                                weight=40,
                            )
                        )
                    if member.issym() or member.islnk():
                        report.findings.append(
                            PreflightFinding(
                                code="archive-symlink",
                                severity=RiskLevel.MEDIUM,
                                message=f"archive entry {member.name!r} is a link",
                                evidence=member.name,
                                weight=15,
                            )
                        )
                    if member.isdev():
                        report.findings.append(
                            PreflightFinding(
                                code="archive-device-entry",
                                severity=RiskLevel.HIGH,
                                message=f"archive entry {member.name!r} is a device node",
                                evidence=member.name,
                                weight=35,
                            )
                        )
        else:
            report.kind = "unknown"
            return report
    except (OSError, zipfile.BadZipFile, tarfile.TarError) as exc:  # pragma: no cover
        # A guard against a file that changes between the type check and
        # the open. Both checks swallow their own errors, so there is no
        # ordinary way to reach this.
        report.findings.append(
            PreflightFinding(
                code="archive-unreadable",
                severity=RiskLevel.MEDIUM,
                message=f"archive could not be read: {exc}",
                weight=10,
            )
        )
        return report

    if report.entries > MAX_ARCHIVE_ENTRIES:
        report.findings.append(
            PreflightFinding(
                code="archive-too-many-entries",
                severity=RiskLevel.MEDIUM,
                message=f"archive holds {report.entries} entries",
                weight=15,
            )
        )
    if report.uncompressed_size > max_total_size:
        report.findings.append(
            PreflightFinding(
                code="archive-too-large",
                severity=RiskLevel.HIGH,
                message=(
                    f"archive expands to {report.uncompressed_size} bytes, above the "
                    f"{max_total_size} byte limit"
                ),
                weight=35,
            )
        )
    if report.ratio > MAX_COMPRESSION_RATIO:
        report.findings.append(
            PreflightFinding(
                code="archive-compression-bomb",
                severity=RiskLevel.HIGH,
                message=(
                    f"archive expands {report.ratio:.0f}x, above the "
                    f"{MAX_COMPRESSION_RATIO}x limit"
                ),
                weight=45,
            )
        )
    return report


# -- scripts ------------------------------------------------------------

_SCRIPT_RULES: tuple[tuple[str, re.Pattern[str], RiskLevel, int, str], ...] = (
    (
        "script-network-call",
        re.compile(
            r"(?i)\b(curl|wget|nc|ncat|netcat|ssh|scp|ftp)\b|"
            r"\b(urllib|requests|socket|httpx|aiohttp)\b|https?://[^\s'\"]{4,}"
        ),
        RiskLevel.MEDIUM,
        15,
        "script makes network calls",
    ),
    (
        "script-credential-access",
        re.compile(
            r"(?i)(~|\$HOME|/root|/home/[^/\s]+)?/?\.(ssh|aws|gnupg|config/gcloud)\b|"
            r"/etc/(shadow|passwd|sudoers)\b|\.npmrc\b|\.pypirc\b|"
            r"\b(id_rsa|id_ed25519|\.netrc)\b|"
            r"\b(AWS_SECRET_ACCESS_KEY|AWS_ACCESS_KEY_ID|GITHUB_TOKEN|OPENAI_API_KEY)\b"
        ),
        RiskLevel.HIGH,
        35,
        "script reads credential paths or secret-looking environment variables",
    ),
    (
        "script-obfuscation",
        re.compile(
            r"(?i)\bbase64\s+(-d|--decode)\b|\batob\b|\bb64decode\b|"
            r"\beval\s*[\( ]|\bexec\s*[\( ]|\\x[0-9a-f]{2}(\\x[0-9a-f]{2}){8,}"
        ),
        RiskLevel.MEDIUM,
        20,
        "script decodes or evaluates encoded content",
    ),
    (
        "script-persistence",
        re.compile(
            r"(?i)\bcrontab\b|/etc/cron|\.bashrc\b|\.profile\b|systemctl\s+(enable|start)|"
            r"LD_PRELOAD|/etc/ld\.so\.preload|authorized_keys"
        ),
        RiskLevel.HIGH,
        30,
        "script attempts to persist itself",
    ),
    (
        "script-destructive",
        re.compile(
            r"(?i)\brm\s+(-[a-z]*\s+)*-[a-z]*[rf]|\bmkfs\b|\bdd\b[^|]*of=/dev/|"
            r"\bshred\b|:\(\)\s*\{\s*:\|:&\s*\};|>\s*/dev/sda"
        ),
        RiskLevel.HIGH,
        35,
        "script contains destructive commands",
    ),
    (
        "script-privilege-change",
        re.compile(r"(?i)\bsudo\b|\bsu\s+-\b|\bsetcap\b|\bchmod\s+[0-7]*[4-7][0-7]{3}\b"),
        RiskLevel.MEDIUM,
        15,
        "script attempts to change privileges",
    ),
    (
        "script-package-install",
        re.compile(
            r"(?i)\b(pip3?|npm|apt(-get)?|yum|dnf|apk|brew|gem|cargo|go)\s+"
            r"(install|add|get|update)\b"
        ),
        RiskLevel.MEDIUM,
        10,
        "script installs packages at run time",
    ),
)

_LONG_BASE64_RE = re.compile(r"[A-Za-z0-9+/]{180,}={0,2}")


def inspect_script(path: Path, *, max_read: int = 1_000_000) -> list[PreflightFinding]:
    """Inspect a script for network, credential, obfuscation, persistence and damage."""
    try:
        data = path.read_bytes()[:max_read]
    except OSError as exc:
        return [
            PreflightFinding(
                code="script-unreadable",
                severity=RiskLevel.MEDIUM,
                message=f"script could not be read: {exc}",
                weight=10,
            )
        ]
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        text = data.decode("utf-8", errors="replace")

    findings: list[PreflightFinding] = []
    for code, pattern, severity, weight, message in _SCRIPT_RULES:
        match = pattern.search(text)
        if match:
            findings.append(
                PreflightFinding(
                    code=code,
                    severity=severity,
                    message=message,
                    evidence=match.group(0)[:200],
                    weight=weight,
                )
            )
    long_blob = _LONG_BASE64_RE.search(text)
    if long_blob:
        findings.append(
            PreflightFinding(
                code="script-embedded-payload",
                severity=RiskLevel.MEDIUM,
                message="script contains a long base64 blob that may hide a payload",
                evidence=long_blob.group(0)[:80] + "...",
                weight=15,
            )
        )
    return findings


# -- binaries -----------------------------------------------------------

_PACKER_MARKERS = (b"UPX!", b".upx", b"ASPack", b"Themida", b"VMProtect")

_SUSPICIOUS_STRINGS = (
    b"/bin/sh",
    b"/bin/bash",
    b"socket",
    b"connect",
    b"execve",
    b"system",
    b"popen",
    b"dlopen",
    b"/etc/passwd",
    b"/etc/shadow",
    b"LD_PRELOAD",
    b"http://",
    b"https://",
    b"curl",
    b"wget",
    b"chmod 777",
    b"base64 -d",
    b"crontab",
)

_PACKED_IMPORT_SIGNATURES = (
    b"UPX!",
    b"UPX0",
    b"UPX1",
)


@dataclass
class BinaryReport:
    """Findings about a native binary."""

    findings: list[PreflightFinding] = field(default_factory=list)
    file_type: str = "binary"
    imports: list[str] = field(default_factory=list)
    libraries: list[str] = field(default_factory=list)
    packed: bool = False
    strings: list[str] = field(default_factory=list)


def _extract_printable_strings(data: bytes, min_length: int = 6, limit: int = 4000) -> list[str]:
    pattern = re.compile(rb"[\x20-\x7e]{%d,}" % min_length)
    out: list[str] = []
    for match in pattern.finditer(data):
        out.append(match.group(0).decode("ascii", errors="replace"))
        if len(out) >= limit:
            break
    return out


def inspect_binary(path: Path, *, max_read: int = 8 * 1024 * 1024) -> BinaryReport:
    """Inspect a native binary for imports, strings and packing (FR-5.1)."""
    report = BinaryReport()
    try:
        data = path.read_bytes()[:max_read]
    except OSError as exc:
        report.findings.append(
            PreflightFinding(
                code="binary-unreadable",
                severity=RiskLevel.MEDIUM,
                message=f"binary could not be read: {exc}",
                weight=10,
            )
        )
        return report

    report.file_type = detect_file_type(path)
    report.packed = any(marker in data for marker in _PACKER_MARKERS)

    if report.file_type == "elf":
        imports, libraries = parse_elf_imports(data)
        report.imports = imports[:500]
        report.libraries = libraries[:100]

    strings = _extract_printable_strings(data)
    report.strings = strings
    lowered = data.lower()
    hits = [marker for marker in _SUSPICIOUS_STRINGS if marker.lower() in lowered]

    if report.packed:
        report.findings.append(
            PreflightFinding(
                code="binary-packed",
                severity=RiskLevel.MEDIUM,
                message="binary appears to be packed or obfuscated",
                weight=20,
            )
        )

    network_imports = sorted(
        {s for s in report.imports if s in {"socket", "connect", "connect_ex", "sendto", "recvfrom"}}
    )
    if network_imports:
        report.findings.append(
            PreflightFinding(
                code="binary-network-imports",
                severity=RiskLevel.MEDIUM,
                message="binary imports network functions",
                evidence=", ".join(network_imports[:8]),
                weight=20,
            )
        )

    exec_imports = sorted({s for s in report.imports if s in {"system", "popen", "execve", "execl", "fork"}})
    if exec_imports:
        report.findings.append(
            PreflightFinding(
                code="binary-process-imports",
                severity=RiskLevel.LOW,
                message="binary imports process-spawning functions",
                evidence=", ".join(exec_imports[:8]),
                weight=8,
            )
        )

    credential_hits = [
        s
        for s in report.strings
        if any(marker in s for marker in ("/etc/shadow", "/etc/passwd", ".ssh/", ".aws/", "id_rsa"))
    ]
    if credential_hits:
        report.findings.append(
            PreflightFinding(
                code="binary-credential-strings",
                severity=RiskLevel.HIGH,
                message="binary contains strings that reference credential locations",
                evidence=credential_hits[0][:120],
                weight=35,
            )
        )

    network_strings = [s for s in report.strings if "http://" in s or "https://" in s]
    if network_strings:
        report.findings.append(
            PreflightFinding(
                code="binary-network-strings",
                severity=RiskLevel.MEDIUM,
                message="binary contains URL strings",
                evidence=network_strings[0][:120],
                weight=12,
            )
        )

    if hits and not network_imports and not credential_hits:
        report.findings.append(
            PreflightFinding(
                code="binary-suspicious-strings",
                severity=RiskLevel.LOW,
                message="binary contains strings associated with shell or fetch activity",
                evidence=", ".join(h.decode("utf-8", "replace") for h in hits[:6]),
                weight=5,
            )
        )
    return report
