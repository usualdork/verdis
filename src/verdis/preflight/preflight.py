"""Attachment preflight (FR-5).

Preflight runs before anything executes. Attachments above the risk
threshold are marked UNSAFE_ATTACHMENT and quarantined; they run only if a
maintainer overrides with a logged decision (FR-5.3).

Findings state observed behaviour only. Nothing here labels a reporter
malicious (FR-5.4).
"""

from __future__ import annotations

import importlib.util
import os
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ..schemas.preflight import PreflightFinding, PreflightResult, RiskLevel
from ..schemas.report import Attachment
from .analyzers import detect_file_type, inspect_archive, inspect_binary, inspect_script

__all__ = ["DEFAULT_THRESHOLD", "Preflight", "PreflightDecision"]

DEFAULT_THRESHOLD = 45


@dataclass
class PreflightDecision:
    """The overall decision for a set of attachments."""

    results: tuple[PreflightResult, ...]
    threshold: int = DEFAULT_THRESHOLD

    @property
    def blocked(self) -> bool:
        return any(result.blocked for result in self.results)

    @property
    def quarantined(self) -> tuple[str, ...]:
        return tuple(result.name for result in self.results if result.blocked)

    @property
    def max_score(self) -> int:
        return max((r.risk_score for r in self.results), default=0)

    def reasons(self) -> list[str]:
        out: list[str] = []
        for result in self.results:
            if result.blocked:
                out.extend(f"{result.name}: {reason}" for reason in result.reasons)
        return out


def load_plugin(path: str) -> Any | None:
    """Load an optional plugin from a file.

    The plugin is a module the operator keeps wherever they like, so it
    is loaded by path rather than imported. A plugin that will not load
    is not an error: the built-in analysis still runs, and the operator
    is told the plugin did not load.
    """
    if not path:
        return None
    source = Path(path)
    if not source.is_file():
        return None
    try:
        spec = importlib.util.spec_from_file_location(
            "verdis_preflight_plugin", source
        )
        if spec is None or spec.loader is None:
            return None
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
    except Exception:
        return None
    return module


class Preflight:
    """Static inspection of attachments."""

    def __init__(
        self,
        threshold: int = DEFAULT_THRESHOLD,
        *,
        plugin: str = "",
    ) -> None:
        self.threshold = threshold
        self.plugin_path = plugin
        self._plugin: Any | None = None
        self._plugin_loaded = False

    @property
    def plugin(self) -> Any | None:
        """The optional plugin, if one is configured and it loads."""
        if not self._plugin_loaded:
            self._plugin_loaded = True
            self._plugin = load_plugin(self.plugin_path)
        return self._plugin

    def _plugin_findings(self, path: Path) -> list[PreflightFinding]:
        """The plugin's findings, if the plugin can run.

        The plugin inspects binaries with REA, which is not a sandbox, so
        it refuses to run unless it is told it is inside one. When it
        cannot run, the built-in analysis stands on its own.
        """
        module = self.plugin
        if module is None:
            return []
        plugin = getattr(module, "ReaPreflight", None)
        if plugin is None:
            return []
        try:
            instance = plugin()
            if not instance.available():
                return []
            return list(instance.findings(path))
        except Exception:
            # A plugin that fails is not a reason to stop the triage.
            return []

    def inspect(self, attachment: Attachment) -> PreflightResult:
        """Inspect one attachment and score it."""
        path = Path(attachment.path)
        findings: list[PreflightFinding] = []
        file_type = detect_file_type(path)

        if not path.exists():
            findings.append(
                PreflightFinding(
                    code="attachment-missing",
                    severity=RiskLevel.MEDIUM,
                    message="attachment is not present in the store",
                    weight=20,
                )
            )
            return PreflightResult(
                name=attachment.name,
                file_type="missing",
                size=0,
                findings=tuple(findings),
                quarantined=True,
                reason="attachment file is missing from the store",
            )

        size = attachment.size or path.stat().st_size
        findings.extend(self._check_permissions(path))
        findings.extend(self._check_size(size))

        if file_type == "unreadable":
            findings.append(
                PreflightFinding(
                    code="attachment-unreadable",
                    severity=RiskLevel.MEDIUM,
                    message="the attachment could not be read, so it was not analysed",
                    weight=20,
                )
            )
        elif file_type in {"zip", "tar", "gzip", "bzip2", "xz"}:
            findings.extend(inspect_archive(path).findings)
        elif file_type == "script":
            findings.extend(inspect_script(path))
        elif file_type in {"elf", "pe", "macho"}:
            findings.extend(inspect_binary(path).findings)
        elif file_type == "text":
            findings.extend(self._check_text(path))
        elif file_type == "binary":
            findings.append(
                PreflightFinding(
                    code="binary-opaque",
                    severity=RiskLevel.LOW,
                    message="file is an unrecognised binary format and was not analysed further",
                    weight=5,
                )
            )

        if file_type in {"elf", "pe", "macho"}:
            findings.extend(self._plugin_findings(path))

        score = min(100, sum(finding.weight for finding in findings))
        blocked = score >= self.threshold
        return PreflightResult(
            name=attachment.name,
            file_type=file_type,
            size=size,
            risk_score=score,
            findings=tuple(findings),
            quarantined=blocked,
            reason=(
                "risk score "
                f"{score} is at or above the threshold of {self.threshold}"
                if blocked
                else ""
            ),
        )

    def inspect_all(self, attachments: tuple[Attachment, ...]) -> PreflightDecision:
        results = tuple(self.inspect(attachment) for attachment in attachments)
        return PreflightDecision(results=results, threshold=self.threshold)

    # -- helpers --------------------------------------------------------

    @staticmethod
    def _check_permissions(path: Path) -> list[PreflightFinding]:
        findings: list[PreflightFinding] = []
        try:
            mode = path.stat().st_mode
        except OSError:
            return findings
        if mode & stat.S_IEXEC and not os.access(path, os.R_OK):
            findings.append(
                PreflightFinding(
                    code="executable-not-readable",
                    severity=RiskLevel.LOW,
                    message="file is marked executable but is not readable",
                    weight=5,
                )
            )
        if mode & stat.S_ISUID:
            findings.append(
                PreflightFinding(
                    code="setuid-file",
                    severity=RiskLevel.HIGH,
                    message="file carries the setuid bit",
                    weight=50,
                )
            )
        return findings

    @staticmethod
    def _check_size(size: int) -> list[PreflightFinding]:
        if size > 256 * 1024 * 1024:
            return [
                PreflightFinding(
                    code="attachment-too-large",
                    severity=RiskLevel.MEDIUM,
                    message=f"attachment is {size} bytes, above the 256 MiB review threshold",
                    weight=15,
                )
            ]
        return []

    @staticmethod
    def _check_text(path: Path) -> list[PreflightFinding]:
        """A plain text file that is not a script can still be hostile."""
        findings: list[PreflightFinding] = []
        try:
            head = path.read_bytes()[:64_000].decode("utf-8", errors="replace")
        except OSError:
            return findings
        if head.startswith("-----BEGIN "):
            findings.append(
                PreflightFinding(
                    code="text-private-key",
                    severity=RiskLevel.HIGH,
                    message="file contains a PEM private key block",
                    evidence=head.splitlines()[0][:80],
                    weight=40,
                )
            )
        return findings
