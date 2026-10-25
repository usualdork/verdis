"""Exception oracle: an uncaught exception in a managed runtime (FR-8.2)."""

from __future__ import annotations

import re

from ..schemas.common import OracleType
from ..schemas.run import OracleResult, RunResult
from .base import Oracle, OracleContext, extract_frames

__all__ = ["ExceptionOracle"]

_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"^Traceback \(most recent call last\):", re.MULTILINE),
    re.compile(r"(?i)\bunhandled exception\b"),
    re.compile(r"(?i)\buncaught exception\b"),
    re.compile(r"(?i)^\s*panic:\s", re.MULTILINE),
    re.compile(r"(?i)\bfatal error:\s"),
    re.compile(r"(?i)\bjava\.lang\.\w+(Exception|Error)\b"),
    re.compile(r"(?i)\bSystem\.(NullReferenceException|IndexOutOfRangeException)\b"),
    re.compile(r"(?i)\bnode\.js.*\b(AssertionError|Error)\b"),
    re.compile(r"(?i)\bpanic: runtime error\b"),
    re.compile(r"(?i)\bassertion failed\b"),
    re.compile(r"(?i)\bAssertionError\b"),
    re.compile(r"(?i)\bsegmentation fault\b"),
    re.compile(r"(?i)\bSystem\.NullReferenceException\b"),
)

_EXCEPTION_LINE = re.compile(
    r"(?im)^(?:[A-Za-z_][\w.]*)?(?:Exception|Error|AssertionError|Panic|Fault)"
    r"[^\n:]{0,60}:?[^\n]{0,160}$"
)


class ExceptionOracle(Oracle):
    """Fires when a managed runtime reported an uncaught exception."""

    oracle_type = OracleType.EXCEPTION

    def evaluate(self, run: RunResult, context: OracleContext) -> OracleResult:
        evidence: list[str] = []
        for index, command in enumerate(run.runs):
            blob = command.combined
            hit = None
            for pattern in _PATTERNS:
                hit = pattern.search(blob)
                if hit is not None:
                    break
            if hit is None:
                continue
            evidence.append(f"run {index + 1}: uncaught exception ({hit.group(0).strip()})")
            line_match = _EXCEPTION_LINE.search(blob)
            if line_match:
                evidence.append(f"run {index + 1}: {line_match.group(0).strip()[:160]}")
            frames = extract_frames(blob)
            if frames:
                evidence.append(f"run {index + 1}: frame #1 {frames[0]}")
            if "Traceback" in blob:
                for raw in blob.splitlines():
                    if raw.strip().startswith("File ") and "line" in raw:
                        evidence.append(f"run {index + 1}: {raw.strip()[:160]}")
                        break

        if not evidence:
            return OracleResult(
                oracle=OracleType.EXCEPTION,
                fired=False,
                reason="no uncaught exception was reported",
            )
        return self._result(
            OracleType.EXCEPTION,
            fired=True,
            reason="an uncaught exception was reported",
            evidence=tuple(evidence),
            context=context,
        )
