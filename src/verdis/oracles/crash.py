"""Crash oracle: the process died from a signal (FR-8.2)."""

from __future__ import annotations

import re

from ..schemas.common import OracleType
from ..schemas.run import OracleResult, RunResult
from .base import Oracle, OracleContext, extract_frames, signal_name

__all__ = ["CrashOracle"]

_CRASH_TEXT = re.compile(
    r"(?i)\b(segmentation fault|segfault|core dumped|core dump|"
    r"stack smashing detected|double free or corruption|"
    r"illegal instruction|bus error|floating point exception)\b"
)


class CrashOracle(Oracle):
    """Fires when the run died from a signal or printed a crash message."""

    oracle_type = OracleType.CRASH

    def evaluate(self, run: RunResult, context: OracleContext) -> OracleResult:
        evidence: list[str] = []
        for index, command in enumerate(run.runs):
            if command.signal is not None:
                evidence.append(
                    f"run {index + 1} died from {signal_name(command.signal)} "
                    f"(signal {command.signal})"
                )
            if command.exit_code is not None and command.exit_code < 0:
                evidence.append(
                    f"run {index + 1} exited with signal {-command.exit_code}"
                )
            match = _CRASH_TEXT.search(command.combined)
            if match:
                evidence.append(f"run {index + 1} reported: {match.group(0)}")

        if not evidence:
            return OracleResult(
                oracle=OracleType.CRASH,
                fired=False,
                reason="no run died from a signal and no crash message was printed",
            )

        frames = extract_frames(run.combined_output)
        if frames:
            evidence.append("top frames: " + " | ".join(frames[:4]))
        return self._result(
            OracleType.CRASH,
            fired=True,
            reason="the process crashed",
            evidence=tuple(evidence),
            context=context,
        )
