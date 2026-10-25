"""Sanitizer oracle: ASan, UBSan, MSan or TSan reported something (FR-8.2)."""

from __future__ import annotations

import re

from ..schemas.common import OracleType
from ..schemas.run import OracleResult, RunResult
from .base import Oracle, OracleContext, extract_frames

__all__ = ["SanitizerOracle"]

_SANITIZER_HEADERS = re.compile(
    r"(?i)(==\d+==\s*)?"
    r"(ERROR|WARNING):\s*"
    r"(AddressSanitizer|UndefinedBehaviorSanitizer|MemorySanitizer|ThreadSanitizer|"
    r"LeakSanitizer)"
)
_SANITIZER_CLASSES = re.compile(
    r"(?i)\b(heap-buffer-overflow|stack-buffer-overflow|global-buffer-overflow|"
    r"heap-use-after-free|stack-use-after-return|use-after-poison|"
    r"dynamic-stack-buffer-overflow|stack-overflow|double-free|"
    r"attempting free on address|SEGV on unknown address|"
    r"attempting double-free|runtime error|data race|"
    r"detected memory leaks|use-of-uninitialized-value|"
    r"allocation-size-too-big|out-of-memory|"
    r"requested allocation size|negative-size-param|"
    r"memcpy-param-overlap|strcpy-param-overlap|strcat-param-overlap|"
    r"new-delete-type-mismatch|"
    r"alloc-dealloc-mismatch|stack-buffer-underflow|"
    r"container-overflow|invalid-pointer-pair|"
    r"odr-violation|alloc-dealloc-mismatch)\b"
)


class SanitizerOracle(Oracle):
    """Fires when a sanitizer printed a diagnostic."""

    oracle_type = OracleType.SANITIZER

    def evaluate(self, run: RunResult, context: OracleContext) -> OracleResult:
        evidence: list[str] = []
        wanted = (
            context.expect.function
            or context.claim.expected.function
            or context.claim.component.name
        ).strip()

        for index, command in enumerate(run.runs):
            blob = command.combined
            header = _SANITIZER_HEADERS.search(blob)
            if header is None and "runtime error:" not in blob.lower():
                continue
            sanitizer = header.group(3) if header else "UndefinedBehaviorSanitizer"
            evidence.append(f"run {index + 1}: {sanitizer} reported a diagnostic")
            classes = _SANITIZER_CLASSES.findall(blob)
            if classes:
                unique = list(dict.fromkeys(c for c in classes))
                evidence.append(f"run {index + 1}: sanitizer class {unique[0]}")
                if len(unique) > 1:
                    evidence.append(f"run {index + 1}: also reported {', '.join(unique[1:4])}")
            frames = extract_frames(blob)
            if frames:
                ordered = _order_frames(frames, wanted)
                evidence.append(f"run {index + 1}: frame #1 {ordered[0]}")
                if len(ordered) > 1:
                    evidence.append(f"run {index + 1}: frame #2 {ordered[1]}")

        if not evidence:
            return OracleResult(
                oracle=OracleType.SANITIZER,
                fired=False,
                reason="no sanitizer diagnostic was produced",
            )
        return self._result(
            OracleType.SANITIZER,
            fired=True,
            reason="a sanitizer produced a diagnostic",
            evidence=tuple(evidence),
            context=context,
        )


def _order_frames(frames: tuple[str, ...], wanted: str) -> tuple[str, ...]:
    """Put the frame the claim is about first.

    A stack trace's first frame is often a runtime helper; the frame the
    report names is the one a maintainer needs to see.
    """
    if not wanted:
        return frames
    target = wanted.lower()
    for frame in frames:
        symbol = frame.split(" (")[0].split("+")[0].lower()
        if symbol == target or target in symbol:
            return (frame, *(f for f in frames if f != frame))
    return frames
