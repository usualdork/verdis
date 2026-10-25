"""Oracle interface and shared matching helpers (PRD FR-8.2, FR-8.3).

An oracle turns an observed run into a factual statement: "this fired",
"this did not fire", "this fired but does not match the claim".

Oracles never decide a verdict and never read a model's opinion. The judge
combines their results with the deterministic rules of section 8.2.
"""

from __future__ import annotations

import re
from abc import ABC, abstractmethod
from dataclasses import dataclass, field

from ..schemas.claim import Claim
from ..schemas.common import OracleType, normalize_text
from ..schemas.plan import ExpectStep
from ..schemas.run import OracleResult, RunResult
from .frames import extract_frames as _extract_frames

__all__ = ["Oracle", "OracleContext", "extract_frames", "matches_claim", "signal_name"]

_SIGNAL_NAMES = {
    4: "SIGILL",
    6: "SIGABRT",
    7: "SIGBUS",
    8: "SIGFPE",
    9: "SIGKILL",
    11: "SIGSEGV",
    13: "SIGPIPE",
    15: "SIGTERM",
    24: "SIGXCPU",
    25: "SIGXFSZ",
}


def _names_a_function(evidence: tuple[str, ...]) -> bool:
    """Does the evidence name any function at all?

    The oracle's evidence names a function when it has one: "frame #1
    parse_header (hdr.c:12)" or "top frames: ...". An oracle whose
    output has no stack names none.
    """
    return any("frame #" in line or "top frames:" in line for line in evidence)


def signal_name(number: int | None) -> str:
    """Human name of a POSIX signal number."""
    if number is None:
        return ""
    return _SIGNAL_NAMES.get(number, f"SIG{number}")


def extract_frames(output: str, limit: int = 12) -> tuple[str, ...]:
    """Pull the leading stack frames out of a crash or sanitizer report."""
    return _extract_frames(output, limit=limit)


def matches_claim(
    *,
    evidence: tuple[str, ...],
    expect: ExpectStep,
    claim: Claim,
) -> tuple[bool, str]:
    """Does this evidence match the claim? (FR-8.3)

    Returns ``(matched, reasoning)``. The reasoning is always shown to the
    maintainer, because "a crash happened" is not the same as "the claimed
    crash happened".
    """
    blob = normalize_text(" ".join(evidence))
    lowered = blob.lower()

    expected_signature = expect.signature.strip()
    expected_function = (expect.function or claim.expected.function or "").strip()
    claimed_function = (claim.component.name or "").strip()

    signature_ok = True
    if expected_signature:
        signature_ok = expected_signature.lower() in lowered
        if not signature_ok:
            # The signature may be a loose description, so try the salient
            # words of it before declaring a mismatch.
            words = [w for w in re.split(r"\W+", expected_signature.lower()) if len(w) > 3]
            signature_ok = bool(words) and all(word in lowered for word in words[:3])

    function_ok = True
    function_target = expected_function or claimed_function
    if function_target:
        target = function_target.lower()
        function_ok = target in lowered or target.split(".")[-1] in lowered
        if not function_ok:
            function_ok = False

    if expected_signature and not signature_ok:
        return False, (
            f"expected signature {expected_signature!r} was not present in the output"
        )
    if function_target and not function_ok:
        if expected_signature and not _names_a_function(evidence):
            # The evidence names no function at all. A sanitizer that
            # aborts early prints no stack, and a crash with no stack is
            # not evidence of a *different* function: it is an absence of
            # evidence. The signature decides, and the caveat is recorded.
            return (
                True,
                f"signature {expected_signature!r} matches; the location could not "
                f"be confirmed because the output names no function",
            )
        return False, (
            f"the oracle fired, but not in {function_target!r} as the claim states"
        )
    if expected_signature and function_target:
        return True, (
            f"signature {expected_signature!r} and function {function_target!r} both match"
        )
    if expected_signature:
        return True, f"signature {expected_signature!r} matches"
    if function_target:
        return True, f"function {function_target!r} matches"
    return True, "the oracle fired and the claim states no narrower expectation"


@dataclass
class OracleContext:
    """Everything an oracle may look at besides the run itself."""

    claim: Claim
    expect: ExpectStep
    comparison_run: RunResult | None = None
    canary_secret: str = ""
    property_script: str = ""
    property_result: RunResult | None = None
    extra: dict[str, str] = field(default_factory=dict)


class Oracle(ABC):
    """Base class for every oracle."""

    oracle_type: OracleType

    def applies(self, expect: ExpectStep) -> bool:
        """True when this oracle can answer the given expectation."""
        return expect.oracle is self.oracle_type

    @abstractmethod
    def evaluate(self, run: RunResult, context: OracleContext) -> OracleResult:
        """Evaluate one oracle against a run."""
        ...

    # -- helpers --------------------------------------------------------

    @staticmethod
    def _result(
        oracle_type: OracleType,
        *,
        fired: bool,
        reason: str,
        evidence: tuple[str, ...] = (),
        context: OracleContext | None = None,
    ) -> OracleResult:
        matched = False
        reasoning = reason
        if fired and context is not None:
            matched, reasoning = matches_claim(
                evidence=evidence, expect=context.expect, claim=context.claim
            )
        return OracleResult(
            oracle=oracle_type,
            fired=fired,
            reason=reason if not fired else "",
            evidence=evidence,
            matched_claim=matched,
            matching_reason=reasoning,
        )
