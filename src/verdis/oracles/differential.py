"""Differential oracle: the claimed ref versus a comparison ref (FR-8.2, FR-8.4).

The differential oracle answers "does the claimed behaviour disappear at the
comparison ref". That is what supports the FIXED_AT_HEAD flag, and it is
also how "reproduced, but already fixed" is distinguished from "reproduced
and still present".
"""

from __future__ import annotations

from ..schemas.common import OracleType
from ..schemas.run import OracleResult, RunResult
from .base import Oracle, OracleContext

__all__ = ["DifferentialOracle"]


class DifferentialOracle(Oracle):
    """Compares the primary run with the comparison run."""

    oracle_type = OracleType.DIFFERENTIAL

    def evaluate(self, run: RunResult, context: OracleContext) -> OracleResult:
        comparison = context.comparison_run
        if comparison is None:
            return OracleResult(
                oracle=OracleType.DIFFERENTIAL,
                fired=False,
                reason="no comparison ref was run",
            )

        primary_fired = context.extra.get("primary_fired", "") == "1"
        comparison_fired = context.extra.get("comparison_fired", "") == "1"

        evidence: list[str] = []
        if primary_fired and not comparison_fired:
            evidence.append(
                "the claimed behaviour reproduced at the claimed ref and did not "
                "reproduce at the comparison ref"
            )
        elif primary_fired and comparison_fired:
            evidence.append(
                "the claimed behaviour reproduced at both the claimed ref and the "
                "comparison ref"
            )
        elif not primary_fired and not comparison_fired:
            evidence.append(
                "the claimed behaviour did not reproduce at either the claimed ref "
                "or the comparison ref"
            )
        else:
            evidence.append(
                "the claimed behaviour did not reproduce at the claimed ref but did "
                "reproduce at the comparison ref"
            )

        if comparison.status.value not in {"completed"}:
            evidence.append(
                f"the comparison run did not complete cleanly (status: {comparison.status})"
            )

        if not (primary_fired and not comparison_fired):
            return OracleResult(
                oracle=OracleType.DIFFERENTIAL,
                fired=False,
                reason="the two refs behaved the same way",
                evidence=tuple(evidence),
            )
        return OracleResult(
            oracle=OracleType.DIFFERENTIAL,
            fired=True,
            reason="the behaviour is specific to the claimed ref",
            evidence=tuple(evidence),
            matched_claim=True,
            matching_reason=(
                "the oracle fired at the claimed ref and stayed quiet at the "
                "comparison ref"
            ),
        )
