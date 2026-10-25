"""Verdict models (PRD section 8)."""

from __future__ import annotations

from typing import Self

from pydantic import Field, field_validator, model_validator

from .common import HashableModel, Verdict, VerdictFlag, VerdictTier
from .policy import PolicyMatch
from .run import BuildResult, RunResult

__all__ = ["DedupeMatch", "EvidencePoint", "VerdictResult"]


class EvidencePoint(HashableModel):
    """One inspectable fact behind a verdict (PRD 8.4)."""

    summary: str
    artifact: str = ""
    detail: str = ""


class DedupeMatch(HashableModel):
    """A duplicate candidate (FR-4.4).

    Matches are suggestions only; nothing is ever merged automatically
    (FR-4.5, section 11.4 item 8).
    """

    candidate_id: str
    similarity: float = Field(ge=0.0, le=1.0)
    reasons: tuple[str, ...] = ()
    source: str = "local"
    title: str = ""
    url: str = ""

    @field_validator("reasons")
    @classmethod
    def _as_tuple(cls, value: tuple[str, ...] | list[str]) -> tuple[str, ...]:
        return tuple(value)


class VerdictResult(HashableModel):
    """The final verdict and everything a human needs to trust it."""

    verdict: Verdict
    report_id: str = ""
    target_ref: str = ""
    tier: VerdictTier | None = None
    flags: tuple[VerdictFlag, ...] = ()
    why: str = ""
    evidence: tuple[EvidencePoint, ...] = ()
    policy_matches: tuple[PolicyMatch, ...] = ()
    dedupe_matches: tuple[DedupeMatch, ...] = ()
    next_action: str = ""
    not_established: tuple[str, ...] = ()
    build: BuildResult | None = None
    run: RunResult | None = None
    comparison_run: RunResult | None = None
    bundle_path: str = ""
    model_name: str = ""
    model_cost_usd: float = Field(
        default=0.0,
        ge=0.0,
        description=(
            "The modelled cost of the model calls for this report, in US "
            "dollars. It is zero when no model was used."
        ),
    )
    duration_ms: int = Field(default=0, ge=0)

    @field_validator("flags", "evidence", "policy_matches", "dedupe_matches", "not_established")
    @classmethod
    def _as_tuple(cls, value: tuple[object, ...] | list[object]) -> tuple[object, ...]:
        return tuple(value)

    @model_validator(mode="after")
    def _tier_consistency(self) -> Self:
        if self.verdict is Verdict.REPRODUCED and self.tier is None:
            raise ValueError("REPRODUCED verdicts must carry a tier")
        if self.verdict is not Verdict.REPRODUCED and self.tier is not None:
            raise ValueError("only REPRODUCED verdicts carry a tier")
        return self

    @property
    def is_definitive(self) -> bool:
        """Definitive verdicts assert something about the claim itself.

        NEEDS_INFO, INCONCLUSIVE and UNSAFE_ATTACHMENT defer to a human.
        """
        return self.verdict in {
            Verdict.REPRODUCED,
            Verdict.NOT_REPRODUCED,
            Verdict.OUT_OF_SCOPE,
            Verdict.DUPLICATE,
        }

    def flag_set(self) -> set[VerdictFlag]:
        return set(self.flags)
