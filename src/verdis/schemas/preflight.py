"""Preflight models (PRD FR-5)."""

from __future__ import annotations

from enum import StrEnum
from typing import Self

from pydantic import Field, field_validator, model_validator

from .common import HashableModel

__all__ = ["AttachmentVerdict", "PreflightFinding", "PreflightResult", "RiskLevel"]


class RiskLevel(StrEnum):
    NONE = "none"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AttachmentVerdict(StrEnum):
    SAFE = "safe"
    SUSPICIOUS = "suspicious"
    UNSAFE = "unsafe"


class PreflightFinding(HashableModel):
    """One observed behaviour of an attachment.

    Findings state what was observed. They never characterise the reporter
    (FR-5.4).
    """

    code: str = Field(min_length=1)
    severity: RiskLevel = RiskLevel.LOW
    message: str = ""
    evidence: str = ""
    weight: int = Field(default=0, ge=0)

    @property
    def is_blocking(self) -> bool:
        return self.severity in {RiskLevel.HIGH, RiskLevel.CRITICAL}


class PreflightResult(HashableModel):
    """The preflight outcome for a single attachment."""

    name: str
    file_type: str = "unknown"
    size: int = Field(default=0, ge=0)
    risk_score: int = Field(default=0, ge=0, le=100)
    risk_level: RiskLevel = RiskLevel.NONE
    findings: tuple[PreflightFinding, ...] = ()
    quarantined: bool = False
    reason: str = ""

    @field_validator("findings")
    @classmethod
    def _as_tuple(cls, value: tuple[PreflightFinding, ...] | list[PreflightFinding]) -> tuple[PreflightFinding, ...]:
        return tuple(value)

    @model_validator(mode="after")
    def _derive_level(self) -> Self:
        from .common import Verdict  # noqa: F401  (kept for symmetry of imports)

        if self.risk_score >= 70:
            object.__setattr__(self, "risk_level", RiskLevel.CRITICAL)
        elif self.risk_score >= 45:
            object.__setattr__(self, "risk_level", RiskLevel.HIGH)
        elif self.risk_score >= 20:
            object.__setattr__(self, "risk_level", RiskLevel.MEDIUM)
        elif self.risk_score > 0:
            object.__setattr__(self, "risk_level", RiskLevel.LOW)
        else:
            object.__setattr__(self, "risk_level", RiskLevel.NONE)
        return self

    @property
    def blocked(self) -> bool:
        """True when preflight says this attachment must not run (FR-5.3)."""
        return self.quarantined or self.risk_level in {RiskLevel.HIGH, RiskLevel.CRITICAL}

    @property
    def reasons(self) -> list[str]:
        return [f"{f.code}: {f.message}" for f in self.findings]
