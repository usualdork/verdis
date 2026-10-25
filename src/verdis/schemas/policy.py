"""Policy models (PRD FR-3).

A project describes its own security rules in ``.verdis/policy.yml``. When
that file is absent, hints are derived from ``SECURITY.md`` and
``THREAT_MODEL.md`` and are labelled ``derived, unverified`` until a
maintainer confirms them (FR-3.1).
"""

from __future__ import annotations

from enum import StrEnum
from typing import Self

from pydantic import Field, field_validator, model_validator

from .common import HashableModel

__all__ = [
    "EvidenceRequirements",
    "Policy",
    "PolicyClause",
    "PolicyMatch",
    "PolicyOrigin",
    "PolicyScope",
    "PolicyVerdict",
]


class PolicyOrigin(StrEnum):
    """Where a clause came from."""

    EXPLICIT = "explicit"          # .verdis/policy.yml
    DERIVED = "derived"            # derived from SECURITY.md / THREAT_MODEL.md
    UNVERIFIED = "derived, unverified"  # derived and not yet confirmed by a human


class PolicyVerdict(StrEnum):
    """Result of checking one claim against one policy."""

    IN_SCOPE = "in_scope"
    OUT_OF_SCOPE = "out_of_scope"
    UNSUPPORTED_VERSION = "unsupported_version"
    MISSING_EVIDENCE = "missing_evidence"
    NO_MATCH = "no_match"


class PolicyClause(HashableModel):
    """A single citable rule.

    Clauses always carry a citation: file, heading and line range, so a
    reply can quote the maintainer's own words (FR-3.3, FR-3.4).
    """

    id: str = Field(min_length=1)
    kind: str = Field(min_length=1, description="in_scope | excluded | evidence | version | sla")
    description: str = ""
    file: str = ""
    heading: str = ""
    line_start: int = Field(default=0, ge=0)
    line_end: int = Field(default=0, ge=0)
    quote: str = ""
    origin: PolicyOrigin = PolicyOrigin.EXPLICIT
    version_patterns: tuple[str, ...] = ()
    component_patterns: tuple[str, ...] = ()
    requires_poc: bool | None = None
    default_config_only: bool | None = None
    min_version: str = ""
    severity_rubric: str = ""
    sla_days: int | None = Field(default=None, ge=0)

    @field_validator("version_patterns", "component_patterns")
    @classmethod
    def _as_tuple(cls, value: tuple[str, ...] | list[str]) -> tuple[str, ...]:
        return tuple(value)

    @property
    def citation(self) -> str:
        """Human-readable citation, e.g. ``SECURITY.md:12-18 (Supported versions)``."""
        parts = [self.file or "policy"]
        if self.heading:
            parts.append(self.heading)
        if self.line_end and self.line_end > self.line_start:
            parts.append(f"L{self.line_start}-{self.line_end}")
        return ": ".join(parts[:2]) + (f" {parts[2]}" if len(parts) > 2 else "")

    @property
    def citable(self) -> bool:
        """True when the clause can be quoted back to a reporter."""
        return bool(self.file and (self.quote or self.heading))


class EvidenceRequirements(HashableModel):
    """FR-3.2 evidence requirements."""

    poc_required: bool = True
    default_config_only: bool = True
    min_tested_version: str = ""
    requires_steps: bool = True


class PolicyScope(HashableModel):
    """Supported versions and in-scope components (FR-3.2)."""

    supported_versions: tuple[str, ...] = ()
    in_scope: tuple[str, ...] = ()
    out_of_scope: tuple[str, ...] = ()


class Policy(HashableModel):
    """A project's triage policy."""

    supported_versions: tuple[str, ...] = ()
    in_scope: tuple[str, ...] = ()
    out_of_scope: tuple[str, ...] = ()
    excluded_classes: tuple[PolicyClause, ...] = ()
    evidence: EvidenceRequirements = Field(default_factory=EvidenceRequirements)
    sla: dict[str, str] = Field(default_factory=dict)
    severity_rubric: str = ""
    source_files: tuple[str, ...] = ()
    derived: bool = False
    confirmed: bool = False
    notes: tuple[str, ...] = ()

    @field_validator("supported_versions", "in_scope", "out_of_scope", "source_files", "notes")
    @classmethod
    def _as_tuple(cls, value: tuple[str, ...] | list[str]) -> tuple[str, ...]:
        return tuple(value)

    @model_validator(mode="after")
    def _sync_excluded(self) -> Self:
        if not self.excluded_classes and self.out_of_scope:
            object.__setattr__(
                self,
                "excluded_classes",
                tuple(
                    PolicyClause(
                        id=f"out-of-scope:{pattern}",
                        kind="excluded",
                        description=pattern,
                        component_patterns=(pattern,),
                    )
                    for pattern in self.out_of_scope
                ),
            )
        return self

    @property
    def origin(self) -> PolicyOrigin:
        """Where this policy came from.

        A policy derived from project documentation is labelled
        "derived, unverified" until a maintainer confirms it (FR-3.1).
        """
        if self.confirmed:
            return PolicyOrigin.EXPLICIT
        if self.derived:
            return PolicyOrigin.UNVERIFIED
        return PolicyOrigin.UNVERIFIED

    def all_clauses(self) -> tuple[PolicyClause, ...]:
        clauses: list[PolicyClause] = []
        for pattern in self.supported_versions:
            clauses.append(
                PolicyClause(
                    id=f"supported-version:{pattern}",
                    kind="version",
                    description=f"Supported versions: {pattern}",
                    version_patterns=(pattern,),
                )
            )
        for pattern in self.in_scope:
            clauses.append(
                PolicyClause(
                    id=f"in-scope:{pattern}",
                    kind="in_scope",
                    description=f"In scope: {pattern}",
                    component_patterns=(pattern,),
                )
            )
        clauses.extend(self.excluded_classes)
        return tuple(clauses)


class PolicyMatch(HashableModel):
    """The outcome of checking a claim against the policy."""

    verdict: PolicyVerdict = PolicyVerdict.NO_MATCH
    clause: PolicyClause | None = None
    reason: str = ""
    missing: tuple[str, ...] = ()

    @field_validator("missing")
    @classmethod
    def _as_tuple(cls, value: tuple[str, ...] | list[str]) -> tuple[str, ...]:
        return tuple(value)

    @property
    def citation(self) -> str:
        return self.clause.citation if self.clause else ""
