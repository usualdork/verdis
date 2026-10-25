"""Claim extraction models (PRD FR-2).

A claim is a schema-validated reading of what a report says. Every field
carries the source span it came from, and anything the report does not state
is ``unknown`` rather than invented (FR-2.3).
"""

from __future__ import annotations

from typing import Self

from pydantic import Field, field_validator, model_validator

from .common import HashableModel, SourceSpan, normalize_cwe, normalize_identifier

__all__ = ["Claim", "ClaimComponent", "ClaimImpact", "ExpectedObservable", "PoCArtifact", "PoCCommand"]


class ClaimComponent(HashableModel):
    """Where in the target the claim says the bug lives."""

    name: str = Field(default="", description="Function, module or component name.")
    file: str = Field(default="", description="Path of the offending file.")
    line: int | None = Field(default=None, ge=0)

    @field_validator("name", "file")
    @classmethod
    def _strip(cls, value: str) -> str:
        return value.strip()

    @property
    def key(self) -> str:
        return normalize_identifier(self.name or self.file)


class PoCCommand(HashableModel):
    """A command the reporter says triggers the bug."""

    command: str = Field(min_length=1)
    shell: bool = True
    cwd: str = ""
    span: SourceSpan | None = None

    @field_validator("command")
    @classmethod
    def _strip(cls, value: str) -> str:
        stripped = value.strip()
        if not stripped:
            raise ValueError("command must not be empty")
        return stripped


class PoCArtifact(HashableModel):
    """A file the reporter supplies as part of the PoC."""

    name: str = Field(min_length=1)
    sha256: str = Field(default="", pattern=r"^$|^[0-9a-f]{64}$")
    role: str = Field(default="input", description="input | script | patch | other")
    span: SourceSpan | None = None


class ExpectedObservable(HashableModel):
    """What the reporter says should be observable if the bug is real."""

    kind: str = Field(default="unknown", description="crash | sanitizer | exception | output | none")
    signature: str = Field(default="", description="Text or stack fragment to match.")
    function: str = Field(default="", description="The function the observable should be in.")
    exit_code: int | None = None
    regex: str = ""
    span: SourceSpan | None = None

    @field_validator("kind")
    @classmethod
    def _norm_kind(cls, value: str) -> str:
        return (value or "unknown").strip().lower() or "unknown"


class ClaimImpact(HashableModel):
    """The impact the reporter claims."""

    summary: str = ""
    class_id: str = Field(default="", description="CWE-aligned identifier, e.g. CWE-122.")
    severity_hint: str = ""

    @field_validator("class_id")
    @classmethod
    def _norm_class(cls, value: str) -> str:
        return normalize_cwe(value)


class Claim(HashableModel):
    """The schema-validated claim extracted from a report (FR-2.1)."""

    component: ClaimComponent = Field(default_factory=ClaimComponent)
    vuln_class: str = Field(default="", description="CWE-aligned class identifier.")
    affected_version: str = ""
    affected_commit: str = ""
    preconditions: tuple[str, ...] = ()
    poc_commands: tuple[PoCCommand, ...] = ()
    poc_artifacts: tuple[PoCArtifact, ...] = ()
    impact: ClaimImpact = Field(default_factory=ClaimImpact)
    expected: ExpectedObservable = Field(default_factory=ExpectedObservable)
    config_assumptions: tuple[str, ...] = ()
    non_default_config: bool = False
    source: str = Field(default="heuristic", description="heuristic | model | rrs")
    model_name: str = ""
    missing_fields: tuple[str, ...] = ()
    spans: dict[str, SourceSpan] = Field(default_factory=dict)

    @field_validator("preconditions", "poc_commands", "poc_artifacts", "config_assumptions", "missing_fields")
    @classmethod
    def _as_tuple(cls, value: tuple[object, ...] | list[object]) -> tuple[object, ...]:
        return tuple(value)

    @model_validator(mode="after")
    def _dedupe_spans(self) -> Self:
        if self.vuln_class:
            object.__setattr__(self, "vuln_class", normalize_cwe(self.vuln_class))
        return self

    @property
    def has_poc(self) -> bool:
        """True when the report says how to run the proof of concept.

        An attachment on its own is not a proof of concept: without a
        command there is nothing to run, so the report is still missing
        evidence.
        """
        return bool(self.poc_commands)

    @property
    def is_complete(self) -> bool:
        """True when nothing essential is unknown."""
        return not self.missing_fields

    def span_for(self, field: str) -> SourceSpan | None:
        return self.spans.get(field)
