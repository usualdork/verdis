"""Shared primitives: enums, source spans, hashing and time helpers.

Everything that crosses a module boundary is a Pydantic model defined in
``verdis.schemas`` so that a published JSON schema can be generated for
each one (PRD section 9.5, 10.3).
"""

from __future__ import annotations

import hashlib
import json
import re
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any, Self

from pydantic import BaseModel, ConfigDict, Field, model_validator

__all__ = [
    "UTC",
    "BudgetExceeded",
    "ConfigDict",
    "Field",
    "HashableModel",
    "OracleType",
    "ReportSource",
    "SourceSpan",
    "Verdict",
    "VerdictFlag",
    "VerdictTier",
    "now_utc",
    "sha256_bytes",
    "sha256_file",
    "sha256_text",
    "stable_id",
    "to_jsonable",
]


def now_utc() -> datetime:
    """Current time as an aware UTC datetime."""
    return datetime.now(UTC)


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_text(text: str) -> str:
    return sha256_bytes(text.encode("utf-8"))


def sha256_file(path: str, chunk_size: int = 1024 * 1024) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        while chunk := handle.read(chunk_size):
            digest.update(chunk)
    return digest.hexdigest()


def to_jsonable(value: Any) -> Any:
    """Recursively convert models/enums/datetimes into JSON-safe primitives."""
    if isinstance(value, BaseModel):
        return value.model_dump(mode="json")
    if isinstance(value, dict):
        return {str(k): to_jsonable(v) for k, v in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [to_jsonable(v) for v in value]
    if isinstance(value, StrEnum):
        return str(value)
    if isinstance(value, datetime):
        return value.isoformat()
    return value


def stable_id(prefix: str, *parts: str, length: int = 12) -> str:
    """Content-addressed identifier.

    The same logical input always yields the same id, which makes ingestion
    idempotent (FR-1.5) and report ids reproducible across machines.
    """
    digest = sha256_text("|".join(parts))
    return f"{prefix}-{digest[:length]}"


class HashableModel(BaseModel):
    """Base model with a stable, order-independent JSON representation."""

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        validate_assignment=True,
        use_enum_values=False,
        populate_by_name=True,
    )

    def canonical_json(self) -> str:
        return json.dumps(to_jsonable(self), sort_keys=True, separators=(",", ":"))

    def fingerprint(self) -> str:
        return sha256_text(self.canonical_json())


class Verdict(StrEnum):
    """The seven verdicts of PRD section 8.1."""

    REPRODUCED = "REPRODUCED"
    NOT_REPRODUCED = "NOT_REPRODUCED"
    INCONCLUSIVE = "INCONCLUSIVE"
    OUT_OF_SCOPE = "OUT_OF_SCOPE"
    DUPLICATE = "DUPLICATE"
    NEEDS_INFO = "NEEDS_INFO"
    UNSAFE_ATTACHMENT = "UNSAFE_ATTACHMENT"


class VerdictFlag(StrEnum):
    """Secondary flags attached to a verdict (PRD section 8.1)."""

    FIXED_AT_HEAD = "FIXED_AT_HEAD"
    DEFAULT_CONFIG_ONLY = "DEFAULT_CONFIG_ONLY"
    NON_DEFAULT_CONFIG = "NON_DEFAULT_CONFIG"
    FLAKY = "FLAKY"
    NEEDS_HUMAN_RECIPE = "NEEDS_HUMAN_RECIPE"


class VerdictTier(StrEnum):
    """REPRODUCED tiers (PRD section 8.1)."""

    TIER_1 = "tier1"
    TIER_2 = "tier2"


class ReportSource(StrEnum):
    FILE = "file"
    GITHUB_PRIVATE_REPORT = "github_private_report"
    GITHUB_ISSUE = "github_issue"
    IMAP = "imap"
    REPORTER_PREFLIGHT = "reporter_preflight"


class OracleType(StrEnum):
    CRASH = "crash"
    SANITIZER = "sanitizer"
    EXCEPTION = "exception"
    CANARY = "canary"
    DIFFERENTIAL = "differential"
    PROPERTY = "property"
    OUTPUT = "output"


class SourceSpan(BaseModel):
    """Where in the report text a fact came from (FR-2.2).

    Offsets are character offsets into the normalized report body. ``quote``
    keeps the literal text so the span can be shown to a human without
    re-reading the whole report.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    start: int = Field(ge=0)
    end: int = Field(ge=0)
    quote: str = ""

    @model_validator(mode="after")
    def _check_order(self) -> Self:
        if self.end < self.start:
            raise ValueError("source span end must not precede start")
        return self

    def overlaps(self, other: SourceSpan) -> bool:
        return self.start < other.end and other.start < self.end


class BudgetExceeded(Exception):
    """Raised when a per-report token, time or cost budget is exhausted."""


_WHITESPACE_RE = re.compile(r"\s+")


def normalize_text(text: str) -> str:
    """Collapse whitespace and strip, for stable comparison and hashing."""
    return _WHITESPACE_RE.sub(" ", text).strip()


def normalize_identifier(text: str) -> str:
    """Normalize a symbol-ish string (function, component, file) for matching."""
    lowered = text.strip().lower()
    lowered = re.sub(r"[\s\-]+", "_", lowered)
    lowered = re.sub(r"[^0-9a-z_.:/]", "", lowered)
    return lowered


def normalize_cwe(value: str) -> str:
    """Normalize a CWE-ish string to ``CWE-<n>`` form, or '' when unknown."""
    match = re.search(r"(\d{1,5})", value or "")
    if not match:
        return ""
    number = int(match.group(1))
    if number <= 0:
        return ""
    return f"CWE-{number}"


__all__ += ["normalize_cwe", "normalize_identifier", "normalize_text"]
