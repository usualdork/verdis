"""Report, attachment and target models (PRD FR-1)."""

from __future__ import annotations

import re
from datetime import datetime
from typing import Any, Self

from pydantic import Field, field_validator, model_validator

from .common import UTC, HashableModel, ReportSource, now_utc, sha256_text, stable_id

__all__ = ["Attachment", "Report", "Target"]


class Target(HashableModel):
    """The repository and ref a report claims to affect."""

    repo: str = Field(min_length=1, description="Local path or clone URL.")
    ref: str = Field(default="", description="Claimed version, tag or commit.")
    component: str = Field(default="", description="Optional sub-component of the repo.")

    @field_validator("repo", "ref", "component")
    @classmethod
    def _strip(cls, value: str) -> str:
        return value.strip()


class Attachment(HashableModel):
    """A file that arrived with the report (FR-1.2).

    Attachments are hostile input (PRD section 11.1). Nothing here is ever
    executed before preflight has scored it.
    """

    name: str = Field(min_length=1)
    path: str = Field(min_length=1, description="Absolute path in the immutable store.")
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    size: int = Field(ge=0)
    content_type: str = Field(default="application/octet-stream")
    quarantined: bool = False

    @field_validator("content_type")
    @classmethod
    def _default_content_type(cls, value: str) -> str:
        return value.strip() or "application/octet-stream"

    @property
    def is_archived(self) -> bool:
        return self.name.lower().endswith((".zip", ".tar", ".tar.gz", ".tgz", ".tar.bz2", ".xz"))


class Report(HashableModel):
    """A normalized security report (FR-1.2).

    ``body`` is the full report text; ``text`` is the body with attachment
    placeholders removed so that spans stay stable across re-ingestion.
    """

    id: str = Field(min_length=1)
    source: ReportSource = ReportSource.FILE
    received_at: datetime = Field(default_factory=now_utc)
    reporter: str = Field(default="", description="Reporter handle exactly as given.")
    body: str = ""
    subject: str = ""
    attachments: tuple[Attachment, ...] = ()
    target: Target = Field(default_factory=lambda: Target(repo="."))
    labels: tuple[str, ...] = ()
    metadata: dict[str, str] = Field(default_factory=dict)
    original_path: str = ""
    raw_size: int = Field(default=0, ge=0)

    @field_validator("attachments", "labels")
    @classmethod
    def _as_tuple(cls, value: tuple[Any, ...] | list[Any]) -> tuple[Any, ...]:
        return tuple(value)

    @field_validator("received_at")
    @classmethod
    def _ensure_utc(cls, value: datetime) -> datetime:
        return value if value.tzinfo else value.replace(tzinfo=UTC)

    @model_validator(mode="after")
    def _ensure_id(self) -> Self:
        if not self.id:
            raise ValueError("report id is required")  # pragma: no cover
        return self

    @staticmethod
    def compute_id(body: str, target: Target, source: ReportSource) -> str:
        """Content-addressed report id (FR-1.5, section 10.3)."""
        return stable_id(
            "VDS",
            source.value,
            sha256_text(body),
            sha256_text(f"{target.repo}\n{target.ref}"),
            length=10,
        )

    @property
    def attachment_names(self) -> tuple[str, ...]:
        return tuple(a.name for a in self.attachments)

    def attachment_by_name(self, name: str) -> Attachment | None:
        for attachment in self.attachments:
            if attachment.name == name:
                return attachment
        return None


_REPORT_ID_RE = re.compile(r"^VDS-[0-9a-f]{6,32}$")


def is_report_id(value: str) -> bool:
    """True when ``value`` looks like a Verdis report id."""
    return bool(_REPORT_ID_RE.match(value))
