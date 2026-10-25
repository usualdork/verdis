"""Intake adapters (PRD FR-1).

Every adapter normalises its input into the same :class:`Report` object and
returns it. Re-ingesting the same report yields the same id and no
duplicate run (FR-1.5).
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Protocol, runtime_checkable

from ..schemas.common import ReportSource
from ..schemas.report import Attachment, Report

__all__ = ["IntakeAdapter", "IntakeOutcome", "read_report_file"]


@dataclass
class IntakeOutcome:
    """What an adapter produced."""

    report: Report
    attachments: tuple[Attachment, ...] = ()
    body_path: str = ""
    duplicate_of: str = ""

    @property
    def is_duplicate(self) -> bool:
        return bool(self.duplicate_of)


@runtime_checkable
class IntakeAdapter(Protocol):
    """The interface every intake adapter implements."""

    name: str
    source: ReportSource

    def fetch(self, *args: object, **kwargs: object) -> IntakeOutcome:
        ...


def read_report_file(path: str | Path) -> tuple[str, str]:
    """Read a report file and return ``(body, subject)``."""
    path = Path(path)
    raw = path.read_text(encoding="utf-8", errors="replace")
    subject = ""
    for line in raw.splitlines()[:20]:
        if line.startswith("# "):
            subject = line[2:].strip()
            break
    return raw, subject
