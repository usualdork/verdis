"""Persistent store: SQLite through SQLModel (PRD 10.1, 10.4).

The store keeps report metadata, verdicts and dedupe fingerprints. The
originals themselves live in the immutable evidence store on disk.
"""

from __future__ import annotations

import json
import os
import sqlite3
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Any

from sqlmodel import Field, Session, SQLModel, col, create_engine, select

from ..schemas.common import now_utc, to_jsonable
from ..schemas.report import Report
from ..schemas.verdict import VerdictResult

__all__ = [
    "DedupeEntry",
    "ReportRow",
    "Store",
    "VerdictRow",
    "default_store_path",
]


class ReportRow(SQLModel, table=True):
    """One ingested report."""

    id: str = Field(primary_key=True)
    source: str = ""
    received_at: datetime = Field(default_factory=now_utc)
    reporter: str = ""
    subject: str = ""
    body_hash: str = ""
    body_path: str = ""
    target_repo: str = ""
    target_ref: str = ""
    verdict: str = ""
    created_at: datetime = Field(default_factory=now_utc)
    payload: str = ""


class VerdictRow(SQLModel, table=True):
    """The verdict of one report."""

    report_id: str = Field(primary_key=True)
    verdict: str = ""
    tier: str = ""
    why: str = ""
    created_at: datetime = Field(default_factory=now_utc)
    payload: str = ""


class JobRow(SQLModel, table=True):
    """One triage job.

    The stage is written as the pipeline advances, so a crash leaves a
    record of how far the report got, and a partial result is never lost.
    """

    report_id: str = Field(primary_key=True)
    stage: str = "intake"
    status: str = "running"
    updated_at: datetime = Field(default_factory=now_utc)
    detail: str = ""


class DedupeEntry(SQLModel, table=True):
    """A fingerprint used for duplicate detection."""

    report_id: str = Field(primary_key=True)
    class_component: str = ""
    stack_signature: str = ""
    poc_hash: str = ""
    text_digest: str = ""
    title: str = ""
    body_text: str = ""
    embedding: str = ""
    created_at: datetime = Field(default_factory=now_utc)


def default_store_path() -> Path:
    """Where the store lives when the user does not say otherwise."""
    env = os.environ.get("VERDIS_HOME")
    if env:
        return Path(env).expanduser()
    xdg = os.environ.get("XDG_DATA_HOME")
    if xdg:
        return Path(xdg).expanduser() / "verdis"
    return Path.home() / ".local" / "share" / "verdis"


class Store:
    """A local-first store of reports, verdicts and fingerprints."""

    def __init__(self, path: str | Path | None = None) -> None:
        self.root = Path(path) if path is not None else default_store_path()
        self.root.mkdir(parents=True, exist_ok=True)
        self.db_path = self.root / "verdis.db"
        self.engine = create_engine(
            f"sqlite:///{self.db_path}",
            connect_args={"check_same_thread": False},
        )
        SQLModel.metadata.create_all(self.engine)

    # -- reports --------------------------------------------------------

    def save_report(self, report: Report, *, body_path: str = "") -> None:
        payload = json.dumps(to_jsonable(report), sort_keys=True)
        with Session(self.engine) as session:
            existing = session.get(ReportRow, report.id)
            if existing is None:
                session.add(
                    ReportRow(
                        id=report.id,
                        source=str(report.source),
                        received_at=report.received_at,
                        reporter=report.reporter,
                        subject=report.subject,
                        body_hash=report.metadata.get("body_sha256", ""),
                        body_path=body_path,
                        target_repo=report.target.repo,
                        target_ref=report.target.ref,
                        created_at=now_utc(),
                        payload=payload,
                    )
                )
            else:
                existing.body_path = body_path or existing.body_path
            session.commit()

    def get_report(self, report_id: str) -> Report | None:
        with Session(self.engine) as session:
            row = session.get(ReportRow, report_id)
            if row is None:
                return None
            return Report.model_validate(json.loads(row.payload))

    def list_reports(self, limit: int = 100) -> list[ReportRow]:
        with Session(self.engine) as session:
            statement = select(ReportRow).order_by(col(ReportRow.created_at).desc()).limit(limit)
            return list(session.exec(statement).all())

    def find_by_body_hash(self, body_hash: str) -> ReportRow | None:
        with Session(self.engine) as session:
            statement = select(ReportRow).where(ReportRow.body_hash == body_hash)
            return session.exec(statement).first()

    # -- verdicts -------------------------------------------------------

    def save_verdict(self, verdict: VerdictResult) -> None:
        payload = json.dumps(to_jsonable(verdict), sort_keys=True)
        with Session(self.engine) as session:
            row = session.get(VerdictRow, verdict.report_id)
            if row is None:
                session.add(
                    VerdictRow(
                        report_id=verdict.report_id,
                        verdict=str(verdict.verdict),
                        tier=str(verdict.tier) if verdict.tier else "",
                        why=verdict.why,
                        created_at=now_utc(),
                        payload=payload,
                    )
                )
            else:
                row.verdict = str(verdict.verdict)
                row.tier = str(verdict.tier) if verdict.tier else ""
                row.why = verdict.why
                row.payload = payload
                row.created_at = now_utc()
            session.commit()

    def get_verdict(self, report_id: str) -> VerdictResult | None:
        with Session(self.engine) as session:
            row = session.get(VerdictRow, report_id)
            if row is None:
                return None
            return VerdictResult.model_validate(json.loads(row.payload))

    def list_verdicts(self, limit: int = 100) -> list[VerdictRow]:
        with Session(self.engine) as session:
            statement = select(VerdictRow).order_by(col(VerdictRow.created_at).desc()).limit(limit)
            return list(session.exec(statement).all())

    # -- jobs -----------------------------------------------------------

    def save_job(self, report_id: str, stage: str, *, status: str = "running", detail: str = "") -> None:
        """Record how far a report got."""
        with Session(self.engine) as session:
            row = session.get(JobRow, report_id)
            if row is None:
                session.add(
                    JobRow(
                        report_id=report_id,
                        stage=stage,
                        status=status,
                        updated_at=now_utc(),
                        detail=detail,
                    )
                )
            else:
                row.stage = stage
                row.status = status
                row.detail = detail
                row.updated_at = now_utc()
            session.commit()

    def get_job(self, report_id: str) -> JobRow | None:
        with Session(self.engine) as session:
            return session.get(JobRow, report_id)

    def list_jobs(self, limit: int = 100) -> list[JobRow]:
        with Session(self.engine) as session:
            statement = select(JobRow).order_by(col(JobRow.updated_at).desc()).limit(limit)
            return list(session.exec(statement).all())

    # -- dedupe ---------------------------------------------------------

    def upsert_dedupe(self, entry: DedupeEntry) -> None:
        with Session(self.engine) as session:
            existing = session.get(DedupeEntry, entry.report_id)
            if existing is None:
                session.add(entry)
            else:
                existing.class_component = entry.class_component
                existing.stack_signature = entry.stack_signature
                existing.poc_hash = entry.poc_hash
                existing.text_digest = entry.text_digest
                existing.title = entry.title
                existing.body_text = entry.body_text
                existing.embedding = entry.embedding
            session.commit()

    def all_dedupe_entries(self) -> list[DedupeEntry]:
        with Session(self.engine) as session:
            return list(session.exec(select(DedupeEntry)).all())

    def delete_report(self, report_id: str) -> bool:
        with Session(self.engine) as session:
            row = session.get(ReportRow, report_id)
            if row is None:
                return False
            session.delete(row)
            verdict_row = session.get(VerdictRow, report_id)
            if verdict_row is not None:
                session.delete(verdict_row)
            dedupe_row = session.get(DedupeEntry, report_id)
            if dedupe_row is not None:
                session.delete(dedupe_row)
            job_row = session.get(JobRow, report_id)
            if job_row is not None:
                session.delete(job_row)
            session.commit()
            return True

    def close(self) -> None:
        self.engine.dispose()

    # -- housekeeping ---------------------------------------------------

    def vacuum(self) -> None:
        with sqlite3.connect(self.db_path) as connection:
            connection.execute("VACUUM")

    def stats(self) -> dict[str, Any]:
        with Session(self.engine) as session:
            reports = len(session.exec(select(ReportRow)).all())
            verdicts = len(session.exec(select(VerdictRow)).all())
            fingerprints = len(session.exec(select(DedupeEntry)).all())
        return {
            "root": str(self.root),
            "db": str(self.db_path),
            "reports": reports,
            "verdicts": verdicts,
            "fingerprints": fingerprints,
        }


def temporary_store(prefix: str = "verdis-store-") -> Path:
    """A throwaway store root, used by tests."""
    return Path(tempfile.mkdtemp(prefix=prefix))
