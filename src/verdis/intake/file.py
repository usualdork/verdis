"""File intake: a Markdown or text file, with its attachments (FR-1.1)."""

from __future__ import annotations

from pathlib import Path

from ..schemas.common import ReportSource
from ..schemas.report import Target
from ..storage.evidence import EvidenceStore, build_report
from .base import IntakeOutcome, read_report_file

__all__ = ["FileIntake"]

#: Files next to the report that are treated as attachments.
ATTACHMENT_SUFFIXES = (
    ".bin", ".dat", ".poc", ".txt", ".sh", ".py", ".js", ".xml",
    ".tar", ".gz", ".zip", ".so", ".elf", ".png", ".jpg", ".pcap", ".core",
)


class FileIntake:
    """Reads a report from the filesystem."""

    name = "file"
    source = ReportSource.FILE

    def __init__(self, store: EvidenceStore) -> None:
        self.store = store

    def fetch(
        self,
        path: str | Path,
        *,
        repo: str = ".",
        ref: str = "",
        reporter: str = "",
        attachments: tuple[str | Path, ...] = (),
    ) -> IntakeOutcome:
        path = Path(path)
        if not path.is_file():
            raise FileNotFoundError(f"report file not found: {path}")
        body, subject = read_report_file(path)

        payloads: list[tuple[str, bytes]] = []
        for candidate in attachments:
            candidate_path = Path(candidate)
            if candidate_path.is_file():
                payloads.append((candidate_path.name, candidate_path.read_bytes()))
        if not attachments:
            for candidate in sorted(path.parent.iterdir()):
                if candidate == path or not candidate.is_file():
                    continue
                if candidate.suffix.lower() in ATTACHMENT_SUFFIXES:
                    payloads.append((candidate.name, candidate.read_bytes()))

        target = Target(repo=repo, ref=ref)
        report = build_report(
            body=body,
            source=self.source,
            reporter=reporter,
            subject=subject,
            target=target,
            original_path=str(path),
        )
        self.store.ensure_report(report.id)
        body_path, stored = self.store.store_original(
            report.id, body, attachments=tuple(payloads), subject=subject
        )
        report = report.model_copy(update={"attachments": stored})
        return IntakeOutcome(report=report, attachments=stored, body_path=body_path)
