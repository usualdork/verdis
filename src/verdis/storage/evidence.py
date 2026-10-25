"""The evidence store: immutable originals and evidence bundles (PRD 8.3).

Layout under the store root::

    reports/<report-id>/
        original/report.md          immutable original text
        original/attachments/*      immutable attachments, hashed
        bundle/                     the evidence bundle (PRD 8.3)

Originals are written once and never modified. The bundle is rewritten on
every re-run, and every file in it is hashed into the manifest.
"""

from __future__ import annotations

import json
import os
import shutil
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ..schemas.bundle import BundleFile, BundleManifest, EnvironmentInfo, ModelInfo
from ..schemas.common import now_utc, sha256_bytes, sha256_file, to_jsonable
from ..schemas.report import Attachment, Report, Target

__all__ = ["EvidenceStore", "StoreError"]


class StoreError(RuntimeError):
    """Raised when the evidence store cannot be written."""


@dataclass
class EvidenceStore:
    """A local, first-party store of reports and evidence bundles."""

    root: Path

    def __post_init__(self) -> None:
        self.root = Path(self.root)
        self.root.mkdir(parents=True, exist_ok=True)

    # -- layout ---------------------------------------------------------

    def report_dir(self, report_id: str) -> Path:
        return self.root / "reports" / report_id

    def original_dir(self, report_id: str) -> Path:
        return self.report_dir(report_id) / "original"

    def bundle_dir(self, report_id: str) -> Path:
        return self.report_dir(report_id) / "bundle"

    def ensure_report(self, report_id: str) -> Path:
        path = self.report_dir(report_id)
        path.mkdir(parents=True, exist_ok=True)
        self.original_dir(report_id).mkdir(parents=True, exist_ok=True)
        return path

    # -- originals ------------------------------------------------------

    def store_original(
        self,
        report_id: str,
        body: str,
        *,
        attachments: tuple[tuple[str, bytes], ...] = (),
        subject: str = "",
    ) -> tuple[str, tuple[Attachment, ...]]:
        """Write the original report and its attachments.

        Files are written read-only; re-ingesting the same report produces
        the same content and does not disturb what is already there.
        """
        original = self.original_dir(report_id)
        original.mkdir(parents=True, exist_ok=True)
        body_path = original / "report.md"
        if not body_path.exists():
            _write_immutable(body_path, body)
        header = f"# {subject}\n\n" if subject else ""
        if subject:
            subject_path = original / "subject.txt"
            if not subject_path.exists():
                _write_immutable(subject_path, subject)

        stored: list[Attachment] = []
        attachment_dir = original / "attachments"
        for name, data in attachments:
            safe_name = _safe_name(name)
            attachment_dir.mkdir(parents=True, exist_ok=True)
            path = attachment_dir / safe_name
            if not path.exists():
                _write_immutable(path, data)
            stored.append(
                Attachment(
                    name=safe_name,
                    path=str(path),
                    sha256=sha256_bytes(data),
                    size=len(data),
                )
            )
        _ = header
        return str(body_path), tuple(stored)

    # -- bundle ---------------------------------------------------------

    def write_bundle(
        self,
        report_id: str,
        files: dict[str, str | bytes],
        *,
        manifest_extra: dict[str, Any] | None = None,
        environment: EnvironmentInfo | None = None,
        model: ModelInfo | None = None,
    ) -> BundleManifest:
        """Write an evidence bundle and return its manifest."""
        bundle = self.bundle_dir(report_id)
        bundle.mkdir(parents=True, exist_ok=True)
        entries: list[BundleFile] = []
        for relative, content in sorted(files.items()):
            path = bundle / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            if isinstance(content, bytes):
                path.write_bytes(content)
            else:
                path.write_text(content, encoding="utf-8")
            entries.append(
                BundleFile(
                    path=relative,
                    sha256=sha256_file(str(path)),
                    size=path.stat().st_size,
                )
            )
        manifest = BundleManifest(
            report_id=report_id,
            created_at=now_utc(),
            tool_version=_tool_version(),
            verdict=str((manifest_extra or {}).get("verdict", "")),
            target=dict((manifest_extra or {}).get("target", {})),
            files=tuple(entries),
            environment=environment or EnvironmentInfo(),
            model=model or ModelInfo(),
            extra={k: v for k, v in (manifest_extra or {}).items() if k not in {"verdict", "target"}},
        )
        manifest_path = bundle / "manifest.json"
        manifest_path.write_text(
            json.dumps(to_jsonable(manifest), indent=2, sort_keys=True),
            encoding="utf-8",
        )
        return manifest

    def read_manifest(self, report_id: str) -> BundleManifest | None:
        path = self.bundle_dir(report_id) / "manifest.json"
        if not path.is_file():
            return None
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return None
        return BundleManifest.model_validate(data)

    def verify_bundle(self, report_id: str) -> list[str]:
        """Re-hash every file in the bundle and report mismatches."""
        manifest = self.read_manifest(report_id)
        if manifest is None:
            return ["no manifest found"]
        problems: list[str] = []
        bundle = self.bundle_dir(report_id)
        for entry in manifest.files:
            path = bundle / entry.path
            if not path.is_file():
                problems.append(f"missing: {entry.path}")
                continue
            digest = sha256_file(str(path))
            if digest != entry.sha256:
                problems.append(f"hash mismatch: {entry.path}")
        for entry in manifest.files:
            if entry.path in {"manifest.json"}:  # pragma: no cover
                continue
        return problems

    # -- helpers --------------------------------------------------------

    def list_reports(self) -> list[str]:
        reports = self.root / "reports"
        if not reports.is_dir():
            return []
        return sorted(p.name for p in reports.iterdir() if p.is_dir())

    def remove(self, report_id: str) -> bool:
        path = self.report_dir(report_id)
        if not path.exists():
            return False
        shutil.rmtree(path, ignore_errors=True)
        return True


def _safe_name(name: str) -> str:
    """Reduce a name to a safe single path segment."""
    base = os.path.basename(name.strip().replace("\\", "/")) or "attachment"
    cleaned = "".join(ch for ch in base if ch.isalnum() or ch in "._-")
    return cleaned[:120] or "attachment"


def _write_immutable(path: Path, content: str | bytes) -> None:
    """Write a file once and mark it read-only."""
    if path.exists():
        return
    if isinstance(content, bytes):
        path.write_bytes(content)
    else:
        path.write_text(content, encoding="utf-8")
    try:
        path.chmod(stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH)
    except OSError:  # pragma: no cover - platform dependent
        pass


def _tool_version() -> str:
    from .. import __version__

    return __version__


def build_report(
    *,
    body: str,
    source: Any,
    reporter: str = "",
    subject: str = "",
    attachments: tuple[Attachment, ...] = (),
    target: Target | None = None,
    metadata: dict[str, str] | None = None,
    labels: tuple[str, ...] = (),
    original_path: str = "",
) -> Report:
    """Build a normalized report (FR-1.2)."""
    target = target or Target(repo=".")
    meta = dict(metadata or {})
    meta.setdefault("body_sha256", sha256_bytes(body.encode("utf-8")))
    report = Report(
        id=Report.compute_id(body, target, source),
        source=source,
        received_at=now_utc(),
        reporter=reporter,
        body=body,
        subject=subject,
        attachments=attachments,
        target=target,
        labels=labels,
        metadata=meta,
        original_path=original_path,
        raw_size=len(body.encode("utf-8")),
    )
    return report
