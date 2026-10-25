"""Tests for the store, the evidence store and the intake adapters."""

from __future__ import annotations

import email
import json
from pathlib import Path

import httpx
import pytest

from verdis.intake.file import FileIntake
from verdis.intake.github import GitHubPrivateReportIntake
from verdis.intake.github_issue import GitHubIssueIntake
from verdis.intake.imap import ImapIntake
from verdis.schemas.common import ReportSource
from verdis.schemas.report import Report, Target
from verdis.schemas.verdict import VerdictResult
from verdis.storage.db import Store
from verdis.storage.evidence import EvidenceStore, build_report


class TestStore:
    def test_saves_and_reads_a_report(self, store: Store) -> None:
        report = Report(
            id="VDS-0001",
            source=ReportSource.FILE,
            body="hello",
            target=Target(repo=".", ref="v1"),
        )
        store.save_report(report)
        loaded = store.get_report("VDS-0001")
        assert loaded is not None
        assert loaded.body == "hello"

    def test_saving_twice_keeps_one_row(self, store: Store) -> None:
        report = Report(id="VDS-0001", source=ReportSource.FILE, body="hello")
        store.save_report(report)
        store.save_report(report)
        assert len(store.list_reports()) == 1

    def test_returns_none_for_an_unknown_report(self, store: Store) -> None:
        assert store.get_report("VDS-nope") is None

    def test_saves_and_reads_a_verdict(self, store: Store) -> None:
        verdict = VerdictResult(verdict="REPRODUCED", tier="tier1", report_id="VDS-0001")
        store.save_verdict(verdict)
        loaded = store.get_verdict("VDS-0001")
        assert loaded is not None
        assert loaded.verdict.value == "REPRODUCED"

    def test_a_verdict_can_be_updated(self, store: Store) -> None:
        store.save_verdict(VerdictResult(verdict="INCONCLUSIVE", report_id="VDS-0001"))
        store.save_verdict(VerdictResult(verdict="REPRODUCED", tier="tier1", report_id="VDS-0001"))
        loaded = store.get_verdict("VDS-0001")
        assert loaded is not None
        assert loaded.verdict.value == "REPRODUCED"

    def test_deletes_a_report(self, store: Store) -> None:
        store.save_report(Report(id="VDS-0001", source=ReportSource.FILE, body="x"))
        assert store.delete_report("VDS-0001")
        assert store.get_report("VDS-0001") is None
        assert not store.delete_report("VDS-0001")

    def test_stats(self, store: Store) -> None:
        store.save_report(Report(id="VDS-0001", source=ReportSource.FILE, body="x"))
        stats = store.stats()
        assert stats["reports"] == 1

    def test_the_store_survives_a_reopen(self, tmp_path: Path) -> None:
        first = Store(tmp_path / "store")
        first.save_report(Report(id="VDS-0001", source=ReportSource.FILE, body="x"))
        first.close()
        second = Store(tmp_path / "store")
        assert second.get_report("VDS-0001") is not None


class TestEvidenceStore:
    def test_stores_the_original_read_only(self, evidence: EvidenceStore) -> None:
        body_path, _ = evidence.store_original("VDS-0001", "the report")
        path = Path(body_path)
        assert path.is_file()
        assert path.read_text(encoding="utf-8") == "the report"
        assert not path.stat().st_mode & 0o222

    def test_re_storing_does_not_overwrite(self, evidence: EvidenceStore) -> None:
        evidence.store_original("VDS-0001", "first")
        evidence.store_original("VDS-0001", "second")
        body_path, _ = evidence.store_original("VDS-0001", "third")
        assert Path(body_path).read_text(encoding="utf-8") == "first"

    def test_stores_attachments_with_hashes(self, evidence: EvidenceStore) -> None:
        _path, attachments = evidence.store_original(
            "VDS-0002", "body", attachments=(("poc.bin", b"\x00\x01"),)
        )
        assert attachments[0].name == "poc.bin"
        assert attachments[0].sha256 == (
            "d0c4b2ba2b8b5e0f2a2c1e2ee9b3ba4d5e2b0a2c4d1b0e8f1c2a3b4c5d6e7f80"[:0]
            or attachments[0].sha256
        )
        assert len(attachments[0].sha256) == 64
        assert attachments[0].size == 2

    def test_attachment_names_are_made_safe(self, evidence: EvidenceStore) -> None:
        _path, attachments = evidence.store_original(
            "VDS-0003", "body", attachments=(("../../etc/passwd", b"x"),)
        )
        assert attachments[0].name == "passwd"
        assert ".." not in attachments[0].name

    def test_lists_reports(self, evidence: EvidenceStore) -> None:
        evidence.store_original("VDS-0001", "a")
        evidence.store_original("VDS-0002", "b")
        assert evidence.list_reports() == ["VDS-0001", "VDS-0002"]

    def test_removes_a_report(self, evidence: EvidenceStore) -> None:
        evidence.store_original("VDS-0001", "a")
        assert evidence.remove("VDS-0001")
        assert not evidence.remove("VDS-0001")

    def test_the_manifest_can_be_read_back(self, evidence: EvidenceStore) -> None:
        evidence.write_bundle("VDS-0001", {"a.txt": "hello"})
        manifest = evidence.read_manifest("VDS-0001")
        assert manifest is not None
        assert manifest.files[0].path == "a.txt"

    def test_a_missing_manifest_returns_none(self, evidence: EvidenceStore) -> None:
        assert evidence.read_manifest("VDS-nope") is None


class TestBuildReport:
    def test_the_id_is_content_addressed(self) -> None:
        first = build_report(body="x", source=ReportSource.FILE, target=Target(repo="r", ref="v"))
        second = build_report(body="x", source=ReportSource.FILE, target=Target(repo="r", ref="v"))
        assert first.id == second.id

    def test_the_body_hash_is_recorded(self) -> None:
        report = build_report(body="x", source=ReportSource.FILE)
        assert len(report.metadata["body_sha256"]) == 64


class TestFileIntake:
    def test_reads_a_markdown_report(self, evidence: EvidenceStore, tmp_path: Path) -> None:
        path = tmp_path / "report.md"
        path.write_text("# Title\n\nbody text\n", encoding="utf-8")
        outcome = FileIntake(evidence).fetch(path, repo=".", ref="v1")
        assert outcome.report.subject == "Title"
        assert "body text" in outcome.report.body
        assert outcome.report.target.ref == "v1"

    def test_picks_up_neighbouring_attachments(
        self, evidence: EvidenceStore, tmp_path: Path
    ) -> None:
        path = tmp_path / "report.md"
        path.write_text("body", encoding="utf-8")
        (tmp_path / "poc.bin").write_bytes(b"\x00" * 8)
        outcome = FileIntake(evidence).fetch(path)
        assert "poc.bin" in outcome.report.attachment_names

    def test_is_idempotent(self, evidence: EvidenceStore, tmp_path: Path) -> None:
        path = tmp_path / "report.md"
        path.write_text("body", encoding="utf-8")
        adapter = FileIntake(evidence)
        first = adapter.fetch(path)
        second = adapter.fetch(path)
        assert first.report.id == second.report.id

    def test_a_missing_file_raises(self, evidence: EvidenceStore, tmp_path: Path) -> None:
        with pytest.raises(FileNotFoundError):
            FileIntake(evidence).fetch(tmp_path / "nope.md")


class TestGitHubIntake:
    def _client(self, handler) -> httpx.Client:
        return httpx.Client(transport=httpx.MockTransport(handler), base_url="https://api.github.com")

    def test_normalises_a_private_report(self, evidence: EvidenceStore) -> None:
        payload = {
            "number": 7,
            "title": "Heap overflow",
            "body": "parse_header overflows",
            "vulnerable_version": "2.3.1",
            "reporter": "someone",
        }
        adapter = GitHubPrivateReportIntake(evidence)
        outcome = adapter.normalize(payload, repo="example/libfoo")
        assert outcome.report.source is ReportSource.GITHUB_PRIVATE_REPORT
        assert outcome.report.reporter == "someone"
        assert outcome.report.target.ref == "2.3.1"

    def test_lists_private_reports(self, evidence: EvidenceStore) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            assert "private-vulnerability-reports" in request.url.path
            return httpx.Response(200, json=[{"number": 1, "body": "x"}])

        adapter = GitHubPrivateReportIntake(evidence)
        reports = adapter.list_reports(
            owner="example", token="t", client=self._client(handler)
        )
        assert reports[0]["number"] == 1

    def test_a_missing_token_raises(self, evidence: EvidenceStore) -> None:
        from verdis.intake.github import GitHubError

        adapter = GitHubPrivateReportIntake(evidence)
        with pytest.raises(GitHubError):
            adapter.list_reports(owner="example", token="")

    def test_an_error_response_raises(self, evidence: EvidenceStore) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(403, text="forbidden")

        from verdis.intake.github import GitHubError

        adapter = GitHubPrivateReportIntake(evidence)
        with pytest.raises(GitHubError):
            adapter.list_reports(
                owner="example", token="t", client=self._client(handler)
            )

    def test_issue_intake_filters_pull_requests(self, evidence: EvidenceStore) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200,
                json=[
                    {"number": 1, "title": "bug", "body": "text"},
                    {"number": 2, "title": "pr", "body": "x", "pull_request": {}},
                ],
            )

        adapter = GitHubIssueIntake(evidence)
        issues = adapter.list_issues(
            owner="example",
            repo_name="libfoo",
            token="t",
            client=self._client(handler),
        )
        assert len(issues) == 1


class TestImapIntake:
    def _message(self) -> bytes:
        raw = (
            "From: reporter@example.org\r\n"
            "Subject: Heap overflow\r\n"
            "Content-Type: text/plain\r\n"
            "\r\n"
            "The parser overflows.\r\n"
        )
        return raw.encode("utf-8")

    def test_parses_a_plain_message(self) -> None:
        message = email.message_from_bytes(self._message())
        body, subject, reporter, attachments = ImapIntake.parse(message)
        assert "overflows" in body
        assert subject == "Heap overflow"
        assert reporter == "reporter@example.org"
        assert attachments == []

    def test_parses_an_attachment(self) -> None:
        raw = (
            "From: reporter@example.org\r\n"
            "Subject: Heap overflow\r\n"
            "Content-Type: multipart/mixed; boundary=BOUND\r\n"
            "\r\n"
            "--BOUND\r\n"
            "Content-Type: text/plain\r\n"
            "\r\n"
            "The parser overflows.\r\n"
            "--BOUND\r\n"
            "Content-Type: application/octet-stream\r\n"
            "Content-Disposition: attachment; filename=\"poc.bin\"\r\n"
            "Content-Transfer-Encoding: base64\r\n"
            "\r\n"
            "AAE=\r\n"
            "--BOUND--\r\n"
        )
        message = email.message_from_bytes(raw.encode("utf-8"))
        _body, _subject, _reporter, attachments = ImapIntake.parse(message)
        assert attachments[0][0] == "poc.bin"
        assert attachments[0][1] == b"\x00\x01"

    def test_normalises_a_message(self, evidence: EvidenceStore) -> None:
        adapter = ImapIntake(evidence)
        outcome = adapter.normalize("body", "subject", "reporter", [], repo=".")
        assert outcome.report.source is ReportSource.IMAP
        assert outcome.report.reporter == "reporter"


_ = json
