"""Tests for the attachment analyzers and the GitHub intakes.

The analyzers look at hostile files, so every branch matters: an archive
that cannot be read, a script that is not text, a binary that is not an
ELF, and an API response that is not what was expected.
"""

from __future__ import annotations

import base64
import io
import tarfile
import zipfile
from pathlib import Path

import httpx
import pytest

from verdis.intake.github import GitHubError, GitHubPrivateReportIntake
from verdis.intake.github_issue import GitHubIssueIntake
from verdis.preflight.analyzers import (
    detect_file_type,
    inspect_archive,
    inspect_binary,
    inspect_script,
)
from verdis.storage.evidence import EvidenceStore


def _client(handler) -> httpx.Client:
    return httpx.Client(transport=httpx.MockTransport(handler), base_url="https://api.github.com")


class TestFileTypes:
    def test_a_tar_is_detected_by_its_header(self, tmp_path: Path) -> None:
        path = tmp_path / "a.tar"
        with tarfile.open(path, "w") as archive:
            info = tarfile.TarInfo("a.txt")
            info.size = 0
            archive.addfile(info, io.BytesIO(b""))
        assert detect_file_type(path) == "tar"

    def test_binary_data_is_detected(self, tmp_path: Path) -> None:
        path = tmp_path / "a.bin"
        path.write_bytes(b"\xff\xfe\x00\x01\x02\x03")
        assert detect_file_type(path) == "binary"

    def test_an_unreadable_file_is_reported(self, tmp_path: Path) -> None:
        path = tmp_path / "a.bin"
        path.write_bytes(b"x")
        path.chmod(0o000)
        try:
            assert detect_file_type(path) == "unreadable"
        finally:
            path.chmod(0o600)


class TestArchives:
    def test_a_tar_with_a_symlink_is_flagged(self, tmp_path: Path) -> None:
        path = tmp_path / "a.tar"
        with tarfile.open(path, "w") as archive:
            info = tarfile.TarInfo("link")
            info.type = tarfile.SYMTYPE
            info.linkname = "/etc/passwd"
            archive.addfile(info)
        report = inspect_archive(path)
        assert any(f.code == "archive-symlink" for f in report.findings)

    def test_a_tar_with_a_device_is_flagged(self, tmp_path: Path) -> None:
        path = tmp_path / "a.tar"
        with tarfile.open(path, "w") as archive:
            info = tarfile.TarInfo("dev")
            info.type = tarfile.CHRTYPE
            info.devmajor = 1
            info.devminor = 3
            archive.addfile(info)
        report = inspect_archive(path)
        assert any(f.code == "archive-device-entry" for f in report.findings)

    def test_a_zip_with_a_symlink_is_flagged(self, tmp_path: Path) -> None:
        path = tmp_path / "a.zip"
        with zipfile.ZipFile(path, "w") as archive:
            info = zipfile.ZipInfo("link")
            info.create_system = 3
            info.external_attr = (0o120777 << 16) | 0o777
            archive.writestr(info, "/etc/passwd")
        report = inspect_archive(path)
        assert any(f.code == "archive-symlink" for f in report.findings)

    def test_a_file_that_is_not_an_archive(self, tmp_path: Path) -> None:
        path = tmp_path / "a.zip"
        path.write_bytes(b"not a zip at all")
        report = inspect_archive(path)
        assert report.kind == "unknown"

    def test_too_many_entries_are_flagged(self, tmp_path: Path) -> None:
        path = tmp_path / "many.zip"
        with zipfile.ZipFile(path, "w") as archive:
            for index in range(20):
                archive.writestr(f"file{index}.txt", "x")
        report = inspect_archive(path)
        assert report.entries == 20

    def test_an_expanding_archive_is_flagged(self, tmp_path: Path) -> None:
        path = tmp_path / "bomb.zip"
        with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("big.bin", b"\x00" * (4 * 1024 * 1024))
        report = inspect_archive(path)
        assert any(f.code == "archive-compression-bomb" for f in report.findings)

    def test_an_archive_over_the_size_limit_is_flagged(self, tmp_path: Path) -> None:
        path = tmp_path / "big.zip"
        with zipfile.ZipFile(path, "w", zipfile.ZIP_STORED) as archive:
            archive.writestr("big.bin", b"\x00" * 4096)
        report = inspect_archive(path, max_total_size=1024)
        assert any(f.code == "archive-too-large" for f in report.findings)


class TestScripts:
    def test_an_unreadable_script_is_reported(self, tmp_path: Path) -> None:
        path = tmp_path / "run.sh"
        path.write_text("x")
        path.chmod(0o000)
        try:
            findings = inspect_script(path)
            assert any(f.code == "script-unreadable" for f in findings)
        finally:
            path.chmod(0o600)

    def test_a_script_that_is_not_text_is_still_inspected(
        self, tmp_path: Path
    ) -> None:
        path = tmp_path / "run.sh"
        path.write_bytes(b"\xff\xfe cat ~/.ssh/id_rsa \x00")
        findings = inspect_script(path)
        assert any(f.code == "script-credential-access" for f in findings)


class TestBinaries:
    def test_a_binary_that_is_not_elf_has_no_imports(self, tmp_path: Path) -> None:
        path = tmp_path / "a.bin"
        path.write_bytes(b"MZ" + b"\x00" * 100)
        report = inspect_binary(path)
        assert report.imports == []

    def test_a_binary_with_network_imports_is_flagged(self, tmp_path: Path) -> None:
        from tests.unit.test_elf_and_backends import _build_elf

        path = tmp_path / "net.elf"
        path.write_bytes(_build_elf(["printf", "socket", "connect"], ["libc.so.6"]))
        report = inspect_binary(path)
        assert any(f.code == "binary-network-imports" for f in report.findings)

    def test_a_binary_with_process_imports_is_flagged(self, tmp_path: Path) -> None:
        from tests.unit.test_elf_and_backends import _build_elf

        path = tmp_path / "exec.elf"
        path.write_bytes(_build_elf(["system", "popen"], ["libc.so.6"]))
        report = inspect_binary(path)
        assert any(f.code == "binary-process-imports" for f in report.findings)

    def test_a_binary_with_a_url_is_flagged(self, tmp_path: Path) -> None:
        path = tmp_path / "url.bin"
        path.write_bytes(b"\x7fELF" + b"http://example.org/x\x00" + b"\x00" * 64)
        report = inspect_binary(path)
        assert any(f.code == "binary-network-strings" for f in report.findings)

    def test_a_binary_with_suspicious_strings_is_flagged(self, tmp_path: Path) -> None:
        path = tmp_path / "sh.bin"
        path.write_bytes(b"\x7fELF" + b"/bin/sh\x00" + b"\x00" * 64)
        report = inspect_binary(path)
        assert any(f.code == "binary-suspicious-strings" for f in report.findings)


class TestGitHubPrivateReports:
    def test_the_reports_are_fetched_and_normalised(
        self, evidence: EvidenceStore
    ) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200,
                json=[
                    {
                        "number": 7,
                        "title": "Heap overflow",
                        "body": "parse_header overflows",
                        "vulnerable_version": "2.3.1",
                        "reporter": "someone",
                    }
                ],
            )

        adapter = GitHubPrivateReportIntake(evidence)
        outcomes = adapter.fetch(
            owner="example",
            repo="example/libfoo",
            token="t",
            client=_client(handler),
        )
        assert outcomes[0].report.target.ref == "2.3.1"
        assert outcomes[0].report.reporter == "someone"

    def test_a_repository_endpoint_is_tried_when_the_org_one_404s(
        self, evidence: EvidenceStore
    ) -> None:
        seen: list[str] = []

        def handler(request: httpx.Request) -> httpx.Response:
            seen.append(request.url.path)
            if "/orgs/" in request.url.path:
                return httpx.Response(404, text="no")
            return httpx.Response(200, json=[])

        adapter = GitHubPrivateReportIntake(evidence)
        adapter.list_reports(owner="example", token="t", client=_client(handler))
        assert any("/repos/" in path for path in seen)

    def test_a_paginated_response_is_unwrapped(self, evidence: EvidenceStore) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json={"items": [{"number": 1, "body": "x"}]})

        adapter = GitHubPrivateReportIntake(evidence)
        reports = adapter.list_reports(
            owner="example", token="t", client=_client(handler)
        )
        assert reports[0]["number"] == 1

    def test_an_attachment_is_decoded(self, evidence: EvidenceStore) -> None:
        payload = {
            "number": 1,
            "body": "x",
            "attachments": [
                {
                    "filename": "poc.bin",
                    "content": base64.b64encode(b"\x00\x01").decode(),
                }
            ],
        }
        adapter = GitHubPrivateReportIntake(evidence)
        outcome = adapter.normalize(payload, repo="example/libfoo")
        assert outcome.report.attachment_names == ("poc.bin",)

    def test_an_attachment_that_is_not_base64_is_skipped(
        self, evidence: EvidenceStore
    ) -> None:
        payload = {
            "number": 1,
            "body": "x",
            "attachments": [{"filename": "poc.bin", "content": "!!!not base64!!!"}],
        }
        adapter = GitHubPrivateReportIntake(evidence)
        outcome = adapter.normalize(payload, repo="example/libfoo")
        assert outcome.report.attachment_names == ()

    def test_an_error_response_is_reported(self, evidence: EvidenceStore) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(403, text="forbidden")

        adapter = GitHubPrivateReportIntake(evidence)
        with pytest.raises(GitHubError):
            adapter.list_reports(
                owner="example", token="t", client=_client(handler)
            )


class TestGitHubIssues:
    def test_the_issues_are_fetched_and_normalised(
        self, evidence: EvidenceStore
    ) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200,
                json=[
                    {
                        "number": 1,
                        "title": "bug",
                        "body": "text",
                        "user": {"login": "someone"},
                        "labels": [{"name": "security"}],
                    }
                ],
            )

        adapter = GitHubIssueIntake(evidence)
        outcomes = adapter.fetch(
            owner="example",
            repo_name="libfoo",
            repo="example/libfoo",
            token="t",
            client=_client(handler),
        )
        assert outcomes[0].report.reporter == "someone"
        assert outcomes[0].report.labels == ("security",)

    def test_a_pull_request_is_filtered_out(self, evidence: EvidenceStore) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200,
                json=[
                    {"number": 1, "title": "bug", "body": "x"},
                    {"number": 2, "title": "pr", "body": "x", "pull_request": {}},
                ],
            )

        adapter = GitHubIssueIntake(evidence)
        issues = adapter.list_issues(
            owner="example", repo_name="libfoo", token="t", client=_client(handler)
        )
        assert len(issues) == 1

    def test_a_response_that_is_not_a_list(self, evidence: EvidenceStore) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json={"message": "nope"})

        adapter = GitHubIssueIntake(evidence)
        assert (
            adapter.list_issues(
                owner="example", repo_name="libfoo", token="t", client=_client(handler)
            )
            == []
        )

    def test_an_error_response_is_reported(self, evidence: EvidenceStore) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(500, text="boom")

        adapter = GitHubIssueIntake(evidence)
        with pytest.raises(GitHubError):
            adapter.list_issues(
                owner="example", repo_name="libfoo", token="t", client=_client(handler)
            )
