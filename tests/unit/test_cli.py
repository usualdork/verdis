"""Tests for the command line interface (PRD 9.1)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from verdis.cli import app

runner = CliRunner()


@pytest.fixture()
def isolated(tmp_path: Path) -> dict[str, str]:
    store = tmp_path / "store"
    evidence = tmp_path / "evidence"
    store.mkdir()
    evidence.mkdir()
    return ["--store", str(store), "--evidence", str(evidence)]


class TestBasics:
    def test_help_works(self) -> None:
        result = runner.invoke(app, ["--help"])
        assert result.exit_code == 0
        assert "triage" in result.stdout

    def test_version(self) -> None:
        result = runner.invoke(app, ["version"])
        assert result.exit_code == 0
        assert result.stdout.strip()

    def test_doctor(self, isolated: list[str]) -> None:
        result = runner.invoke(app, ["doctor", *isolated])
        assert result.exit_code == 0
        assert "sandbox backend" in result.stdout


class TestPolicy:
    def test_init_creates_a_policy(self, tmp_path: Path) -> None:
        result = runner.invoke(app, ["policy", "init", str(tmp_path)])
        assert result.exit_code == 0
        assert (tmp_path / ".verdis" / "policy.yml").is_file()

    def test_init_does_not_overwrite(self, tmp_path: Path) -> None:
        runner.invoke(app, ["policy", "init", str(tmp_path)])
        result = runner.invoke(app, ["policy", "init", str(tmp_path)])
        assert result.exit_code == 1

    def test_check_reports_the_origin(self, tmp_path: Path) -> None:
        runner.invoke(app, ["policy", "init", str(tmp_path)])
        result = runner.invoke(app, ["policy", "check", str(tmp_path)])
        assert result.exit_code == 0
        assert "policy.yml" in result.stdout

    def test_check_without_a_policy(self, tmp_path: Path) -> None:
        result = runner.invoke(app, ["policy", "check", str(tmp_path)])
        assert result.exit_code == 1


class TestRecipe:
    def test_init_creates_a_recipe(self, tmp_path: Path) -> None:
        result = runner.invoke(app, ["recipe", "init", str(tmp_path)])
        assert result.exit_code == 0
        assert (tmp_path / ".verdis" / "recipe.yml").is_file()

    def test_validate_accepts_a_good_recipe(self, tmp_path: Path) -> None:
        runner.invoke(app, ["recipe", "init", str(tmp_path)])
        result = runner.invoke(app, ["recipe", "validate", str(tmp_path)])
        assert result.exit_code == 0
        assert "valid" in result.stdout

    def test_validate_rejects_a_broken_recipe(self, tmp_path: Path) -> None:
        (tmp_path / ".verdis").mkdir(parents=True)
        (tmp_path / ".verdis" / "recipe.yml").write_text("build: [\n", encoding="utf-8")
        result = runner.invoke(app, ["recipe", "validate", str(tmp_path)])
        assert result.exit_code == 1

    def test_validate_without_a_recipe(self, tmp_path: Path) -> None:
        result = runner.invoke(app, ["recipe", "validate", str(tmp_path)])
        assert result.exit_code == 1


class TestPreflight:
    def test_it_emits_an_rrs_block(self, tmp_path: Path) -> None:
        poc = tmp_path / "poc"
        poc.mkdir()
        (poc / "poc.bin").write_bytes(b"A" * 32)
        result = runner.invoke(
            app, ["preflight", str(poc), "--repo", "example/libfoo", "--ref", "v1"]
        )
        assert result.exit_code == 0
        assert "rrs:" in result.stdout
        assert "0.1" in result.stdout
        assert "example/libfoo" in result.stdout

    def test_it_reports_findings(self, tmp_path: Path) -> None:
        poc = tmp_path / "poc"
        poc.mkdir()
        (poc / "run.sh").write_text("cat ~/.ssh/id_rsa\n", encoding="utf-8")
        result = runner.invoke(app, ["preflight", str(poc)])
        assert "credential" in result.stderr.lower() or "credential" in result.stdout.lower()

    def test_it_writes_the_block_to_a_file(self, tmp_path: Path) -> None:
        poc = tmp_path / "poc"
        poc.mkdir()
        (poc / "poc.bin").write_bytes(b"A")
        out = tmp_path / "rrs.yaml"
        result = runner.invoke(app, ["preflight", str(poc), "--out", str(out)])
        assert result.exit_code == 0
        assert out.is_file()
        assert "rrs:" in out.read_text(encoding="utf-8")

    def test_a_missing_directory_is_an_error(self, tmp_path: Path) -> None:
        result = runner.invoke(app, ["preflight", str(tmp_path / "nope")])
        assert result.exit_code == 2


class TestTriage:
    def test_a_missing_report_is_an_error(self, tmp_path: Path, isolated: list[str]) -> None:
        result = runner.invoke(
            app, ["triage", str(tmp_path / "nope.md"), *isolated]
        )
        assert result.exit_code == 2

    def test_a_vague_report_needs_info(
        self, tmp_path: Path, isolated: list[str]
    ) -> None:
        report = tmp_path / "report.md"
        report.write_text(
            "# Something is wrong\n\nI think the parser has a problem.\n", encoding="utf-8"
        )
        result = runner.invoke(
            app,
            [
                "triage",
                str(report),
                "--repo",
                str(tmp_path),
                "--sandbox",
                "local",
                *isolated,
            ],
        )
        assert result.exit_code == 1
        assert "NEEDS_INFO" in result.stdout

    def test_json_output_is_valid_json(
        self, tmp_path: Path, isolated: list[str]
    ) -> None:
        report = tmp_path / "report.md"
        report.write_text(
            "# Something is wrong\n\nI think the parser has a problem.\n", encoding="utf-8"
        )
        result = runner.invoke(
            app,
            [
                "triage",
                str(report),
                "--repo",
                str(tmp_path),
                "--sandbox",
                "local",
                "--output",
                "json",
                *isolated,
            ],
        )
        payload = json.loads(result.stdout)
        assert payload["verdict"] == "NEEDS_INFO"


class TestBundle:
    def test_verify_reports_a_missing_manifest(self, tmp_path: Path) -> None:
        result = runner.invoke(app, ["bundle", "verify", str(tmp_path)])
        assert result.exit_code == 1

    def test_verify_accepts_an_intact_bundle(self, tmp_path: Path) -> None:
        from verdis.emit.bundle import BundleBuilder
        from verdis.schemas.common import Verdict, VerdictTier
        from verdis.schemas.verdict import VerdictResult
        from verdis.storage.evidence import EvidenceStore

        store = EvidenceStore(tmp_path / "evidence")
        BundleBuilder(store).build(
            report_id="VDS-0001",
            verdict=VerdictResult(verdict=Verdict.REPRODUCED, tier=VerdictTier.TIER_1),
            original_body="x",
        )
        result = runner.invoke(app, ["bundle", "verify", str(store.bundle_dir("VDS-0001"))])
        assert result.exit_code == 0
        assert "intact" in result.stdout

    def test_verify_detects_tampering(self, tmp_path: Path) -> None:
        from verdis.emit.bundle import BundleBuilder
        from verdis.schemas.common import Verdict, VerdictTier
        from verdis.schemas.verdict import VerdictResult
        from verdis.storage.evidence import EvidenceStore

        store = EvidenceStore(tmp_path / "evidence")
        BundleBuilder(store).build(
            report_id="VDS-0001",
            verdict=VerdictResult(verdict=Verdict.REPRODUCED, tier=VerdictTier.TIER_1),
            original_body="x",
        )
        (store.bundle_dir("VDS-0001") / "verdict.md").write_text("tampered", encoding="utf-8")
        result = runner.invoke(app, ["bundle", "verify", str(store.bundle_dir("VDS-0001"))])
        assert result.exit_code == 1


class TestInbox:
    def test_an_empty_inbox(self, isolated: list[str]) -> None:
        result = runner.invoke(app, ["inbox", "list", *isolated])
        assert result.exit_code == 0
        assert "empty" in result.stdout

    def test_showing_an_unknown_report(self, isolated: list[str]) -> None:
        result = runner.invoke(app, ["inbox", "show", "VDS-nope", *isolated])
        assert result.exit_code == 1
