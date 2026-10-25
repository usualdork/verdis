"""Tests for the remaining branches of the smaller modules.

Each of these is a path a report, a policy or a runtime can take that the
main tests do not reach.
"""

from __future__ import annotations

import json
import struct
from pathlib import Path

import pytest

from verdis.build.recipe import (
    RecipeError,
    detect_recipe,
    has_flag,
    load_recipe_file,
    recipe_from_dict,
)
from verdis.config import Config, ConfigError, config_from_dict, default_config, load_config
from verdis.preflight.elf import parse_elf_imports
from verdis.schemas.run import CommandResult, OracleResult, RunResult
from verdis.storage.db import Store, default_store_path, temporary_store

# -- the store ----------------------------------------------------------


class TestStoreDetails:
    def test_a_report_is_found_by_its_body_hash(self, store: Store) -> None:
        from verdis.schemas.common import ReportSource
        from verdis.schemas.report import Report

        report = Report(
            id="VDS-0001",
            source=ReportSource.FILE,
            body="hello",
            metadata={"body_sha256": "abc"},
        )
        store.save_report(report)
        assert store.find_by_body_hash("abc") is not None
        assert store.find_by_body_hash("nope") is None

    def test_the_verdicts_are_listed(self, store: Store) -> None:
        from verdis.schemas.common import Verdict, VerdictTier
        from verdis.schemas.verdict import VerdictResult

        store.save_verdict(VerdictResult(verdict=Verdict.REPRODUCED, tier=VerdictTier.TIER_1, report_id="VDS-1"))
        store.save_verdict(VerdictResult(verdict=Verdict.INCONCLUSIVE, report_id="VDS-2"))
        assert len(store.list_verdicts()) == 2

    def test_deleting_a_report_removes_its_verdict_and_fingerprint(
        self, store: Store
    ) -> None:
        from verdis.schemas.common import ReportSource, Verdict
        from verdis.schemas.report import Report
        from verdis.schemas.verdict import VerdictResult

        store.save_report(Report(id="VDS-1", source=ReportSource.FILE, body="x"))
        store.save_verdict(VerdictResult(verdict=Verdict.INCONCLUSIVE, report_id="VDS-1"))
        store.upsert_dedupe(
            __import__("verdis.storage.db", fromlist=["DedupeEntry"]).DedupeEntry(
                report_id="VDS-1"
            )
        )
        assert store.delete_report("VDS-1")
        assert store.get_verdict("VDS-1") is None

    def test_the_store_can_be_vacuumed(self, store: Store) -> None:
        store.vacuum()
        assert store.db_path.is_file()

    def test_the_store_path_follows_the_environment(self, monkeypatch) -> None:
        monkeypatch.setenv("VERDIS_HOME", "/tmp/verdis-home")
        assert default_store_path() == Path("/tmp/verdis-home")

    def test_the_store_path_follows_xdg(self, monkeypatch) -> None:
        monkeypatch.delenv("VERDIS_HOME", raising=False)
        monkeypatch.setenv("XDG_DATA_HOME", "/tmp/xdg")
        assert default_store_path() == Path("/tmp/xdg/verdis")

    def test_a_throwaway_store_is_created(self) -> None:
        path = temporary_store()
        assert path.is_dir()


# -- the configuration --------------------------------------------------


class TestConfigBranches:
    @pytest.mark.parametrize(
        ("data", "message"),
        [
            ({"preflight": {"threshold": 200}}, "preflight.threshold"),
            ({"preflight": "yes"}, "preflight must be a mapping"),
            ({"llm": "yes"}, "llm must be a mapping"),
            ({"actions": "yes"}, "actions must be a mapping"),
            ({"dedupe": "yes"}, "dedupe must be a mapping"),
            ({"advisories": "yes"}, "advisories must be a mapping"),
            ({"build": "yes"}, "build must be a mapping"),
            ({"run": "yes"}, "run must be a mapping"),
            (["not", "a", "mapping"], "must be a mapping"),
        ],
    )
    def test_a_malformed_section_is_rejected(self, data: object, message: str) -> None:
        with pytest.raises(ConfigError, match=message):
            config_from_dict(data)  # type: ignore[arg-type]

    def test_shadow_mode_is_recognised(self) -> None:
        assert Config(mode="shadow").is_shadow
        assert not Config(mode="comment").is_shadow

    def test_the_default_configuration_reads_the_work_directory(
        self, monkeypatch
    ) -> None:
        monkeypatch.setenv("VERDIS_WORK_DIR", "/tmp/work")
        assert default_config().work_dir == "/tmp/work"

    def test_a_missing_config_file_is_the_default(self, tmp_path: Path) -> None:
        assert load_config(tmp_path).mode == "shadow"

    def test_an_unreadable_config_file_is_reported(self, tmp_path: Path) -> None:
        (tmp_path / ".verdis").mkdir()
        path = tmp_path / ".verdis" / "config.yml"
        path.write_text("mode: shadow\n", encoding="utf-8")
        path.chmod(0o000)
        try:
            with pytest.raises(ConfigError, match="cannot read"):
                load_config(tmp_path)
        finally:
            path.chmod(0o600)


# -- the recipes --------------------------------------------------------


class TestRecipeBranches:
    def test_a_recipe_that_is_not_a_mapping_is_rejected(self) -> None:
        with pytest.raises(RecipeError, match="must be a mapping"):
            recipe_from_dict(["a"])  # type: ignore[arg-type]

    def test_a_recipe_with_malformed_sections_is_rejected(self) -> None:
        with pytest.raises(RecipeError, match="must be mappings"):
            recipe_from_dict({"build": "x", "run": "y"})

    def test_an_unreadable_recipe_is_reported(self, tmp_path: Path) -> None:
        with pytest.raises(RecipeError, match="cannot read"):
            load_recipe_file(tmp_path / "nope.yml")

    def test_an_empty_recipe_is_the_default(self, tmp_path: Path) -> None:
        path = tmp_path / "recipe.yml"
        path.write_text("", encoding="utf-8")
        assert load_recipe_file(path).language == "unknown"

    def test_a_missing_project_has_no_recipe(self, tmp_path: Path) -> None:
        assert detect_recipe(tmp_path) is None

    def test_a_python_project_is_detected(self, tmp_path: Path) -> None:
        (tmp_path / "pyproject.toml").write_text("[project]\n", encoding="utf-8")
        recipe = detect_recipe(tmp_path)
        assert recipe is not None
        assert recipe.language == "python"

    def test_a_rust_project_is_detected(self, tmp_path: Path) -> None:
        (tmp_path / "Cargo.toml").write_text("[package]\n", encoding="utf-8")
        recipe = detect_recipe(tmp_path)
        assert recipe is not None
        assert recipe.language == "rust"

    def test_a_java_project_is_detected(self, tmp_path: Path) -> None:
        (tmp_path / "build.gradle").write_text("plugins {}\n", encoding="utf-8")
        recipe = detect_recipe(tmp_path)
        assert recipe is not None
        assert recipe.language == "java"

    def test_an_autotools_project_is_detected(self, tmp_path: Path) -> None:
        (tmp_path / "configure.ac").write_text("AC_INIT\n", encoding="utf-8")
        recipe = detect_recipe(tmp_path)
        assert recipe is not None
        assert recipe.build.system == "autotools"

    def test_the_flags_are_compared_without_case(self) -> None:
        assert has_flag(("ASAN",), "asan")
        assert not has_flag(("asan",), "ubsan")

    def test_an_unreadable_dockerfile_has_no_base_image(self, tmp_path: Path) -> None:
        from verdis.build.recipe import _dockerfile_base_image

        path = tmp_path / "Dockerfile"
        path.write_text("FROM alpine\n", encoding="utf-8")
        path.chmod(0o000)
        try:
            assert _dockerfile_base_image(path) == ""
        finally:
            path.chmod(0o600)


# -- the ELF parser -----------------------------------------------------


class TestElfBranches:
    def test_data_that_is_too_short_is_handled(self) -> None:
        assert parse_elf_imports(b"\x7fELF") == ([], [])

    def test_a_truncated_header_is_handled(self) -> None:
        assert parse_elf_imports(b"\x7fELF" + b"\x00" * 8) == ([], [])

    def test_a_section_table_beyond_the_data_is_handled(self) -> None:
        data = bytearray(b"\x7fELF" + b"\x00" * 200)
        struct.pack_into("<Q", data, 0x28, 10_000_000)
        assert parse_elf_imports(bytes(data)) == ([], [])

    def test_a_static_symbol_table_is_not_an_import(self) -> None:
        # A section of type 2 (SHT_SYMTAB) is a static table; only the
        # dynamic one is an import.
        data = bytearray(b"\x7fELF" + b"\x00" * 200)
        struct.pack_into("<Q", data, 0x28, 64)
        struct.pack_into("<H", data, 0x3C, 2)  # two sections
        struct.pack_into("<H", data, 0x3E, 1)  # the string table index
        # A section header of type 2 at offset 64.
        struct.pack_into("<II", data, 64, 0, 2)
        assert parse_elf_imports(bytes(data)) == ([], [])


# -- the run results ----------------------------------------------------


class TestRunResultProperties:
    def test_the_combined_output_joins_both_streams(self) -> None:
        command = CommandResult(cmd="x", stdout="out", stderr="err")
        assert command.combined == "out\nerr"

    def test_the_headline_is_the_first_evidence_line(self) -> None:
        result = OracleResult(oracle="crash", fired=True, evidence=("first", "second"))
        assert result.headline == "first"

    def test_without_evidence_the_headline_is_the_reason(self) -> None:
        result = OracleResult(oracle="crash", fired=False, reason="nothing")
        assert result.headline == "nothing"

    def test_the_matched_fire_is_reported(self) -> None:
        run = RunResult(
            oracles=(
                OracleResult(oracle="crash", fired=True, matched_claim=True),
                OracleResult(oracle="output", fired=True, matched_claim=False),
            )
        )
        assert run.matched_fired

    def test_a_run_without_a_matched_fire_is_reported(self) -> None:
        run = RunResult(oracles=(OracleResult(oracle="crash", fired=True),))
        assert not run.matched_fired

    def test_the_fired_count_is_reported(self) -> None:
        run = RunResult(
            oracles=(
                OracleResult(oracle="crash", fired=True),
                OracleResult(oracle="output", fired=False),
            )
        )
        assert run.fired_count == 1

    def test_the_evidence_lines_are_collected(self) -> None:
        run = RunResult(
            oracles=(
                OracleResult(oracle="crash", fired=True, evidence=("a",)),
                OracleResult(oracle="output", fired=True, evidence=("b",)),
            )
        )
        assert run.evidence_lines() == ("a", "b")

    def test_the_output_is_normalised(self) -> None:
        run = RunResult(runs=(CommandResult(cmd="x", stdout=" a  b "),))
        assert run.normalized_output() == "a b"


# -- the command line ---------------------------------------------------


class TestCommandLineBranches:
    def test_the_recipe_is_not_overwritten(self, tmp_path: Path) -> None:
        from typer.testing import CliRunner

        from verdis.cli import app

        runner = CliRunner()
        runner.invoke(app, ["recipe", "init", str(tmp_path)])
        result = runner.invoke(app, ["recipe", "init", str(tmp_path)])
        assert result.exit_code == 1
        assert "already exists" in result.stderr

    def test_the_policy_is_not_overwritten(self, tmp_path: Path) -> None:
        from typer.testing import CliRunner

        from verdis.cli import app

        runner = CliRunner()
        runner.invoke(app, ["policy", "init", str(tmp_path)])
        result = runner.invoke(app, ["policy", "init", str(tmp_path)])
        assert result.exit_code == 1

    def test_a_broken_policy_is_reported(self, tmp_path: Path) -> None:
        from typer.testing import CliRunner

        from verdis.cli import app

        (tmp_path / ".verdis").mkdir()
        (tmp_path / ".verdis" / "policy.yml").write_text(
            "supported_versions: [\n", encoding="utf-8"
        )
        result = CliRunner().invoke(app, ["policy", "check", str(tmp_path)])
        assert result.exit_code == 1
        assert "invalid policy" in result.stderr

    def test_a_derived_policy_is_flagged(self, tmp_path: Path) -> None:
        from typer.testing import CliRunner

        from verdis.cli import app

        (tmp_path / "SECURITY.md").write_text(
            "# Security\n\n## Supported versions\n\n- 2.x\n", encoding="utf-8"
        )
        result = CliRunner().invoke(app, ["policy", "check", str(tmp_path)])
        assert result.exit_code == 0
        assert "unverified" in result.stderr

    def test_a_broken_manifest_is_reported(self, tmp_path: Path) -> None:
        from typer.testing import CliRunner

        from verdis.cli import app

        (tmp_path / "manifest.json").write_text("{not json", encoding="utf-8")
        result = CliRunner().invoke(app, ["bundle", "verify", str(tmp_path)])
        assert result.exit_code == 1
        assert "cannot read the manifest" in result.stderr

    def test_a_missing_file_in_a_bundle_is_reported(self, tmp_path: Path) -> None:
        from typer.testing import CliRunner

        from verdis.cli import app

        (tmp_path / "manifest.json").write_text(
            json.dumps({"files": [{"path": "gone.txt", "sha256": "0" * 64}]}),
            encoding="utf-8",
        )
        result = CliRunner().invoke(app, ["bundle", "verify", str(tmp_path)])
        assert result.exit_code == 1
        assert "missing" in result.stderr

    def test_an_unreadable_config_is_reported(self, tmp_path: Path) -> None:
        from verdis.cli import _load_config
        from verdis.config import ConfigError

        path = tmp_path / "config.yml"
        path.write_text("mode: shadow\n", encoding="utf-8")
        path.chmod(0o000)
        try:
            with pytest.raises(ConfigError, match="cannot read"):
                _load_config(str(path))
        finally:
            path.chmod(0o600)
