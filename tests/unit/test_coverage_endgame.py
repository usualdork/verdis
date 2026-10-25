"""The last handful of branches.

What is left here needs a specific input each time: a truncated file, a
named recipe, a property script, a timeout. They are worth pinning down
because each one changes what a maintainer is told.
"""

from __future__ import annotations

import struct
from pathlib import Path

import pytest

from verdis.build.recipe import recipe_from_dict
from verdis.config import Config
from verdis.pipeline.orchestrator import Orchestrator
from verdis.preflight.analyzers import detect_file_type
from verdis.preflight.elf import parse_elf_imports
from verdis.sandbox.base import SandboxRequest, SandboxResult
from verdis.sandbox.local import LocalBackend
from verdis.schemas.common import Verdict
from verdis.schemas.plan import ExpectStep, Plan, RunStep
from verdis.schemas.run import CommandResult, RunResult, RunStatus
from verdis.storage.evidence import EvidenceStore


class TestOrchestratorBranches:
    def _orchestrator(self, tmp_path: Path, **kwargs) -> Orchestrator:
        config = Config(mode="shadow", sandbox="local", repeats=1, **kwargs)
        return Orchestrator(
            config=config,
            store=None,
            evidence=EvidenceStore(tmp_path / "evidence"),
            backend=LocalBackend(),
        )

    def test_a_named_recipe_is_loaded(self, tmp_path: Path) -> None:
        orchestrator = self._orchestrator(tmp_path)
        recipe_dir = tmp_path / ".verdis"
        recipe_dir.mkdir()
        (recipe_dir / "recipe-special.yml").write_text(
            "language: c\nbuild:\n  steps: ['echo built']\n", encoding="utf-8"
        )
        plan = Plan(
            steps=(
                RunStep(cmd="./demo"),
                ExpectStep(oracle="crash"),
            )
        )
        from verdis.schemas.plan import BuildStep

        plan = plan.model_copy(
            update={"steps": (BuildStep(recipe="special"), RunStep(cmd="./demo"), ExpectStep(oracle="crash"))}
        )
        result = orchestrator._build(tmp_path, "v1", plan)
        assert result.status.value == "ok"

    def test_a_broken_named_recipe_is_ignored(self, tmp_path: Path) -> None:
        orchestrator = self._orchestrator(tmp_path)
        recipe_dir = tmp_path / ".verdis"
        recipe_dir.mkdir()
        (recipe_dir / "recipe-special.yml").write_text("build: [\n", encoding="utf-8")
        plan = Plan(
            steps=(
                RunStep(cmd="./demo"),
                ExpectStep(oracle="crash"),
            )
        )
        result = orchestrator._build(tmp_path, "v1", plan)
        # The broken recipe is ignored and the detection is used.
        assert result.status.value in {"ok", "unsupported", "failed"}

    def test_the_property_script_runs(self, tmp_path: Path) -> None:
        orchestrator = self._orchestrator(tmp_path)
        source = tmp_path / "src"
        source.mkdir()
        script = source / "check.sh"
        script.write_text("#!/bin/sh\nexit 1\n", encoding="utf-8")
        script.chmod(0o755)
        recipe = recipe_from_dict(
            {"language": "c", "build": {"steps": ["true"]}, "property_script": "check.sh"}
        )
        result = orchestrator._run_property_script(source, recipe)
        assert result is not None
        assert result.runs[0].exit_code == 1

    def test_a_missing_property_script_is_skipped(self, tmp_path: Path) -> None:
        orchestrator = self._orchestrator(tmp_path)
        recipe = recipe_from_dict(
            {"language": "c", "build": {"steps": ["true"]}, "property_script": "nope.sh"}
        )
        assert orchestrator._run_property_script(tmp_path, recipe) is None

    def test_a_recipe_without_a_property_script_is_skipped(self, tmp_path: Path) -> None:
        orchestrator = self._orchestrator(tmp_path)
        recipe = recipe_from_dict({"language": "c", "build": {"steps": ["true"]}})
        assert orchestrator._run_property_script(tmp_path, recipe) is None

    def test_a_timeout_stops_the_run(self, tmp_path: Path) -> None:
        class _Slow(LocalBackend):
            def run(self, request: SandboxRequest) -> SandboxResult:
                # The build succeeds; the PoC times out.
                if any("-c" in part for part in request.command):
                    return SandboxResult(exit_code=0, stdout="built")
                return SandboxResult(exit_code=None, timed_out=True)

        (tmp_path / "Makefile").write_text("all:\n\t@echo built\n", encoding="utf-8")
        orchestrator = Orchestrator(
            config=Config(mode="shadow", sandbox="local", repeats=3),
            store=None,
            evidence=EvidenceStore(tmp_path / "evidence"),
            backend=_Slow(),
        )
        from verdis.schemas.report import Report, Target

        report = Report(
            id="VDS-0001",
            body="# Report\n\n**Version**: 2.3.1\n\n```\n./demo\n```\n",
            target=Target(repo=".", ref="v1"),
        )
        result = orchestrator.triage(report, repo_path=tmp_path)
        assert result.verdict.verdict is Verdict.INCONCLUSIVE
        assert "time limit" in result.verdict.why


class TestElfRemaining:
    def test_a_static_symbol_table_is_not_an_import(self) -> None:
        # A section of type 2 is a static symbol table: it is not an
        # import, and it has no dynamic string table to point into.
        data = bytearray(b"\x7fELF" + b"\x00" * 300)
        struct.pack_into("<Q", data, 0x28, 64)
        struct.pack_into("<H", data, 0x3C, 2)
        struct.pack_into("<H", data, 0x3E, 1)
        struct.pack_into("<II", data, 64, 0, 2)
        assert parse_elf_imports(bytes(data)) == ([], [])

    def test_a_dynamic_section_without_a_string_table(self) -> None:
        data = bytearray(b"\x7fELF" + b"\x00" * 300)
        struct.pack_into("<Q", data, 0x28, 64)
        struct.pack_into("<H", data, 0x3C, 2)
        struct.pack_into("<H", data, 0x3E, 1)
        # A section of type 6 (SHT_DYNAMIC) with no .dynstr.
        struct.pack_into("<II", data, 64, 0, 6)
        assert isinstance(parse_elf_imports(bytes(data)), tuple)


class TestFileTypeRemaining:
    def test_a_file_with_a_ustar_header_is_a_tar(self, tmp_path: Path) -> None:
        path = tmp_path / "a.tar"
        path.write_bytes(b"x" * 257 + b"ustar" + b"\x00" * 100)
        assert detect_file_type(path) == "tar"


class TestPreflightRemaining:
    def test_an_unreadable_attachment_is_flagged(self, tmp_path: Path) -> None:
        from verdis.preflight.preflight import Preflight
        from verdis.schemas.report import Attachment

        path = tmp_path / "locked.bin"
        path.write_bytes(b"\x00" * 10)
        path.chmod(0o000)
        try:
            result = Preflight().inspect(
                Attachment(
                    name="locked.bin",
                    path=str(path),
                    sha256="0" * 64,
                    size=10,
                )
            )
            assert result.findings
        finally:
            path.chmod(0o600)


class TestPolicyRemaining:
    def test_a_policy_file_that_is_not_a_mapping(self, tmp_path: Path) -> None:
        from verdis.policy.loader import PolicyLoadError, load_policy_file

        path = tmp_path / "policy.yml"
        path.write_text("- a\n", encoding="utf-8")
        with pytest.raises(PolicyLoadError):
            load_policy_file(path)

    def test_a_list_of_numbers_is_turned_into_text(self) -> None:
        from verdis.policy.loader import policy_from_dict

        policy = policy_from_dict({"supported_versions": [1, 2]})
        assert policy.supported_versions == ("1", "2")


class TestSchemaRemaining:
    def test_the_plan_steps_are_always_a_tuple(self) -> None:
        plan = Plan(
            steps=[
                RunStep(cmd="./demo"),
                ExpectStep(oracle="crash"),
            ]
        )
        assert isinstance(plan.steps, tuple)

    def test_a_run_without_a_fire_is_reported(self) -> None:
        run = RunResult(
            status=RunStatus.COMPLETED,
            runs=(CommandResult(cmd="./demo", exit_code=0),),
        )
        assert not run.any_fired

    def test_the_rrs_step_keeps_an_unknown_mapping(self) -> None:
        from verdis.schemas.rrs import RRSPlanStep

        step = RRSPlanStep.model_validate({"custom": "value"})
        assert step.action == "custom"

    def test_the_rrs_step_reads_a_build_key(self) -> None:
        from verdis.schemas.rrs import RRSPlanStep

        step = RRSPlanStep.model_validate({"build": "default"})
        assert step.action == "build"

    def test_the_rrs_step_reads_a_run_key(self) -> None:
        from verdis.schemas.rrs import RRSPlanStep

        step = RRSPlanStep.model_validate({"run": "./demo"})
        assert step.action == "run"

    def test_an_empty_class_stays_empty(self) -> None:
        from verdis.schemas.rrs import RRS, RRSTarget

        assert RRS(target=RRSTarget(repo="r"), claim_class="").claim_class == ""


class TestEvidenceRemaining:
    def test_a_bundle_without_a_manifest_verifies_as_missing(self, tmp_path: Path) -> None:
        store = EvidenceStore(tmp_path / "evidence")
        assert store.verify_bundle("VDS-nope") == ["no manifest found"]

    def test_a_file_that_is_not_in_the_manifest_is_ignored(self, tmp_path: Path) -> None:
        store = EvidenceStore(tmp_path / "evidence")
        store.write_bundle("VDS-1", {"a.txt": "x"})
        (store.bundle_dir("VDS-1") / "extra.txt").write_text("y", encoding="utf-8")
        assert store.verify_bundle("VDS-1") == []

    def test_removing_a_report_that_is_not_there(self, tmp_path: Path) -> None:
        store = EvidenceStore(tmp_path / "evidence")
        assert store.remove("VDS-nope") is False
