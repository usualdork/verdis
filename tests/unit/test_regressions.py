"""Regression tests for the bugs the code review found.

Each test here fails on the code as it was before the fix.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from verdis.build.builder import BuildCache, Builder
from verdis.config import Config
from verdis.emit.bundle import RERUN_SCRIPT, BundleBuilder
from verdis.oracles.engine import OracleEngine
from verdis.pipeline.orchestrator import Orchestrator
from verdis.sandbox.local import LocalBackend
from verdis.schemas.claim import Claim, ClaimComponent, ExpectedObservable
from verdis.schemas.common import OracleType, Verdict, VerdictFlag
from verdis.schemas.plan import ExpectStep, Plan, RunStep
from verdis.schemas.run import CommandResult, RunResult, RunStatus
from verdis.storage.db import Store
from verdis.storage.evidence import EvidenceStore


class TestRerunScript:
    def test_it_triages_the_report_not_the_repository(self) -> None:
        # The first positional argument of `verdis triage` is the report.
        assert '"$REPORT"' in RERUN_SCRIPT
        assert 'triage "$REPORT"' in RERUN_SCRIPT
        assert '--repo "$VERDIS_REPO"' in RERUN_SCRIPT

    def test_it_points_at_the_stored_original(self) -> None:
        assert 'REPORT="$BUNDLE_DIR/original/report.md"' in RERUN_SCRIPT

    def test_it_checks_the_report_is_there(self) -> None:
        assert "the original report is missing" in RERUN_SCRIPT

    def test_the_bundle_contains_the_original(self, tmp_path: Path) -> None:
        from verdis.schemas.common import Verdict, VerdictTier
        from verdis.schemas.verdict import VerdictResult

        store = EvidenceStore(tmp_path / "evidence")
        BundleBuilder(store).build(
            report_id="VDS-0001",
            verdict=VerdictResult(verdict=Verdict.REPRODUCED, tier=VerdictTier.TIER_1),
            original_body="the report",
        )
        assert (store.bundle_dir("VDS-0001") / "original" / "report.md").is_file()


class TestBuildCache:
    def test_a_cache_hit_restores_the_built_tree(self, tmp_path: Path) -> None:
        project = tmp_path / "project"
        project.mkdir()
        (project / "Makefile").write_text(
            "all:\n\tmkdir -p build\n\techo built > build/out.txt\n", encoding="utf-8"
        )

        cache = BuildCache(root=tmp_path / "cache")
        builder = Builder(backend=LocalBackend(), cache=cache)

        first = builder.build(repo_path=project, in_place=True)
        assert first.status.value == "ok"
        assert (project / "build" / "out.txt").is_file()

        # Wipe the tree, as a fresh checkout would be.
        shutil.rmtree(project / "build")
        assert not (project / "build").exists()

        second = builder.build(repo_path=project, in_place=True)
        assert second.status.value == "ok"
        assert second.cached
        # The built artefact has to be back, or the PoC would run against
        # an unbuilt tree and the verdict would be wrong.
        assert (project / "build" / "out.txt").is_file()


class TestDifferentialOracle:
    def _plan(self) -> Plan:
        return Plan(
            steps=(RunStep(cmd="./demo"), ExpectStep(oracle=OracleType.SANITIZER))
        )

    def _run(self, crashed: bool) -> RunResult:
        return RunResult(
            status=RunStatus.COMPLETED,
            runs=(
                CommandResult(
                    cmd="./demo",
                    exit_code=1 if crashed else 0,
                    stderr=(
                        "==1234==ERROR: AddressSanitizer: heap-buffer-overflow on "
                        "address 0x602000000010\n"
                        "    #0 0x4f2a in parse_header src/hdr.c:212\n"
                        if crashed
                        else ""
                    ),
                ),
            ),
        )

    def test_it_is_evaluated_once(self) -> None:
        outcomes = OracleEngine().evaluate(
            self._run(True), self._plan(), Claim(), comparison_run=self._run(False)
        )
        differentials = [o for o in outcomes if o.oracle is OracleType.DIFFERENTIAL]
        assert len(differentials) == 1
        assert differentials[0].fired

    def test_it_does_not_fire_when_both_refs_reproduce(self) -> None:
        outcomes = OracleEngine().evaluate(
            self._run(True), self._plan(), Claim(), comparison_run=self._run(True)
        )
        differential = next(o for o in outcomes if o.oracle is OracleType.DIFFERENTIAL)
        assert not differential.fired

    def test_it_is_not_evaluated_without_a_comparison(self) -> None:
        outcomes = OracleEngine().evaluate(self._run(True), self._plan(), Claim())
        assert all(o.oracle is not OracleType.DIFFERENTIAL for o in outcomes)


class TestFixedAtHead:
    def test_a_differential_run_sets_the_flag(
        self, tmp_path: Path, c_project: Path, c_project_fixed: Path, has_clang: bool
    ) -> None:
        if not has_clang:
            pytest.skip("no C compiler available")
        from verdis.intake.file import FileIntake

        config = Config(mode="shadow", sandbox="local", repeats=1)
        orchestrator = Orchestrator(
            config=config,
            store=Store(tmp_path / "store"),
            evidence=EvidenceStore(tmp_path / "evidence"),
            backend=LocalBackend(),
        )
        report = tmp_path / "report.md"
        report.write_text(
            "# Heap buffer overflow in parse_header\n\n"
            "**Version**: 2.3.1\n**Class**: CWE-122\n\n"
            "```\n./build/parse_demo poc.bin\n```\n\n"
            "AddressSanitizer reports a heap-buffer-overflow in parse_header.\n",
            encoding="utf-8",
        )
        outcome = FileIntake(orchestrator.evidence).fetch(
            report, repo=str(c_project), attachments=(c_project / "poc.bin",)
        )
        result = orchestrator.triage(
            outcome.report,
            repo_path=c_project,
            comparison_ref=str(c_project_fixed),
        )
        assert result.verdict.verdict is Verdict.REPRODUCED
        assert VerdictFlag.FIXED_AT_HEAD in result.verdict.flags


class TestRedaction:
    def test_the_report_text_is_redacted_before_it_leaves(self) -> None:
        import httpx

        from verdis.extract.providers import OpenAICompatibleProvider, ProviderConfig

        captured: dict[str, object] = {}

        def handler(request: httpx.Request) -> httpx.Response:
            captured["payload"] = json.loads(request.content)
            return httpx.Response(
                200,
                json={"choices": [{"message": {"content": "{}"}}], "usage": {}},
            )

        provider = OpenAICompatibleProvider(
            ProviderConfig(provider="openai", model="m", redaction=True)
        )
        provider._client = httpx.Client(transport=httpx.MockTransport(handler))
        provider.complete_json(
            system="s",
            user="reporter@example.org says the token is ghp_" + "a" * 36,
            schema={"type": "object"},
        )
        body = json.dumps(captured["payload"])
        assert "reporter@example.org" not in body
        assert "ghp_" not in body

    def test_redaction_can_be_turned_off(self) -> None:
        import httpx

        from verdis.extract.providers import OpenAICompatibleProvider, ProviderConfig

        captured: dict[str, object] = {}

        def handler(request: httpx.Request) -> httpx.Response:
            captured["payload"] = json.loads(request.content)
            return httpx.Response(
                200,
                json={"choices": [{"message": {"content": "{}"}}], "usage": {}},
            )

        provider = OpenAICompatibleProvider(
            ProviderConfig(provider="openai", model="m", redaction=False)
        )
        provider._client = httpx.Client(transport=httpx.MockTransport(handler))
        provider.complete_json(
            system="s", user="reporter@example.org", schema={"type": "object"}
        )
        assert "reporter@example.org" in json.dumps(captured["payload"])


class TestCanary:
    def test_a_canary_secret_is_planted_and_checked(
        self, tmp_path: Path, c_project: Path, has_clang: bool
    ) -> None:
        if not has_clang:
            pytest.skip("no C compiler available")
        from verdis.intake.file import FileIntake

        config = Config(mode="shadow", sandbox="local", repeats=1)
        orchestrator = Orchestrator(
            config=config,
            store=Store(tmp_path / "store"),
            evidence=EvidenceStore(tmp_path / "evidence"),
            backend=LocalBackend(),
        )
        report = tmp_path / "report.md"
        report.write_text(
            "# Heap buffer overflow\n\n**Version**: 2.3.1\n\n"
            "```\n./build/parse_demo poc.bin\n```\n",
            encoding="utf-8",
        )
        outcome = FileIntake(orchestrator.evidence).fetch(
            report, repo=str(c_project), attachments=(c_project / "poc.bin",)
        )
        result = orchestrator.triage(outcome.report, repo_path=c_project)
        assert result.verdict.run is not None
        # The canary oracle ran and had something to say.
        canary = next(
            (o for o in result.verdict.run.oracles if o.oracle is OracleType.CANARY),
            None,
        )
        assert canary is not None
        assert canary.reason or canary.evidence


class TestHeuristicGaps:
    def test_a_report_without_a_poc_needs_info(self, tmp_path: Path) -> None:
        from verdis.intake.file import FileIntake

        config = Config(mode="shadow", sandbox="local")
        orchestrator = Orchestrator(
            config=config,
            store=Store(tmp_path / "store"),
            evidence=EvidenceStore(tmp_path / "evidence"),
            backend=LocalBackend(),
        )
        report = tmp_path / "report.md"
        report.write_text("# Something is wrong\n\nThe parser misbehaves.\n", encoding="utf-8")
        outcome = FileIntake(orchestrator.evidence).fetch(report, repo=str(tmp_path))
        result = orchestrator.triage(outcome.report, repo_path=tmp_path)
        assert result.verdict.verdict is Verdict.NEEDS_INFO


_ = (ClaimComponent, ExpectedObservable)
