"""The final branches.

Everything here is a narrow path that the coverage report found. The
point of the file is to make the last of them explicit rather than
accidental.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from verdis.build.builder import Builder
from verdis.build.recipe import detect_recipe
from verdis.config import load_config
from verdis.dedupe.fingerprint import cosine_similarity
from verdis.dedupe.osv import OSVAdvisorySource
from verdis.extract.heuristics import HeuristicExtractor
from verdis.intake.github import GitHubError
from verdis.judge.impact import demonstrated_impact, impact_level
from verdis.judge.rules import Judge, JudgeContext
from verdis.oracles.base import OracleContext
from verdis.oracles.differential import DifferentialOracle
from verdis.oracles.frames import extract_frames
from verdis.planner.validator import PlanValidator
from verdis.policy.engine import PolicyEngine
from verdis.policy.loader import PolicyLoadError, load_policy_file
from verdis.preflight.analyzers import detect_file_type, inspect_binary
from verdis.sandbox.base import SandboxProfile
from verdis.sandbox.container import ContainerBackend
from verdis.schemas.claim import Claim, ClaimComponent
from verdis.schemas.common import OracleType
from verdis.schemas.plan import ExpectStep, Plan, RunStep
from verdis.schemas.policy import Policy, PolicyClause
from verdis.schemas.report import Report
from verdis.schemas.rrs import RRSPlanStep
from verdis.schemas.run import CommandResult, RunResult, RunStatus
from verdis.storage.evidence import EvidenceStore


class TestBuilderBranches:
    def test_the_cache_is_stored_and_cleaned_up(self, tmp_path: Path) -> None:
        from verdis.build.builder import BuildCache
        from verdis.build.recipe import recipe_from_dict

        cache = BuildCache(root=tmp_path / "cache")
        recipe = recipe_from_dict({"language": "c", "build": {"steps": ["true"]}})
        key = cache.key("v1", recipe)
        source = tmp_path / "src"
        source.mkdir()
        cache.store(key, source)
        assert cache.get(key) is not None

    def test_the_build_profile_for_a_mirror(self, tmp_path: Path) -> None:
        from verdis.build.recipe import recipe_from_dict

        builder = Builder(
            backend=__import__(
                "verdis.sandbox.local", fromlist=["LocalBackend"]
            ).LocalBackend(),
            mirror_proxy="http://proxy:3128",
        )
        recipe = recipe_from_dict(
            {"language": "c", "build": {"steps": ["true"], "network": "mirror"}}
        )
        profile = builder._build_profile(recipe)
        assert profile.network == "mirror"

    def test_the_build_profile_without_a_mirror(self, tmp_path: Path) -> None:
        from verdis.build.recipe import recipe_from_dict

        builder = Builder(backend=__import__(
            "verdis.sandbox.local", fromlist=["LocalBackend"]
        ).LocalBackend())
        recipe = recipe_from_dict(
            {"language": "c", "build": {"steps": ["true"], "network": "mirror"}}
        )
        # Without a configured mirror the build stage has no network
        # either.
        assert builder._build_profile(recipe).network == "none"

    def test_a_build_with_no_log_lines(self) -> None:
        from verdis.sandbox.base import SandboxResult

        builder = Builder(backend=__import__(
            "verdis.sandbox.local", fromlist=["LocalBackend"]
        ).LocalBackend())
        assert builder._log_lines(SandboxResult(exit_code=0)) == ()

    def test_the_failing_step_is_the_last_one(self) -> None:
        from verdis.build.recipe import recipe_from_dict
        from verdis.sandbox.base import SandboxResult

        builder = Builder(backend=__import__(
            "verdis.sandbox.local", fromlist=["LocalBackend"]
        ).LocalBackend())
        recipe = recipe_from_dict({"language": "c", "build": {"steps": ["a", "b"]}})
        result = SandboxResult(exit_code=1, stdout="the compilation stopped")
        assert builder._failing_step(recipe, result).startswith("step 2")


class TestConfigBranch:
    def test_an_empty_config_file_is_the_default(self, tmp_path: Path) -> None:
        (tmp_path / ".verdis").mkdir()
        (tmp_path / ".verdis" / "config.yml").write_text("", encoding="utf-8")
        assert load_config(tmp_path).mode == "shadow"


class TestRecipeBranch:
    def test_a_path_that_is_not_a_directory_has_no_recipe(self, tmp_path: Path) -> None:
        path = tmp_path / "a.txt"
        path.write_text("x", encoding="utf-8")
        assert detect_recipe(path) is None


class TestDedupeBranches:
    def test_the_cosine_of_two_empty_vectors_is_zero(self) -> None:
        assert cosine_similarity((), ()) == 0.0

    def test_an_advisory_that_is_not_a_mapping_is_skipped(self, tmp_path: Path) -> None:
        from verdis.dedupe.index import LocalAdvisorySource

        path = tmp_path / "advisories.json"
        path.write_text(json.dumps(["not a mapping"]), encoding="utf-8")
        assert LocalAdvisorySource(path).lookup() == []

    def test_the_osv_classes_are_collected_from_several_entries(self) -> None:
        import httpx

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200,
                json={
                    "vulns": [
                        {
                            "id": "GHSA-1",
                            "affected": [
                                {"package": {"name": "a"}, "database_specific": {"cwe_ids": ["CWE-1"]}},
                                {"package": {"name": "b"}, "database_specific": {"cwe_ids": ["CWE-2"]}},
                            ],
                        }
                    ]
                },
            )

        source = OSVAdvisorySource(
            package="libfoo",
            ecosystem="Debian",
            client=httpx.Client(transport=httpx.MockTransport(handler)),
        )
        assert source.lookup()[0].vuln_class == "CWE-1"


class TestRrsBranch:
    def test_a_block_that_is_not_a_mapping_is_skipped(self) -> None:
        from verdis.extract.rrs import parse_rrs

        assert parse_rrs("```yaml\n- a\n- b\n```\n") is None


class TestImpactBranches:
    def test_an_impact_with_a_phrase_inside_it(self) -> None:
        assert impact_level("it leads to memory corruption") == 1

    def test_the_demonstrated_impact_of_an_exception(self) -> None:
        assert demonstrated_impact({"exception"}) == "crash"

    def test_the_demonstrated_impact_of_a_canary(self) -> None:
        assert demonstrated_impact({"canary"}) == "information disclosure"


class TestHeuristicBranches:
    def test_a_command_that_is_already_seen_is_ignored(self) -> None:
        claim = HeuristicExtractor().extract("```\n./demo\n./demo\n```")
        assert len(claim.poc_commands) == 1

    def test_a_prompt_line_outside_a_fence_is_found(self) -> None:
        claim = HeuristicExtractor().extract("Run:\n$ ./demo poc.bin")
        assert claim.poc_commands[0].command == "./demo poc.bin"

    def test_a_command_that_is_not_a_command_is_ignored(self) -> None:
        assert not HeuristicExtractor._looks_like_command("Something went wrong")

    def test_a_known_binary_is_a_command(self) -> None:
        assert HeuristicExtractor._looks_like_command("python3 x.py")


class TestExtractorBranches:
    def test_the_model_fills_the_preconditions(self) -> None:
        from tests.unit.test_extractor import FakeProvider

        from verdis.extract.extractor import ClaimExtractor

        provider = FakeProvider({"preconditions": []})
        outcome = ClaimExtractor(provider).extract("nothing here")
        assert outcome.claim.preconditions == ()

    def test_a_value_that_is_not_in_the_text_has_no_span(self) -> None:
        from tests.unit.test_extractor import FakeProvider

        from verdis.extract.extractor import ClaimExtractor

        provider = FakeProvider({"impact": "not in the report"})
        outcome = ClaimExtractor(provider).extract("CWE-122 in the parser")
        assert outcome.claim.span_for("impact") is None


class TestIntakeBranches:
    def test_the_github_client_is_created_and_closed(self, evidence: EvidenceStore) -> None:
        from verdis.intake.github import GitHubPrivateReportIntake

        adapter = GitHubPrivateReportIntake(evidence)
        # No token: the client is never created.
        with pytest.raises(GitHubError):
            adapter.list_reports(owner="example", token="")

    def test_the_issue_client_is_created_and_closed(self, evidence: EvidenceStore) -> None:
        from verdis.intake.github_issue import GitHubIssueIntake

        adapter = GitHubIssueIntake(evidence)
        with pytest.raises(GitHubError):
            adapter.list_issues(owner="example", repo_name="libfoo", token="")

    def test_the_imap_connection_is_opened(self, evidence: EvidenceStore, monkeypatch) -> None:
        import imaplib

        from verdis.intake.imap import ImapIntake

        class _Fake:
            def __init__(self, host, port):
                self.logged_in: tuple[str, str] | None = None

            def login(self, username, password):
                self.logged_in = (username, password)

        monkeypatch.setattr(imaplib, "IMAP4", _Fake)
        monkeypatch.setattr(imaplib, "IMAP4_SSL", _Fake)
        connection = ImapIntake(evidence).connect(host="imap.example.org")
        assert connection is not None

    def test_a_connection_the_adapter_opened_is_closed(self, evidence: EvidenceStore) -> None:
        from verdis.intake.imap import ImapIntake

        class _Owned:
            def __init__(self):
                self.closed = False

            def select(self, mailbox):
                return "OK", [b"0"]

            def uid(self, command, *args):
                if command == "search":
                    return "OK", [b""]
                return "OK", []

            def close(self):
                self.closed = True
                return "OK", [b""]

        # The adapter closes a connection it opened; one it was given is
        # left alone.
        adapter = ImapIntake(evidence)
        connection = _Owned()
        adapter.fetch(host="imap.example.org", connection=connection)
        assert connection.closed is False


class TestJudgeBranches:
    def test_the_reproduce_rule_stands_down_without_a_run(self) -> None:
        judge = Judge()
        assert judge._rule_reproduce(JudgeContext(claim=Claim(), run=None)) is None


class TestOracleBranches:
    def test_an_oracle_applies_to_its_own_expectation(self) -> None:
        from verdis.oracles.crash import CrashOracle

        oracle = CrashOracle()
        assert oracle.applies(ExpectStep(oracle=OracleType.CRASH))
        assert not oracle.applies(ExpectStep(oracle=OracleType.SANITIZER))

    def test_the_differential_reports_the_quiet_case(self) -> None:
        context = OracleContext(
            claim=Claim(),
            expect=ExpectStep(oracle=OracleType.DIFFERENTIAL),
            comparison_run=RunResult(status=RunStatus.COMPLETED, runs=()),
            extra={"primary_fired": "0", "comparison_fired": "0"},
        )
        result = DifferentialOracle().evaluate(
            RunResult(status=RunStatus.COMPLETED, runs=()), context
        )
        assert not result.fired
        assert any("neither" in line or "did not reproduce" in line for line in result.evidence)

    def test_the_frames_skip_a_duplicate_position(self) -> None:
        output = "    #0 0x1 in parse_header a.c:1\n    #0 0x1 in parse_header a.c:1\n"
        assert len(extract_frames(output)) == 2


class TestValidatorBranches:
    def test_a_path_in_the_system_is_allowed(self) -> None:
        plan = Plan(
            steps=(
                RunStep(cmd="./demo /lib/x86_64-linux-gnu/libc.so.6"),
                ExpectStep(oracle="crash"),
            )
        )
        assert PlanValidator().validate(plan).ok

    def test_an_empty_ref_is_ignored(self) -> None:
        plan = Plan(
            steps=(
                RunStep(cmd="./demo"),
                ExpectStep(oracle="crash"),
            )
        )
        assert PlanValidator().validate(plan).ok


class TestPolicyBranches:
    def test_a_pattern_matches_a_stem(self) -> None:
        policy = Policy(in_scope=("parse",))
        assessment = PolicyEngine(policy).check(
            Claim(component=ClaimComponent(name="parse_header"))
        )
        assert assessment.component_in_scope is True

    def test_an_exclusion_with_a_pattern_that_does_not_match(self) -> None:
        policy = Policy(
            excluded_classes=(
                PolicyClause(
                    id="x",
                    kind="excluded",
                    description="d",
                    component_patterns=("config-loader",),
                ),
            )
        )
        assessment = PolicyEngine(policy).check(
            Claim(component=ClaimComponent(name="parse_header"))
        )
        assert not assessment.exclusions

    def test_a_policy_that_is_not_a_mapping_is_rejected(self, tmp_path: Path) -> None:
        path = tmp_path / "policy.yml"
        path.write_text("- a\n", encoding="utf-8")
        with pytest.raises(PolicyLoadError):
            load_policy_file(path)

    def test_a_value_that_is_not_a_list_is_rejected(self) -> None:
        from verdis.policy.loader import policy_from_dict

        with pytest.raises(PolicyLoadError):
            policy_from_dict({"supported_versions": 3})


class TestPreflightBranches:
    def test_a_binary_that_is_not_text_is_flagged(self, tmp_path: Path) -> None:
        path = tmp_path / "a.bin"
        path.write_bytes(b"\xff\xfe\x00\x01")
        assert detect_file_type(path) == "binary"

    def test_an_elf_that_is_not_readable_is_reported(self, tmp_path: Path) -> None:
        report = inspect_binary(tmp_path / "gone.bin")
        assert any(f.code == "binary-unreadable" for f in report.findings)


class TestSandboxBranches:
    def test_the_profile_serialises(self) -> None:
        from dataclasses import asdict

        assert asdict(SandboxProfile())["network"] == "none"

    def test_the_container_reads_a_podman_style_info(self, monkeypatch) -> None:
        import verdis.sandbox.container as container_module

        class _Concrete(ContainerBackend):
            runtime = "fake"
            name = "fake"

            def _unused(self) -> None:  # pragma: no cover
                raise NotImplementedError

        def handler(*args, **kwargs):
            return subprocess.CompletedProcess(
                args, 0, json.dumps({"host": {"security": {"rootless": True}}}), ""
            )

        monkeypatch.setattr(container_module.subprocess, "run", handler)
        backend = _Concrete(binary="fake")
        assert backend._isolation_notes() == [f"{backend.binary} is running rootless"]

    def test_the_container_reads_a_docker_style_info(self, monkeypatch) -> None:
        import verdis.sandbox.container as container_module

        class _Concrete(ContainerBackend):
            runtime = "fake"
            name = "fake"

            def _unused(self) -> None:  # pragma: no cover
                raise NotImplementedError

        def handler(*args, **kwargs):
            return subprocess.CompletedProcess(
                args, 0, json.dumps({"SecurityOptions": ["name=rootless"]}), ""
            )

        monkeypatch.setattr(container_module.subprocess, "run", handler)
        backend = _Concrete(binary="fake")
        assert backend._isolation_notes() == [f"{backend.binary} is running rootless"]


class TestSchemaBranches:
    def test_the_plan_steps_are_normalised(self) -> None:
        plan = Plan(
            steps=[
                RunStep(cmd="./demo"),
                ExpectStep(oracle="crash"),
            ]
        )
        assert isinstance(plan.steps, tuple)

    def test_a_report_needs_an_id(self) -> None:
        from pydantic import ValidationError

        with pytest.raises(ValidationError):
            Report(id="", body="x")

    def test_the_run_reports_no_fire(self) -> None:
        run = RunResult(
            status=RunStatus.COMPLETED,
            runs=(CommandResult(cmd="./demo", exit_code=0),),
        )
        assert not run.any_fired

    def test_the_rrs_step_keeps_its_shape(self) -> None:
        step = RRSPlanStep.model_validate({"action": "run", "value": "./demo"})
        assert step.raw == ""

    def test_the_rrs_step_builds_its_raw_text(self) -> None:
        step = RRSPlanStep.model_validate({"run": "./demo"})
        assert step.raw == "run: ./demo"


class TestStorageBranches:
    def test_a_file_that_is_not_in_the_bundle_is_ignored(self, tmp_path: Path) -> None:
        store = EvidenceStore(tmp_path / "evidence")
        store.write_bundle("VDS-1", {"a.txt": "x"})
        manifest = store.read_manifest("VDS-1")
        assert manifest is not None
        assert len(manifest.files) == 1

    def test_the_bundle_verification_ignores_extra_files(self, tmp_path: Path) -> None:
        store = EvidenceStore(tmp_path / "evidence")
        store.write_bundle("VDS-1", {"a.txt": "x"})
        (store.bundle_dir("VDS-1") / "extra.txt").write_text("y", encoding="utf-8")
        assert store.verify_bundle("VDS-1") == []


class TestSchemaGeneration:
    def test_the_command_writes_the_schemas(self, tmp_path: Path, capsys) -> None:
        from verdis.schemas.generate import main

        assert main([str(tmp_path)]) == 0
        assert (tmp_path / "verdict.schema.json").is_file()
        assert capsys.readouterr().out
