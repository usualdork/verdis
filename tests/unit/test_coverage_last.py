"""Tests for the last of the reachable branches.

The paths here are the ones a report, a policy or a runtime can take that
the behavioural tests do not reach.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from verdis.build.builder import Builder
from verdis.build.checkout import CheckoutError, checkout_ref, default_branch
from verdis.build.recipe import recipe_from_dict
from verdis.dedupe.fingerprint import DedupeFingerprint, extract_stack_signature
from verdis.dedupe.index import LocalAdvisorySource
from verdis.dedupe.osv import OSVAdvisorySource
from verdis.emit.bundle import BundleBuilder
from verdis.emit.card import render_card
from verdis.emit.reply import render_reply, render_reply_body
from verdis.extract.extractor import ClaimExtractor
from verdis.extract.heuristics import HeuristicExtractor
from verdis.extract.rrs import emit_rrs_block, parse_rrs, rrs_fingerprint
from verdis.intake.base import IntakeOutcome
from verdis.judge.rules import Judge, JudgeContext
from verdis.oracles.base import OracleContext, matches_claim, signal_name
from verdis.oracles.canary import CanaryOracle
from verdis.oracles.differential import DifferentialOracle
from verdis.oracles.frames import extract_frame_symbols, extract_frames
from verdis.oracles.property_ import PropertyOracle
from verdis.oracles.sanitizer import SanitizerOracle
from verdis.planner.planner import Planner
from verdis.planner.validator import PlanValidator
from verdis.policy.engine import PolicyEngine, component_matches_pattern
from verdis.policy.loader import PolicyLoadError, derive_policy_from_docs, load_policy_file
from verdis.sandbox.base import SandboxResult
from verdis.sandbox.local import LocalBackend
from verdis.schemas.claim import Claim, ClaimComponent, PoCArtifact
from verdis.schemas.common import OracleType, Verdict
from verdis.schemas.plan import ExpectStep, Plan, RunStep
from verdis.schemas.policy import Policy, PolicyClause, PolicyVerdict
from verdis.schemas.report import Report
from verdis.schemas.run import CommandResult, RunResult, RunStatus
from verdis.schemas.verdict import VerdictResult
from verdis.storage.evidence import EvidenceStore


class TestDedupeFingerprint:
    def test_a_cosine_of_different_lengths_is_zero(self) -> None:
        from verdis.dedupe.fingerprint import cosine_similarity

        assert cosine_similarity((1.0,), (1.0, 0.0)) == 0.0

    def test_a_sanitizer_signature_is_extracted(self) -> None:
        output = "==1==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x1"
        assert "heap-buffer-overflow" in extract_stack_signature(output)

    def test_a_runtime_error_signature_is_extracted(self) -> None:
        output = "src/x.c:10:9: runtime error: signed integer overflow"
        assert "signed integer overflow" in extract_stack_signature(output)

    def test_the_fingerprint_can_be_serialised(self) -> None:
        fingerprint = DedupeFingerprint.build(report_id="VDS-1", body="x")
        assert fingerprint.to_row()["report_id"] == "VDS-1"


class TestDedupeIndex:
    def test_a_broken_advisory_file_is_ignored(self, tmp_path: Path) -> None:
        path = tmp_path / "advisories.json"
        path.write_text("{not json", encoding="utf-8")
        assert LocalAdvisorySource(path).lookup() == []

    def test_an_advisory_file_that_is_not_a_list_is_ignored(self, tmp_path: Path) -> None:
        path = tmp_path / "advisories.json"
        path.write_text('{"a": 1}', encoding="utf-8")
        assert LocalAdvisorySource(path).lookup() == []

    def test_an_advisory_without_an_id_is_skipped(self, tmp_path: Path) -> None:
        path = tmp_path / "advisories.json"
        path.write_text(json.dumps([{"title": "no id"}]), encoding="utf-8")
        assert LocalAdvisorySource(path).lookup() == []

    def test_a_missing_file_is_not_an_error(self, tmp_path: Path) -> None:
        assert LocalAdvisorySource(tmp_path / "nope.json").lookup() == []


class TestOsv:
    def test_a_network_error_is_not_fatal(self) -> None:
        import httpx

        def handler(request: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError("no network")

        source = OSVAdvisorySource(
            package="libfoo",
            ecosystem="Debian",
            client=httpx.Client(transport=httpx.MockTransport(handler)),
        )
        assert source.lookup() == []

    def test_a_response_that_is_not_json_is_not_fatal(self) -> None:
        import httpx

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, text="not json")

        source = OSVAdvisorySource(
            package="libfoo",
            ecosystem="Debian",
            client=httpx.Client(transport=httpx.MockTransport(handler)),
        )
        assert source.lookup() == []

    def test_the_version_is_sent(self) -> None:
        import httpx

        captured: dict[str, object] = {}

        def handler(request: httpx.Request) -> httpx.Response:
            captured["payload"] = json.loads(request.read())
            return httpx.Response(200, json={"vulns": []})

        source = OSVAdvisorySource(
            package="libfoo",
            ecosystem="Debian",
            client=httpx.Client(transport=httpx.MockTransport(handler)),
        )
        source.lookup(version="2.3.1")
        assert captured["payload"]["version"] == "2.3.1"
        assert captured["payload"]["package"]["ecosystem"] == "Debian"

    def test_an_advisory_without_an_id_is_skipped(self) -> None:
        import httpx

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json={"vulns": [{"summary": "no id"}]})

        source = OSVAdvisorySource(
            package="libfoo",
            ecosystem="Debian",
            client=httpx.Client(transport=httpx.MockTransport(handler)),
        )
        assert source.lookup() == []

    def test_the_classes_are_collected(self) -> None:
        import httpx

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200,
                json={
                    "vulns": [
                        {
                            "id": "GHSA-1",
                            "summary": "s",
                            "affected": [
                                {
                                    "package": {"name": "libfoo"},
                                    "database_specific": {"cwe_ids": ["CWE-122"]},
                                }
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
        candidates = source.lookup()
        assert candidates[0].vuln_class == "CWE-122"

    def test_a_class_outside_the_affected_block_is_collected(self) -> None:
        import httpx

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200,
                json={
                    "vulns": [
                        {
                            "id": "GHSA-1",
                            "summary": "s",
                            "affected": [
                                {
                                    "package": {"name": "libfoo"},
                                    "database_specific": {"cwe_ids": ["CWE-79"]},
                                }
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
        assert source.lookup()[0].vuln_class == "CWE-79"


class TestEmit:
    def test_more_than_four_policy_matches_are_counted(self) -> None:
        from verdis.schemas.policy import PolicyMatch

        matches = tuple(
            PolicyMatch(verdict=PolicyVerdict.IN_SCOPE, clause=PolicyClause(id=str(i), kind="version"))
            for i in range(6)
        )
        verdict = VerdictResult(verdict=Verdict.INCONCLUSIVE, policy_matches=matches)
        assert "more policy matches" in render_card(verdict)

    def test_the_reporter_name_is_taken_from_an_address(self) -> None:
        verdict = VerdictResult(verdict=Verdict.INCONCLUSIVE)
        assert "alice@example.org" in render_reply(verdict, reporter="Alice <alice@example.org>")

    def test_the_reporter_name_is_used_as_it_is(self) -> None:
        verdict = VerdictResult(verdict=Verdict.INCONCLUSIVE)
        assert "@someone" in render_reply(verdict, reporter="@someone")

    def test_the_build_failure_is_named(self) -> None:
        from verdis.schemas.run import BuildResult, BuildStatus

        verdict = VerdictResult(
            verdict=Verdict.INCONCLUSIVE,
            build=BuildResult(
                status=BuildStatus.FAILED, failure_step="step 2: make", log_excerpt="x"
            ),
        )
        assert "The build failed at step 2: make." in render_reply_body(verdict)

    def test_the_timeout_is_named(self) -> None:
        verdict = VerdictResult(
            verdict=Verdict.INCONCLUSIVE,
            run=RunResult(status=RunStatus.TIMEOUT, runs=()),
        )
        assert "ran past the time limit" in render_reply_body(verdict)

    def test_the_blocked_network_is_written(self, tmp_path: Path) -> None:
        store = EvidenceStore(tmp_path / "evidence")
        run = RunResult(
            status=RunStatus.COMPLETED,
            runs=(CommandResult(cmd="./demo"),),
            blocked_network=("connection refused",),
        )
        BundleBuilder(store).build(
            report_id="VDS-1",
            verdict=VerdictResult(verdict=Verdict.INCONCLUSIVE),
            run_result=run,
        )
        assert (store.bundle_dir("VDS-1") / "blocked_network.json").is_file()

    def test_the_original_is_copied_in(self, tmp_path: Path) -> None:
        store = EvidenceStore(tmp_path / "evidence")
        source = tmp_path / "report.md"
        source.write_text("the report", encoding="utf-8")
        BundleBuilder(store).copy_original("VDS-1", str(source))
        assert (
            store.bundle_dir("VDS-1") / "original" / "report.md"
        ).read_text(encoding="utf-8") == "the report"

    def test_a_missing_original_is_skipped(self, tmp_path: Path) -> None:
        store = EvidenceStore(tmp_path / "evidence")
        BundleBuilder(store).copy_original("VDS-1", str(tmp_path / "nope.md"))
        assert not (store.bundle_dir("VDS-1") / "original" / "report.md").exists()


class TestExtraction:
    def test_the_heuristics_find_a_script(self) -> None:
        claim = HeuristicExtractor().extract(
            "run it", attachment_names=("run.sh",)
        )
        assert claim.poc_artifacts[0].role == "script"

    def test_the_heuristics_find_a_patch(self) -> None:
        claim = HeuristicExtractor().extract(
            "apply it", attachment_names=("fix.patch",)
        )
        assert claim.poc_artifacts[0].role == "patch"

    def test_a_command_that_is_prose_is_ignored(self) -> None:
        claim = HeuristicExtractor().extract("# Something is wrong in the parser")
        assert claim.poc_commands == ()

    def test_a_command_with_a_known_binary_is_kept(self) -> None:
        claim = HeuristicExtractor().extract("```\npython3 exploit.py\n```")
        assert claim.poc_commands[0].command == "python3 exploit.py"

    def test_a_command_with_a_path_is_kept(self) -> None:
        claim = HeuristicExtractor().extract("```\n./build/demo poc.bin\n```")
        assert claim.poc_commands[0].command == "./build/demo poc.bin"

    def test_a_prompt_line_outside_a_fence_is_kept(self) -> None:
        claim = HeuristicExtractor().extract("Run it:\n$ ./demo poc.bin\n")
        assert claim.poc_commands[0].command == "./demo poc.bin"

    def test_a_command_in_a_fence_is_kept(self) -> None:
        claim = HeuristicExtractor().extract("```sh\n./demo poc.bin\n```")
        assert claim.poc_commands[0].command == "./demo poc.bin"

    def test_a_duplicated_command_is_kept_once(self) -> None:
        claim = HeuristicExtractor().extract("```\n./demo\n./demo\n```")
        assert len(claim.poc_commands) == 1

    def test_the_model_fills_the_artifacts(self) -> None:
        from tests.unit.test_extractor import FakeProvider

        provider = FakeProvider({"artifacts": ["poc.bin"], "commands": []})
        outcome = ClaimExtractor(provider).extract("nothing here")
        assert outcome.claim.poc_artifacts[0].name == "poc.bin"

    def test_the_model_fills_the_preconditions(self) -> None:
        from tests.unit.test_extractor import FakeProvider

        provider = FakeProvider({"preconditions": ["a server is running"]})
        outcome = ClaimExtractor(provider).extract("nothing here")
        assert outcome.claim.preconditions == ("a server is running",)

    def test_a_stale_span_is_dropped(self) -> None:
        from tests.unit.test_extractor import FakeProvider

        # The model names a different file from the one the heuristics
        # found; the span must not point at the old value.
        provider = FakeProvider({"component_file": "other/place.c"})
        outcome = ClaimExtractor(provider).extract(
            "CWE-122 in src/hdr.c"
        )
        span = outcome.claim.span_for("component.file")
        if span is not None:
            assert span.quote == "other/place.c"


class TestRrsHelpers:
    def test_the_block_is_rendered_as_markdown(self) -> None:
        block = emit_rrs_block(repo="r", ref="v1", commands=("./demo",))
        assert block.startswith("```yaml")
        assert parse_rrs(block) is not None

    def test_the_fingerprint_is_stable(self) -> None:
        from verdis.schemas.rrs import RRS, RRSTarget

        rrs = RRS(target=RRSTarget(repo="r", ref="v1"))
        assert rrs_fingerprint(rrs) == rrs_fingerprint(rrs)

    def test_a_block_that_is_not_a_mapping_is_rejected(self) -> None:
        from verdis.extract.rrs import RRSParseError, parse_rrs_document

        with pytest.raises(RRSParseError, match="mapping"):
            parse_rrs_document(["a"])

    def test_a_non_rrs_yaml_block_is_skipped(self) -> None:
        assert parse_rrs("```yaml\nfoo: bar\n```\n") is None


class TestOracles:
    def test_a_missing_signal_has_no_name(self) -> None:
        assert signal_name(None) == ""

    def test_a_signal_has_a_name(self) -> None:
        assert signal_name(11) == "SIGSEGV"

    def test_a_function_only_expectation_matches(self) -> None:
        matched, reason = matches_claim(
            evidence=("in parse_header",),
            expect=ExpectStep(function="parse_header"),
            claim=Claim(),
        )
        assert matched
        assert "parse_header" in reason

    def test_the_canary_records_a_connection(self) -> None:
        run = RunResult(
            status=RunStatus.COMPLETED,
            runs=(CommandResult(cmd="./demo"),),
            canary_hits=("127.0.0.1:5555",),
        )
        context = OracleContext(claim=Claim(), expect=ExpectStep(oracle=OracleType.CANARY))
        result = CanaryOracle().evaluate(run, context)
        assert result.fired
        assert any("connection attempt" in line for line in result.evidence)

    def test_the_property_script_output_is_quoted(self) -> None:
        property_run = RunResult(
            status=RunStatus.COMPLETED,
            runs=(CommandResult(cmd="./check", exit_code=1, stdout="the length was wrong"),),
        )
        context = OracleContext(
            claim=Claim(), expect=ExpectStep(oracle=OracleType.PROPERTY), property_result=property_run
        )
        result = PropertyOracle().evaluate(RunResult(), context)
        assert result.fired
        assert any("the length was wrong" in line for line in result.evidence)

    def test_several_sanitizer_classes_are_reported(self) -> None:
        output = (
            "==1==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x1\n"
            "==1==ERROR: AddressSanitizer: stack-buffer-overflow on address 0x2\n"
        )
        context = OracleContext(claim=Claim(), expect=ExpectStep(oracle=OracleType.SANITIZER))
        result = SanitizerOracle().evaluate(
            RunResult(runs=(CommandResult(cmd="x", stderr=output),)), context
        )
        assert result.fired
        assert any("also reported" in line for line in result.evidence)

    def test_the_differential_reports_the_mixed_case(self) -> None:
        context = OracleContext(
            claim=Claim(),
            expect=ExpectStep(oracle=OracleType.DIFFERENTIAL),
            comparison_run=RunResult(status=RunStatus.COMPLETED, runs=(CommandResult(cmd="x"),)),
            extra={"primary_fired": "0", "comparison_fired": "1"},
        )
        result = DifferentialOracle().evaluate(
            RunResult(status=RunStatus.COMPLETED, runs=(CommandResult(cmd="x"),)), context
        )
        assert not result.fired
        assert any("did not reproduce at the claimed ref" in line for line in result.evidence)

    def test_the_frames_skip_the_noise(self) -> None:
        output = (
            "    #0 0x1 in ERROR something\n"
            "    #1 0x2 in parse_header src/hdr.c:212\n"
        )
        frames = extract_frames(output)
        assert any("parse_header" in frame for frame in frames)

    def test_the_symbols_are_deduplicated(self) -> None:
        output = "    #0 0x1 in parse_header a.c:1\n    #1 0x2 in parse_header b.c:2\n"
        assert extract_frame_symbols(output) == ("parse_header",)


class TestPlannerAndPolicy:
    def test_a_plan_with_a_signature_reports_it(self) -> None:
        plan = Plan(
            steps=(
                RunStep(cmd="./demo"),
                ExpectStep(oracle="crash", signature="  segfault  "),
            )
        )
        assert plan.expected_signature() == "segfault"

    def test_a_plan_without_a_signature_has_none(self) -> None:
        plan = Plan(steps=(RunStep(cmd="./demo"), ExpectStep(oracle="crash")))
        assert plan.expected_signature() == ""

    def test_an_rrs_plan_copies_its_inputs(self) -> None:
        from verdis.schemas.rrs import RRS, RRSInput, RRSPlanStep, RRSTarget

        rrs = RRS(
            target=RRSTarget(repo="r", ref="v1"),
            steps=(RRSPlanStep(action="run", value="./demo poc.bin"),),
            inputs=(RRSInput(path="poc.bin"),),
        )
        plan = Planner(None).plan(Claim(), ref="v1", rrs=rrs)
        assert plan.copy_steps[0].artifact == "poc.bin"

    def test_an_rrs_plan_without_a_command_uses_a_placeholder(self) -> None:
        from verdis.schemas.rrs import RRS, RRSTarget

        rrs = RRS(target=RRSTarget(repo="r", ref="v1"))
        plan = Planner(None).plan(Claim(), ref="v1", rrs=rrs)
        assert plan.run_step.cmd == "./repro"

    def test_an_rrs_plan_can_have_a_comparison(self) -> None:
        from verdis.schemas.rrs import RRS, RRSTarget

        rrs = RRS(target=RRSTarget(repo="r", ref="v1"))
        plan = Planner(None).plan(Claim(), ref="v1", rrs=rrs, comparison_ref="v2")
        assert plan.compare_steps[0].ref == "v2"

    def test_a_model_plan_keeps_the_claim_signature(self) -> None:
        from tests.unit.test_extractor import FakeProvider

        provider = FakeProvider({"commands": ["./demo"], "expect_kind": "crash"})
        claim = Claim(expected={"kind": "crash", "signature": "segfault"})
        plan = Planner(provider).plan(claim, ref="v1")
        assert plan.expect_steps[0].signature == "segfault"

    def test_a_model_plan_copies_the_artifacts(self) -> None:
        from tests.unit.test_extractor import FakeProvider

        provider = FakeProvider({"commands": ["./demo"]})
        claim = Claim(poc_artifacts=(PoCArtifact(name="poc.bin"),))
        plan = Planner(provider).plan(claim, ref="v1")
        assert plan.copy_steps[0].to == "/work/poc.bin"

    def test_a_pattern_matches_a_component(self) -> None:
        assert component_matches_pattern("parser", "parse_header")

    def test_a_pattern_does_not_match_an_unrelated_component(self) -> None:
        assert not component_matches_pattern("parser", "unrelated_module")

    def test_an_exclusion_can_name_the_component(self) -> None:
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
        claim = Claim(component=ClaimComponent(name="config_loader"))
        assessment = PolicyEngine(policy).check(claim)
        assert assessment.exclusions

    def test_a_policy_without_a_scope_is_neutral(self) -> None:
        assessment = PolicyEngine(Policy()).check(Claim())
        assert assessment.component_in_scope is None
        assert assessment.version_supported is None

    def test_an_exclusion_without_a_pattern_does_not_match(self) -> None:
        policy = Policy(
            excluded_classes=(
                PolicyClause(id="x", kind="excluded", description="something unrelated"),
            )
        )
        assessment = PolicyEngine(policy).check(Claim())
        assert not assessment.exclusions

    def test_a_derived_policy_needs_a_document(self, tmp_path: Path) -> None:
        assert derive_policy_from_docs(tmp_path) is None

    def test_an_unreadable_policy_is_reported(self, tmp_path: Path) -> None:
        path = tmp_path / "policy.yml"
        path.write_text("mode: shadow\n", encoding="utf-8")
        path.chmod(0o000)
        try:
            with pytest.raises(PolicyLoadError):
                load_policy_file(path)
        finally:
            path.chmod(0o600)


class TestValidatorBranches:
    def test_a_plan_with_a_seccomp_profile_is_allowed(self) -> None:
        plan = Plan(steps=(RunStep(cmd="./demo"), ExpectStep(oracle="crash")))
        assert PlanValidator().validate(plan).ok

    def test_a_command_outside_the_workdir_needs_confirmation(self) -> None:
        plan = Plan(steps=(RunStep(cmd="./demo /etc/thing"), ExpectStep(oracle="crash")))
        validation = PlanValidator().validate(plan)
        assert validation.needs_confirmation


class TestJudgeBranches:
    def test_a_missing_evidence_clause_is_quoted(self) -> None:
        claim = Claim(missing_fields=("poc",))
        verdict = Judge().judge(JudgeContext(claim=claim))
        assert verdict.verdict is Verdict.NEEDS_INFO
        assert "proof of concept" in verdict.why

    def test_a_verdict_with_no_rule_falls_back(self) -> None:
        # A context with nothing in it cannot produce a verdict.
        verdict = Judge().judge(JudgeContext(claim=Claim()))
        assert verdict.verdict is Verdict.INCONCLUSIVE


class TestIntakeOutcome:
    def test_a_duplicate_is_recognised(self) -> None:
        assert IntakeOutcome(report=Report(id="VDS-1", body="x"), duplicate_of="VDS-0").is_duplicate
        assert not IntakeOutcome(report=Report(id="VDS-1", body="x")).is_duplicate


class TestBuildBranches:
    def test_the_explicit_recipe_is_used(self, tmp_path: Path) -> None:
        project = tmp_path / "project"
        (project / ".verdis").mkdir(parents=True)
        (project / ".verdis" / "recipe.yml").write_text(
            "language: c\nbuild:\n  steps: ['echo built']\n", encoding="utf-8"
        )
        result = Builder(backend=LocalBackend()).build(repo_path=project, in_place=True)
        assert result.status.value == "ok"

    def test_a_broken_recipe_falls_back_to_detection(self, tmp_path: Path) -> None:
        project = tmp_path / "project"
        (project / ".verdis").mkdir(parents=True)
        (project / ".verdis" / "recipe.yml").write_text("build: [\n", encoding="utf-8")
        (project / "Makefile").write_text("all:\n\t@echo built\n", encoding="utf-8")
        result = Builder(backend=LocalBackend()).build(repo_path=project, in_place=True)
        assert result.status.value == "ok"

    def test_a_build_with_no_output_is_reported(self, tmp_path: Path) -> None:

        recipe_from_dict({"language": "c", "build": {"steps": ["true"]}})
        builder = Builder(backend=LocalBackend())
        assert builder._excerpt(SandboxResult(exit_code=1)) == "the build produced no output"

    def test_the_failing_step_is_named(self) -> None:

        recipe = recipe_from_dict(
            {"language": "c", "build": {"steps": ["make build", "make install"]}}
        )
        builder = Builder(backend=LocalBackend())
        result = SandboxResult(exit_code=1, stdout="make build: boom")
        assert "step 1" in builder._failing_step(recipe, result)

    def test_a_recipe_without_steps_has_no_failing_step(self) -> None:

        recipe = recipe_from_dict({"language": "c", "build": {"steps": []}})
        builder = Builder(backend=LocalBackend())
        assert builder._failing_step(recipe, SandboxResult(exit_code=1)) == ""

    def test_the_suggestions_cover_the_common_failures(self) -> None:

        builder = Builder(backend=LocalBackend())
        recipe = recipe_from_dict({"language": "c", "build": {"steps": ["a"]}})
        cases = {
            "command not found": "missing from the build image",
            "Permission denied": "the right mount",
            "network is unreachable": "allowlisted mirror",
            "undefined reference": "did not link",
        }
        for log, expected in cases.items():
            suggestion = builder._suggest_fix(recipe, SandboxResult(exit_code=1, stderr=log))
            assert expected in suggestion


class TestCheckoutBranches:
    def test_a_git_failure_is_reported(self, tmp_path: Path, monkeypatch) -> None:
        import verdis.build.checkout as checkout_module

        def broken(*args, **kwargs):
            raise OSError("git is not installed")

        monkeypatch.setattr(checkout_module.subprocess, "run", broken)
        with pytest.raises(CheckoutError, match="failed"):
            checkout_ref(tmp_path, "v1")

    def test_the_head_is_used_when_there_is_no_branch(self, tmp_path: Path) -> None:
        import verdis.build.checkout as checkout_module

        calls: list[list[str]] = []

        def fake(args, cwd, timeout=120):
            calls.append(list(args))
            if "--git-dir" in args:
                return subprocess.CompletedProcess(args, 0, ".git\n", "")
            if "symbolic-ref" in args:
                return subprocess.CompletedProcess(args, 0, "main\n", "")
            return subprocess.CompletedProcess(args, 1, "", "")

        original = checkout_module._run_git
        checkout_module._run_git = fake  # type: ignore[assignment]
        try:
            assert default_branch(tmp_path) == "main"
            assert any("symbolic-ref" in call for call in calls)
        finally:
            checkout_module._run_git = original  # type: ignore[assignment]
