"""Tests for the model helpers and the schema validators.

Each of these is a small branch in the data model: the ones a maintainer
hits when a report, a plan or a verdict does not fit the shape.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from verdis.schemas.bundle import BundleManifest, ModelInfo
from verdis.schemas.claim import (
    Claim,
    ClaimComponent,
    ClaimImpact,
    ExpectedObservable,
    PoCArtifact,
    PoCCommand,
)
from verdis.schemas.common import (
    ReportSource,
    Verdict,
    VerdictFlag,
    to_jsonable,
)
from verdis.schemas.plan import (
    BuildStep,
    CheckoutStep,
    CompareStep,
    CopyStep,
    ExpectStep,
    Plan,
    RunStep,
)
from verdis.schemas.policy import (
    EvidenceRequirements,
    Policy,
    PolicyClause,
    PolicyMatch,
    PolicyOrigin,
    PolicyScope,
    PolicyVerdict,
)
from verdis.schemas.preflight import PreflightFinding, PreflightResult, RiskLevel
from verdis.schemas.report import Attachment, Report
from verdis.schemas.rrs import RRS, RRSInput, RRSPlanStep, RRSTarget
from verdis.schemas.run import (
    BuildResult,
    BuildStatus,
    CommandResult,
    OracleResult,
    ResourceUsage,
    RunResult,
    RunStatus,
)
from verdis.schemas.verdict import DedupeMatch, EvidencePoint, VerdictResult


class TestCommon:
    def test_a_value_is_converted_to_json(self) -> None:
        assert to_jsonable({"a": 1}) == {"a": 1}

    def test_an_enum_is_converted_to_its_value(self) -> None:
        assert to_jsonable(Verdict.REPRODUCED) == "REPRODUCED"

    def test_a_datetime_is_converted_to_text(self) -> None:
        moment = datetime(2026, 1, 1, tzinfo=UTC)
        assert to_jsonable(moment) == moment.isoformat()

    def test_a_model_hashes_consistently(self) -> None:
        claim = Claim(vuln_class="CWE-122")
        assert claim.fingerprint() == claim.fingerprint()
        assert len(claim.fingerprint()) == 64


class TestClaim:
    def test_an_empty_command_is_rejected(self) -> None:
        with pytest.raises(ValidationError):
            PoCCommand(command="   ")

    def test_the_class_is_normalised(self) -> None:
        assert ClaimImpact(class_id="cwe 787").class_id == "CWE-787"

    def test_the_component_key_is_normalised(self) -> None:
        assert ClaimComponent(name="Parse Header").key == "parse_header"

    def test_the_observable_kind_is_normalised(self) -> None:
        assert ExpectedObservable(kind="  SANITIZER ").kind == "sanitizer"

    def test_an_empty_observable_kind_is_unknown(self) -> None:
        assert ExpectedObservable(kind="").kind == "unknown"

    def test_an_artifact_without_a_hash_is_allowed(self) -> None:
        assert PoCArtifact(name="poc.bin").sha256 == ""


class TestPlan:
    def test_a_plan_without_a_run_step_is_rejected(self) -> None:
        with pytest.raises(ValueError, match="run step"):
            Plan(steps=(ExpectStep(oracle="crash"),))

    def test_a_plan_without_an_expect_step_is_rejected(self) -> None:
        with pytest.raises(ValueError, match="expect step"):
            Plan(steps=(RunStep(cmd="./demo"),))

    def test_two_run_steps_are_rejected(self) -> None:
        with pytest.raises(ValueError, match="exactly one run step"):
            Plan(steps=(RunStep(cmd="./a"), RunStep(cmd="./b"), ExpectStep(oracle="crash")))

    def test_the_expect_step_must_follow_the_run(self) -> None:
        with pytest.raises(ValueError, match="must follow"):
            Plan(steps=(ExpectStep(oracle="crash"), RunStep(cmd="./a")))

    def test_the_steps_are_reachable_by_kind(self) -> None:
        plan = Plan(
            steps=(
                CheckoutStep(ref="v1"),
                BuildStep(recipe="cmake"),
                CopyStep(artifact="poc.bin", to="/work/poc.bin"),
                RunStep(cmd="./demo"),
                ExpectStep(oracle="crash"),
                CompareStep(ref="v2"),
            )
        )
        assert plan.checkout_step is not None
        assert plan.build_step is not None
        assert plan.copy_steps[0].artifact == "poc.bin"
        assert plan.run_step.cmd == "./demo"
        assert plan.expect_steps[0].oracle.value == "crash"
        assert plan.compare_steps[0].ref == "v2"


class TestPolicy:
    def test_the_citation_names_the_file_and_the_heading(self) -> None:
        clause = PolicyClause(
            id="x",
            kind="excluded",
            description="d",
            file="SECURITY.md",
            heading="Out of scope",
            line_start=10,
            line_end=14,
        )
        assert "SECURITY.md" in clause.citation
        assert "L10-14" in clause.citation

    def test_a_clause_without_a_file_is_not_citable(self) -> None:
        clause = PolicyClause(id="x", kind="excluded", description="d")
        assert clause.citable is False

    def test_a_clause_with_a_quote_is_citable(self) -> None:
        clause = PolicyClause(id="x", kind="excluded", file="SECURITY.md", quote="q")
        assert clause.citable is True

    def test_the_exclusions_are_built_from_the_out_of_scope_list(self) -> None:
        policy = Policy(out_of_scope=["docs only"])
        assert policy.excluded_classes[0].kind == "excluded"

    def test_a_derived_policy_is_unverified(self) -> None:
        assert Policy(derived=True).origin is PolicyOrigin.UNVERIFIED
        assert Policy(confirmed=True).origin is PolicyOrigin.EXPLICIT

    def test_the_evidence_defaults_require_a_poc(self) -> None:
        assert EvidenceRequirements().poc_required is True

    def test_a_match_carries_its_clause(self) -> None:
        match = PolicyMatch(
            verdict=PolicyVerdict.IN_SCOPE,
            clause=PolicyClause(id="x", kind="version", file="SECURITY.md"),
        )
        assert match.citation == "SECURITY.md"

    def test_the_scope_model_is_empty_by_default(self) -> None:
        assert PolicyScope().in_scope == ()


class TestPreflight:
    def test_a_high_finding_is_blocking(self) -> None:
        finding = PreflightFinding(code="x", severity=RiskLevel.HIGH)
        assert finding.is_blocking

    def test_a_low_finding_is_not_blocking(self) -> None:
        finding = PreflightFinding(code="x", severity=RiskLevel.LOW)
        assert not finding.is_blocking

    def test_the_risk_level_follows_the_score(self) -> None:
        assert PreflightResult(name="x", risk_score=80).risk_level is RiskLevel.CRITICAL
        assert PreflightResult(name="x", risk_score=50).risk_level is RiskLevel.HIGH
        assert PreflightResult(name="x", risk_score=30).risk_level is RiskLevel.MEDIUM
        assert PreflightResult(name="x", risk_score=5).risk_level is RiskLevel.LOW
        assert PreflightResult(name="x", risk_score=0).risk_level is RiskLevel.NONE

    def test_a_quarantined_result_is_blocked(self) -> None:
        assert PreflightResult(name="x", quarantined=True).blocked


class TestReport:
    def test_the_attachment_is_looked_up_by_name(self) -> None:
        attachment = Attachment(
            name="poc.bin", path="/tmp/poc.bin", sha256="0" * 64, size=1
        )
        report = Report(id="VDS-1", source=ReportSource.FILE, body="x", attachments=(attachment,))
        assert report.attachment_by_name("poc.bin") is attachment
        assert report.attachment_by_name("other") is None

    def test_the_received_time_is_assumed_utc(self) -> None:
        report = Report(
            id="VDS-1",
            source=ReportSource.FILE,
            body="x",
            received_at=datetime(2026, 1, 1),
        )
        assert report.received_at.tzinfo is not None

    def test_a_report_needs_an_id(self) -> None:
        with pytest.raises(ValidationError):
            Report(id="", source=ReportSource.FILE, body="x")


class TestRun:
    def test_a_run_without_a_status_is_completed(self) -> None:
        assert RunResult().status is RunStatus.COMPLETED

    def test_the_exit_code_is_the_first_one(self) -> None:
        run = RunResult(runs=(CommandResult(cmd="a", exit_code=3),))
        assert run.exit_code == 3
        assert run.exit_codes == (3,)

    def test_a_run_without_commands_has_no_exit_code(self) -> None:
        assert RunResult().exit_code is None

    def test_the_run_did_not_execute_as_intended(self) -> None:
        run = RunResult(runs=(CommandResult(cmd="a"),))
        assert not run.ran_as_intended

    def test_a_run_that_timed_out_did_execute(self) -> None:
        run = RunResult(runs=(CommandResult(cmd="a", timed_out=True),))
        assert run.ran_as_intended

    def test_the_resource_usage_is_reported(self) -> None:
        usage = ResourceUsage(wall_ms=10, exit_status=1)
        assert usage.wall_ms == 10

    def test_an_oracle_result_records_its_extra(self) -> None:
        result = OracleResult(oracle="canary", extra={"secret_leaked": "1"})
        assert result.extra["secret_leaked"] == "1"

    def test_a_build_result_knows_whether_it_worked(self) -> None:
        assert BuildResult(status=BuildStatus.OK).ok
        assert not BuildResult(status=BuildStatus.FAILED).ok


class TestVerdict:
    def test_the_flags_are_a_set(self) -> None:
        verdict = VerdictResult(
            verdict=Verdict.REPRODUCED, tier="tier1", flags=(VerdictFlag.FIXED_AT_HEAD,)
        )
        assert verdict.flag_set() == {VerdictFlag.FIXED_AT_HEAD}

    def test_a_reproduced_verdict_needs_a_tier(self) -> None:
        with pytest.raises(ValidationError):
            VerdictResult(verdict=Verdict.REPRODUCED)

    def test_another_verdict_must_not_have_a_tier(self) -> None:
        with pytest.raises(ValidationError):
            VerdictResult(verdict=Verdict.INCONCLUSIVE, tier="tier1")

    def test_the_evidence_points_are_carried(self) -> None:
        verdict = VerdictResult(
            verdict=Verdict.INCONCLUSIVE, evidence=(EvidencePoint(summary="a"),)
        )
        assert verdict.evidence[0].summary == "a"

    def test_a_duplicate_match_carries_its_reasons(self) -> None:
        match = DedupeMatch(candidate_id="VDS-1", similarity=0.9, reasons=("same",))
        assert match.reasons == ("same",)


class TestBundle:
    def test_an_empty_model_is_not_used(self) -> None:
        assert ModelInfo().used is False
        assert ModelInfo(name="gpt").used is True

    def test_a_manifest_records_its_files(self) -> None:
        manifest = BundleManifest(report_id="VDS-1")
        assert manifest.files == ()

    def test_the_manifest_is_serialisable(self) -> None:
        manifest = BundleManifest(report_id="VDS-1", verdict="REPRODUCED")
        assert json.loads(manifest.model_dump_json())["verdict"] == "REPRODUCED"


class TestRRS:
    def test_a_step_can_be_a_single_key_mapping(self) -> None:
        step = RRSPlanStep.model_validate({"run": "./demo"})
        assert step.action == "run"
        assert step.value == "./demo"

    def test_a_step_can_be_a_string(self) -> None:
        step = RRSPlanStep.model_validate("run: ./demo")
        assert step.action == "run"
        assert step.value == "./demo"

    def test_a_hash_may_be_a_number(self) -> None:
        assert RRSInput(path="poc.bin", sha256=0).sha256 == "0" * 64

    def test_a_negative_hash_is_rejected(self) -> None:
        with pytest.raises(ValidationError):
            RRSInput(path="poc.bin", sha256=-1)

    def test_a_boolean_hash_is_rejected(self) -> None:
        with pytest.raises(ValidationError):
            RRSInput(path="poc.bin", sha256=True)

    def test_the_version_must_be_supported(self) -> None:
        with pytest.raises(ValidationError):
            RRS(target=RRSTarget(repo="r"), version="9.9")

    def test_the_expect_block_is_read(self) -> None:
        rrs = RRS(
            target=RRSTarget(repo="r"),
            expect={"oracle": "SANITIZER", "signature": "sig"},
        )
        assert rrs.oracle is not None
        assert rrs.signature == "sig"

    def test_the_build_instructions_are_read(self) -> None:
        rrs = RRS(
            target=RRSTarget(repo="r"),
            steps=(RRSPlanStep(action="build", value="default"),),
        )
        assert rrs.build_instructions() == ("default",)

    def test_a_claim_with_a_class_is_flattened(self) -> None:
        rrs = RRS.model_validate(
            {"rrs": "0.1", "target": {"repo": "r"}, "claim": {"class": "CWE-122"}}
        )
        assert rrs.claim_class == "CWE-122"
