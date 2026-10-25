"""Tests for the deterministic decision rules (PRD section 8.2)."""

from __future__ import annotations

import pytest

from verdis.judge.impact import demonstrated_impact, impact_level, impact_matches
from verdis.judge.rules import Judge, JudgeContext
from verdis.oracles.engine import OracleOutcome
from verdis.schemas.claim import Claim, ClaimComponent, ExpectedObservable
from verdis.schemas.common import OracleType, Verdict, VerdictFlag, VerdictTier
from verdis.schemas.plan import ExpectStep, Plan, RunStep
from verdis.schemas.policy import PolicyClause, PolicyMatch, PolicyVerdict
from verdis.schemas.preflight import PreflightFinding, PreflightResult, RiskLevel
from verdis.schemas.run import (
    BuildResult,
    BuildStatus,
    CommandResult,
    RunResult,
    RunStatus,
)
from verdis.schemas.verdict import DedupeMatch

ASAN = "AddressSanitizer: heap-buffer-overflow in parse_header src/hdr.c:212"


def _claim(**kwargs) -> Claim:
    base = {
        "component": ClaimComponent(name="parse_header"),
        "vuln_class": "CWE-122",
        "affected_version": "2.3.1",
        "impact": {"summary": "memory corruption"},
        "expected": ExpectedObservable(kind="sanitizer", signature="heap-buffer-overflow"),
    }
    base.update(kwargs)
    return Claim(**base)


def _run(status=RunStatus.COMPLETED, exit_code=0, stderr="", stdout="", signal=None) -> RunResult:
    return RunResult(
        status=status,
        runs=(
            CommandResult(
                cmd="./demo",
                exit_code=exit_code,
                signal=signal,
                stderr=stderr,
                stdout=stdout,
            ),
        ),
    )


def _oracle(
    oracle_type=OracleType.SANITIZER, fired=True, matched=True, flaky=False
) -> OracleOutcome:
    from verdis.schemas.run import OracleResult

    result = OracleResult(
        oracle=oracle_type,
        fired=fired,
        evidence=(f"{oracle_type} fired",),
        matched_claim=matched,
        matching_reason="it matches",
    )
    return OracleOutcome(
        oracle=oracle_type,
        results=(result,),
        fired_count=1 if fired else 0,
        total=1,
        flaky=flaky,
    )


def _context(**kwargs) -> JudgeContext:
    base = {"report_id": "VDS-0001", "target_ref": "v2.3.1", "claim": _claim()}
    base.update(kwargs)
    return JudgeContext(**base)


class TestRule1UnsafeAttachment:
    def test_a_blocked_attachment_stops_the_run(self) -> None:
        preflight = (
            PreflightResult(
                name="run.sh",
                risk_score=90,
                risk_level=RiskLevel.CRITICAL,
                quarantined=True,
                findings=(
                    PreflightFinding(
                        code="script-credential-access",
                        severity=RiskLevel.HIGH,
                        message="script reads credential paths",
                    ),
                ),
            ),
        )
        verdict = Judge().judge(_context(preflight=preflight))
        assert verdict.verdict is Verdict.UNSAFE_ATTACHMENT
        assert verdict.evidence
        assert "not reproduced" in " ".join(verdict.not_established)

    def test_a_safe_attachment_does_not_stop_the_run(self) -> None:
        preflight = (PreflightResult(name="poc.bin"),)
        verdict = Judge().judge(
            _context(preflight=preflight, run=_run(), oracles=(_oracle(),))
        )
        assert verdict.verdict is Verdict.REPRODUCED


class TestRule2NeedsInfo:
    def test_missing_evidence_yields_needs_info(self) -> None:
        match = PolicyMatch(
            verdict=PolicyVerdict.MISSING_EVIDENCE,
            clause=PolicyClause(
                id="evidence:poc-required",
                kind="evidence",
                description="A proof of concept is required",
            ),
            reason="the report contains no proof of concept",
            missing=("poc",),
        )
        verdict = Judge().judge(
            _context(policy_matches=(match,), policy_missing=("poc",))
        )
        assert verdict.verdict is Verdict.NEEDS_INFO
        assert "proof of concept" in verdict.why

    def test_needs_info_quotes_the_policy_clause(self) -> None:
        match = PolicyMatch(
            verdict=PolicyVerdict.MISSING_EVIDENCE,
            clause=PolicyClause(
                id="x",
                kind="evidence",
                description="Reproduce on the default configuration only",
            ),
            missing=("default_configuration",),
        )
        verdict = Judge().judge(
            _context(policy_matches=(match,), policy_missing=("default_configuration",))
        )
        assert "default configuration" in verdict.why


class TestRule3Inconclusive:
    def test_a_failed_build_is_inconclusive(self) -> None:
        build = BuildResult(
            status=BuildStatus.FAILED,
            failure_step="step 1: cmake -S . -B build",
            log_excerpt="CMake Error: no CMAKE_C_COMPILER",
            suggested_fix="install a compiler in the build image",
        )
        verdict = Judge().judge(_context(build=build))
        assert verdict.verdict is Verdict.INCONCLUSIVE
        assert "cmake" in verdict.why
        assert verdict.next_action

    def test_a_timeout_is_inconclusive(self) -> None:
        verdict = Judge().judge(_context(run=_run(status=RunStatus.TIMEOUT)))
        assert verdict.verdict is Verdict.INCONCLUSIVE
        assert "time limit" in verdict.why

    def test_a_flaky_result_is_inconclusive(self) -> None:
        verdict = Judge().judge(
            _context(
                run=_run(),
                oracles=(_oracle(fired=True, matched=False, flaky=True),),
            )
        )
        assert verdict.verdict is Verdict.INCONCLUSIVE
        assert VerdictFlag.FLAKY in verdict.flags

    def test_no_run_at_all_is_inconclusive(self) -> None:
        verdict = Judge().judge(_context(run=None))
        assert verdict.verdict is Verdict.INCONCLUSIVE

    def test_a_failed_to_run_status_is_inconclusive(self) -> None:
        verdict = Judge().judge(_context(run=_run(status=RunStatus.FAILED_TO_RUN)))
        assert verdict.verdict is Verdict.INCONCLUSIVE

    def test_a_command_that_is_not_there_is_inconclusive(self) -> None:
        # 127 is the shell's way of saying the command is not there. The
        # proof of concept never ran, so nothing was shown either way.
        verdict = Judge().judge(_context(run=_run(exit_code=127)))
        assert verdict.verdict is Verdict.INCONCLUSIVE
        assert "not found" in verdict.why
        assert verdict.next_action

    def test_a_run_that_ended_in_127_but_ran_before_is_not_inconclusive(
        self,
    ) -> None:
        verdict = Judge().judge(
            _context(
                run=_run(exit_code=127),
                oracles=(_oracle(),),
            )
        )
        assert verdict.verdict is Verdict.REPRODUCED

    def test_an_unsupported_build_is_inconclusive(self) -> None:
        build = BuildResult(status=BuildStatus.UNSUPPORTED)
        verdict = Judge().judge(_context(build=build))
        assert verdict.verdict is Verdict.INCONCLUSIVE


class TestRule4Oracles:
    def test_a_matched_oracle_yields_reproduced(self) -> None:
        verdict = Judge().judge(
            _context(run=_run(stderr=ASAN), oracles=(_oracle(),))
        )
        assert verdict.verdict is Verdict.REPRODUCED
        assert verdict.tier is VerdictTier.TIER_1
        assert verdict.evidence

    def test_no_oracle_yields_not_reproduced(self) -> None:
        verdict = Judge().judge(
            _context(run=_run(stdout="all good"), oracles=(_oracle(fired=False),))
        )
        assert verdict.verdict is Verdict.NOT_REPRODUCED
        assert verdict.why

    def test_an_unmatched_oracle_yields_not_reproduced_with_the_reason(self) -> None:
        verdict = Judge().judge(
            _context(
                run=_run(stderr="crash in other_function"),
                oracles=(_oracle(fired=True, matched=False),),
            )
        )
        assert verdict.verdict is Verdict.NOT_REPRODUCED
        assert "did not match the claim" in verdict.why

    def test_a_weak_impact_yields_tier_two(self) -> None:
        claim = _claim(impact={"summary": "remote code execution"})
        verdict = Judge().judge(
            _context(
                claim=claim,
                run=_run(stderr=ASAN),
                oracles=(_oracle(oracle_type=OracleType.SANITIZER),),
            )
        )
        assert verdict.verdict is Verdict.REPRODUCED
        assert verdict.tier is VerdictTier.TIER_2
        assert "not proven" in verdict.why

    def test_a_strong_impact_yields_tier_one(self) -> None:
        claim = _claim(impact={"summary": "memory corruption"})
        verdict = Judge().judge(
            _context(
                claim=claim,
                run=_run(stderr=ASAN),
                oracles=(_oracle(oracle_type=OracleType.SANITIZER),),
            )
        )
        assert verdict.tier is VerdictTier.TIER_1

    def test_not_reproduced_states_that_the_poc_did_not_run(self) -> None:
        run = RunResult(status=RunStatus.FAILED_TO_RUN, runs=())
        verdict = Judge().judge(_context(run=run, oracles=()))
        assert verdict.verdict is Verdict.INCONCLUSIVE

    def test_a_non_default_configuration_is_flagged(self) -> None:
        plan = Plan(
            steps=(RunStep(cmd="./demo"), ExpectStep(oracle=OracleType.SANITIZER)),
            default_config=False,
        )
        verdict = Judge().judge(
            _context(run=_run(stderr=ASAN), oracles=(_oracle(),), plan=plan)
        )
        assert VerdictFlag.NON_DEFAULT_CONFIG in verdict.flags

    def test_the_default_configuration_is_flagged(self) -> None:
        plan = Plan(
            steps=(RunStep(cmd="./demo"), ExpectStep(oracle=OracleType.SANITIZER)),
            default_config=True,
        )
        verdict = Judge().judge(
            _context(run=_run(stderr=ASAN), oracles=(_oracle(),), plan=plan)
        )
        assert VerdictFlag.DEFAULT_CONFIG_ONLY in verdict.flags

    def test_a_differential_oracle_sets_fixed_at_head(self) -> None:
        verdict = Judge().judge(
            _context(
                run=_run(stderr=ASAN),
                oracles=(_oracle(), _oracle(oracle_type=OracleType.DIFFERENTIAL)),
            )
        )
        assert VerdictFlag.FIXED_AT_HEAD in verdict.flags


class TestRule5OutOfScope:
    def test_an_exclusion_after_reproduction_yields_out_of_scope(self) -> None:
        exclusion = PolicyMatch(
            verdict=PolicyVerdict.OUT_OF_SCOPE,
            clause=PolicyClause(
                id="local-dos",
                kind="excluded",
                description="Denial of service from unbounded local CLI input",
                quote="DoS from local CLI input is out of scope",
                file="SECURITY.md",
                heading="Out of scope",
                line_start=10,
                line_end=10,
            ),
            reason="matches an excluded class",
        )
        verdict = Judge().judge(
            _context(
                run=_run(stderr=ASAN),
                oracles=(_oracle(),),
                policy_exclusion=exclusion,
            )
        )
        assert verdict.verdict is Verdict.OUT_OF_SCOPE
        assert "SECURITY.md" in verdict.why or "out of scope" in verdict.why.lower()


class TestRule6Duplicate:
    def test_a_duplicate_above_the_threshold_wins(self) -> None:
        matches = (
            DedupeMatch(
                candidate_id="VDS-0002",
                similarity=0.95,
                reasons=("same crash or sanitizer stack signature",),
            ),
        )
        verdict = Judge().judge(
            _context(
                run=_run(stdout="clean"),
                oracles=(_oracle(fired=False),),
                dedupe_matches=matches,
            )
        )
        assert verdict.verdict is Verdict.DUPLICATE
        assert "VDS-0002" in verdict.why

    def test_a_duplicate_wins_over_a_reproduction(self) -> None:
        matches = (DedupeMatch(candidate_id="VDS-0002", similarity=0.95),)
        verdict = Judge().judge(
            _context(run=_run(stderr=ASAN), oracles=(_oracle(),), dedupe_matches=matches)
        )
        assert verdict.verdict is Verdict.DUPLICATE
        # The reproduction evidence is still on the card.
        assert verdict.dedupe_matches
        assert verdict.evidence

    def test_a_duplicate_without_a_run_is_still_a_duplicate(self) -> None:
        # A match above the threshold is a duplicate, whether or not the
        # report was run: the pre-run short-circuit depends on it.
        matches = (DedupeMatch(candidate_id="VDS-0002", similarity=0.95),)
        verdict = Judge().judge(_context(dedupe_matches=matches))
        assert verdict.verdict is Verdict.DUPLICATE

    def test_a_similarity_below_the_threshold_is_not_a_duplicate(self) -> None:
        matches = (DedupeMatch(candidate_id="VDS-0002", similarity=0.3),)
        verdict = Judge().judge(
            _context(
                run=_run(stdout="clean"),
                oracles=(_oracle(fired=False),),
                dedupe_matches=matches,
            )
        )
        assert verdict.verdict is Verdict.NOT_REPRODUCED

    def test_the_threshold_is_configurable(self) -> None:
        judge = Judge(dedupe_threshold=0.2)
        matches = (DedupeMatch(candidate_id="VDS-0002", similarity=0.3),)
        verdict = judge.judge(
            _context(
                run=_run(stdout="clean"),
                oracles=(_oracle(fired=False),),
                dedupe_matches=matches,
            )
        )
        assert verdict.verdict is Verdict.DUPLICATE


class TestRule7Fallback:
    def test_ambiguity_is_never_reproduced(self) -> None:
        # A build that never happened and a run that never happened.
        verdict = Judge().judge(_context(build=None, run=None))
        assert verdict.verdict is Verdict.INCONCLUSIVE
        assert verdict.verdict is not Verdict.REPRODUCED


class TestEvidence:
    def test_every_verdict_states_what_it_does_not_establish(self) -> None:
        verdict = Judge().judge(
            _context(run=_run(stderr=ASAN), oracles=(_oracle(),))
        )
        assert verdict.not_established
        assert any("exploitability" in item for item in verdict.not_established)

    def test_a_not_reproduced_verdict_is_humble(self) -> None:
        verdict = Judge().judge(
            _context(run=_run(stdout="clean"), oracles=(_oracle(fired=False),))
        )
        joined = " ".join(verdict.not_established)
        assert "only that this PoC" in joined
        assert "not vulnerable" in joined  # it explicitly says what is not shown
        assert "invite" in verdict.next_action


class TestImpact:
    @pytest.mark.parametrize(
        ("text", "level"),
        [
            ("remote code execution", 2),
            ("memory corruption", 1),
            ("crash", 1),
            ("privilege escalation", 3),
            ("something vague", 0),
        ],
    )
    def test_impact_level(self, text: str, level: int) -> None:
        assert impact_level(text) == level

    def test_impact_matches_is_at_least_as_strong(self) -> None:
        assert impact_matches("memory corruption", "crash")
        assert not impact_matches("remote code execution", "crash")
        assert impact_matches("anything", "crash")

    def test_demonstrated_impact(self) -> None:
        assert demonstrated_impact({"sanitizer"}) == "memory corruption"
        assert demonstrated_impact({"crash"}) == "crash"
        assert demonstrated_impact({"canary"}, secret_leaked=True) == "information disclosure"
        assert demonstrated_impact(set()) == ""
