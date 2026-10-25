"""The last of the reachable branches.

What is left here is narrow: a stem comparison, a plan accessor, an
engine branch. Each was found by reading the coverage report rather than
by guessing, so each is a real path.
"""

from __future__ import annotations

from pathlib import Path

from verdis.extract.heuristics import HeuristicExtractor
from verdis.judge.rules import Judge, JudgeContext
from verdis.oracles.engine import OracleEngine, OracleOutcome
from verdis.policy.engine import _shares_stem
from verdis.preflight.analyzers import inspect_archive
from verdis.schemas.common import OracleType, Verdict
from verdis.schemas.plan import ExpectStep, Plan, RunStep
from verdis.schemas.rrs import RRSPlanStep
from verdis.schemas.run import CommandResult, OracleResult, RunResult, RunStatus


class TestStemMatching:
    def test_an_empty_word_never_shares_a_stem(self) -> None:
        assert not _shares_stem("", "parse_header")

    def test_a_short_word_never_shares_a_stem(self) -> None:
        assert not _shares_stem("a", "abc")

    def test_a_prefix_shares_a_stem(self) -> None:
        assert _shares_stem("parse", "parse_header")

    def test_the_longer_word_may_come_first(self) -> None:
        assert _shares_stem("parse_header", "parse")

    def test_unrelated_words_do_not_share_a_stem(self) -> None:
        assert not _shares_stem("parser", "unrelated")


class TestPlanAccessors:
    def test_a_plan_without_a_build_step_has_none(self) -> None:
        plan = Plan(steps=(RunStep(cmd="./demo"), ExpectStep(oracle="crash")))
        assert plan.build_step is None
        assert plan.checkout_step is None
        assert plan.compare_steps == ()


class TestEngineBranches:
    def test_a_flaky_result_is_reported_as_flaky(self) -> None:
        plan = Plan(steps=(RunStep(cmd="./demo"), ExpectStep(oracle=OracleType.SANITIZER)))
        run = RunResult(
            status=RunStatus.COMPLETED,
            runs=(
                CommandResult(
                    cmd="./demo",
                    exit_code=1,
                    stderr="==1==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x1",
                ),
                CommandResult(cmd="./demo", exit_code=0),
            ),
        )
        outcomes = OracleEngine().evaluate(run, plan, __import__(
            "verdis.schemas.claim", fromlist=["Claim"]
        ).Claim())
        sanitizer = next(o for o in outcomes if o.oracle is OracleType.SANITIZER)
        assert sanitizer.flaky
        result = sanitizer.to_result()
        assert result.fired
        assert "flaky" in result.matching_reason


class TestJudgeBranches:
    def test_a_skipped_build_is_inconclusive(self) -> None:
        from verdis.schemas.run import BuildResult, BuildStatus

        verdict = Judge().judge(
            JudgeContext(
                claim=__import__("verdis.schemas.claim", fromlist=["Claim"]).Claim(),
                build=BuildResult(status=BuildStatus.SKIPPED),
                run=None,
            )
        )
        assert verdict.verdict is Verdict.INCONCLUSIVE
        assert "not built" in verdict.why

    def test_a_blocked_run_is_inconclusive(self) -> None:
        verdict = Judge().judge(
            JudgeContext(
                claim=__import__("verdis.schemas.claim", fromlist=["Claim"]).Claim(),
                run=RunResult(status=RunStatus.BLOCKED, runs=()),
            )
        )
        assert verdict.verdict is Verdict.INCONCLUSIVE
        assert "blocked the run" in verdict.why

    def test_a_run_that_could_not_start_is_inconclusive(self) -> None:
        verdict = Judge().judge(
            JudgeContext(
                claim=__import__("verdis.schemas.claim", fromlist=["Claim"]).Claim(),
                run=RunResult(status=RunStatus.FAILED_TO_RUN, runs=()),
            )
        )
        assert verdict.verdict is Verdict.INCONCLUSIVE
        assert "could not be started" in verdict.why

    def test_a_poc_that_did_not_run_is_honest(self) -> None:
        run = RunResult(status=RunStatus.COMPLETED, runs=(CommandResult(cmd="./demo"),))
        verdict = Judge().judge(
            JudgeContext(
                claim=__import__("verdis.schemas.claim", fromlist=["Claim"]).Claim(),
                run=run,
                oracles=(),
            )
        )
        assert verdict.verdict is Verdict.NOT_REPRODUCED
        assert "did not execute as intended" in verdict.why

    def test_the_fallback_point_is_added(self) -> None:
        from verdis.schemas.common import OracleType as _Type

        outcome = OracleOutcome(
            oracle=_Type.SANITIZER,
            results=(
                OracleResult(
                    oracle=_Type.SANITIZER,
                    fired=True,
                    matched_claim=True,
                ),
            ),
            fired_count=1,
            total=1,
        )
        verdict = Judge().judge(
            JudgeContext(
                claim=__import__("verdis.schemas.claim", fromlist=["Claim"]).Claim(),
                run=RunResult(
                    status=RunStatus.COMPLETED,
                    runs=(CommandResult(cmd="./demo"),),
                ),
                oracles=(outcome,),
            )
        )
        assert verdict.evidence
        assert "no oracle matched" in verdict.evidence[0].summary


class TestHeuristicBranches:
    def test_a_command_that_is_already_seen_is_ignored(self) -> None:
        claim = HeuristicExtractor().extract("```\n./demo\n./demo\n```")
        assert len(claim.poc_commands) == 1

    def test_a_command_that_is_not_a_command_is_ignored(self) -> None:
        claim = HeuristicExtractor().extract("```\nSomething went wrong\n```")
        assert claim.poc_commands == ()

    def test_a_prompt_line_outside_a_fence_is_found(self) -> None:
        claim = HeuristicExtractor().extract("Run:\n$ ./demo poc.bin")
        assert claim.poc_commands[0].command == "./demo poc.bin"

    def test_a_prompt_line_inside_a_fence_is_found(self) -> None:
        claim = HeuristicExtractor().extract("```\n$ ./demo poc.bin\n```")
        assert claim.poc_commands[0].command == "./demo poc.bin"

    def test_a_span_is_recorded_for_a_prompt_line(self) -> None:
        claim = HeuristicExtractor().extract("Run:\n$ ./demo poc.bin")
        span = claim.poc_commands[0].span
        assert span is not None
        assert span.quote == "./demo poc.bin"


class TestRrsStepBranches:
    def test_a_step_mapping_with_several_keys_is_kept(self) -> None:
        step = RRSPlanStep.model_validate({"other": "value"})
        assert step.action == "other"

    def test_a_step_that_is_already_normalised_is_kept(self) -> None:
        step = RRSPlanStep.model_validate({"action": "run", "value": "./demo"})
        assert step.action == "run"


class TestArchiveBranch:
    def test_an_archive_that_is_too_large_is_flagged(self, tmp_path: Path) -> None:
        import zipfile

        path = tmp_path / "a.zip"
        with zipfile.ZipFile(path, "w", zipfile.ZIP_STORED) as archive:
            archive.writestr("big.bin", b"\x00" * 4096)
        report = inspect_archive(path, max_total_size=1024)
        assert any(f.code == "archive-too-large" for f in report.findings)


class TestIntakeClosers:
    def test_the_github_client_is_closed(self, evidence) -> None:
        from verdis.intake.github import GitHubPrivateReportIntake

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json=[])

        import httpx

        adapter = GitHubPrivateReportIntake(evidence)
        adapter.list_reports(
            owner="example", token="t", client=httpx.Client(
                transport=httpx.MockTransport(handler), base_url="https://api.github.com"
            )
        )

    def test_a_string_label_is_read(self, evidence) -> None:
        from verdis.intake.github_issue import GitHubIssueIntake

        payload = {
            "number": 1,
            "title": "bug",
            "body": "text",
            "labels": ["security"],
        }
        outcome = GitHubIssueIntake(evidence).normalize(payload, repo="example/libfoo")
        assert outcome.report.labels == ("security",)


class TestImapBranches:
    def test_a_message_that_is_not_text_is_skipped(self, evidence) -> None:
        from verdis.intake.imap import ImapIntake

        class _Fake:
            def uid(self, command, *args):
                if command == "search":
                    return "OK", [b"1"]
                return "OK", [(b"1 (RFC822 {1}", b"\r\n\r\n")]

            def select(self, mailbox):
                return "OK", [b"1"]

            def close(self):
                return "OK", [b""]

        outcomes = ImapIntake(evidence).fetch(
            host="imap.example.org", connection=_Fake()
        )
        assert outcomes == []


class TestPreflightBranches:
    def test_an_opaque_binary_is_flagged(self, tmp_path: Path) -> None:
        from verdis.schemas.report import Attachment

        path = tmp_path / "a.bin"
        path.write_bytes(b"\xff\xfe\x00\x01")
        result = Preflight_with(20).inspect(
            Attachment(
                name="a.bin",
                path=str(path),
                sha256="0" * 64,
                size=path.stat().st_size,
            )
        )
        assert any(f.code == "binary-opaque" for f in result.findings)


def Preflight_with(threshold: int):
    from verdis.preflight.preflight import Preflight

    return Preflight(threshold=threshold)
