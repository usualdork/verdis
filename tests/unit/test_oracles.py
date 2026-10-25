"""Tests for the oracles (FR-8.2, FR-8.3)."""

from __future__ import annotations

from verdis.oracles.base import OracleContext, extract_frames, matches_claim
from verdis.oracles.canary import CanaryOracle
from verdis.oracles.crash import CrashOracle
from verdis.oracles.differential import DifferentialOracle
from verdis.oracles.engine import OracleEngine
from verdis.oracles.exception import ExceptionOracle
from verdis.oracles.output import OutputOracle
from verdis.oracles.property_ import PropertyOracle
from verdis.oracles.sanitizer import SanitizerOracle
from verdis.schemas.claim import Claim, ClaimComponent, ExpectedObservable
from verdis.schemas.common import OracleType
from verdis.schemas.plan import ExpectStep
from verdis.schemas.run import CommandResult, RunResult, RunStatus

ASAN_OUTPUT = """\
==12345==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x602000000010
READ of size 64 at 0x602000000010 thread T0
    #0 0x4f2a in parse_header src/hdr.c:212
    #1 0x4f80 in main src/hdr.c:260
SUMMARY: AddressSanitizer: heap-buffer-overflow src/hdr.c:212 in parse_header
"""


def _run(stdout: str = "", stderr: str = "", exit_code: int | None = 0, signal: int | None = None):
    return RunResult(
        status=RunStatus.COMPLETED,
        runs=(CommandResult(cmd="./demo", exit_code=exit_code, signal=signal, stdout=stdout, stderr=stderr),),
    )


def _context(**kwargs) -> OracleContext:
    claim = kwargs.pop(
        "claim",
        Claim(
            component=ClaimComponent(name="parse_header"),
            expected=ExpectedObservable(kind="sanitizer", signature="heap-buffer-overflow"),
        ),
    )
    expect = kwargs.pop("expect", ExpectStep(oracle=OracleType.SANITIZER, signature="heap-buffer-overflow"))
    return OracleContext(claim=claim, expect=expect, **kwargs)


class TestCrashOracle:
    def test_fires_on_a_signal(self) -> None:
        result = CrashOracle().evaluate(_run(exit_code=None, signal=11), _context())
        assert result.fired
        assert any("SIGSEGV" in line for line in result.evidence)

    def test_fires_on_a_crash_message(self) -> None:
        result = CrashOracle().evaluate(_run(stderr="Segmentation fault"), _context())
        assert result.fired

    def test_fires_on_a_negative_exit_code_and_names_the_top_frames(self) -> None:
        # A runtime that reports death by signal as a negative exit code
        # (as a host process does) fires the oracle on its own, and the
        # frames in the output say where it died.
        result = CrashOracle().evaluate(_run(stderr=ASAN_OUTPUT, exit_code=-6), _context())
        assert result.fired
        assert any("exited with signal 6" in line for line in result.evidence)
        assert any(line.startswith("top frames:") and "parse_header" in line for line in result.evidence)

    def test_does_not_fire_on_a_clean_run(self) -> None:
        result = CrashOracle().evaluate(_run(stdout="all good", exit_code=0), _context())
        assert not result.fired
        assert result.reason


class TestSanitizerOracle:
    def test_fires_on_asan_output(self) -> None:
        result = SanitizerOracle().evaluate(_run(stderr=ASAN_OUTPUT), _context())
        assert result.fired
        assert any("heap-buffer-overflow" in line for line in result.evidence)

    def test_does_not_fire_without_a_diagnostic(self) -> None:
        result = SanitizerOracle().evaluate(_run(stdout="fine"), _context())
        assert not result.fired

    def test_ubsan_is_detected(self) -> None:
        output = "src/x.c:10:9: runtime error: signed integer overflow"
        result = SanitizerOracle().evaluate(_run(stderr=output), _context())
        assert result.fired

    def test_a_crash_in_another_function_does_not_match(self) -> None:
        output = ASAN_OUTPUT.replace("parse_header", "other_function")
        context = _context(
            expect=ExpectStep(
                oracle=OracleType.SANITIZER,
                signature="heap-buffer-overflow",
                function="parse_header",
            )
        )
        result = SanitizerOracle().evaluate(_run(stderr=output), context)
        assert result.fired
        assert not result.matched_claim
        assert "parse_header" in result.matching_reason


class TestExceptionOracle:
    def test_fires_on_a_python_traceback(self) -> None:
        output = "Traceback (most recent call last):\n  File \"x.py\", line 3\nValueError: bad"
        result = ExceptionOracle().evaluate(_run(stderr=output), _context())
        assert result.fired

    def test_fires_on_a_panic(self) -> None:
        result = ExceptionOracle().evaluate(_run(stderr="panic: index out of range"), _context())
        assert result.fired

    def test_does_not_fire_on_clean_output(self) -> None:
        result = ExceptionOracle().evaluate(_run(stdout="ok"), _context())
        assert not result.fired


class TestOutputOracle:
    def test_fires_on_a_regex_match(self) -> None:
        context = _context(expect=ExpectStep(oracle=OracleType.OUTPUT, regex="MAGIC=.*"))
        result = OutputOracle().evaluate(_run(stdout="MAGIC=deadbeef"), context)
        assert result.fired

    def test_fires_on_the_expected_exit_code(self) -> None:
        context = _context(expect=ExpectStep(oracle=OracleType.OUTPUT, exit_code=3))
        result = OutputOracle().evaluate(_run(exit_code=3), context)
        assert result.fired

    def test_does_not_fire_on_a_wrong_exit_code(self) -> None:
        context = _context(expect=ExpectStep(oracle=OracleType.OUTPUT, exit_code=3))
        result = OutputOracle().evaluate(_run(exit_code=0), context)
        assert not result.fired

    def test_fires_on_a_stated_string(self) -> None:
        context = _context(
            expect=ExpectStep(oracle=OracleType.OUTPUT, signature="VERDIS-SECRET")
        )
        result = OutputOracle().evaluate(
            _run(stdout="VERDIS-SECRET-9f3a"), context
        )
        assert result.fired
        assert any("VERDIS-SECRET" in line for line in result.evidence)

    def test_does_not_fire_when_the_string_is_absent(self) -> None:
        context = _context(
            expect=ExpectStep(oracle=OracleType.OUTPUT, signature="VERDIS-SECRET")
        )
        result = OutputOracle().evaluate(_run(stdout="nothing here"), context)
        assert not result.fired

    def test_an_invalid_regex_is_reported_not_raised(self) -> None:
        context = _context(expect=ExpectStep(oracle=OracleType.OUTPUT, regex="(["))
        result = OutputOracle().evaluate(_run(stdout="x"), context)
        assert not result.fired
        assert "does not compile" in result.reason


class TestCanaryOracle:
    def test_fires_when_the_secret_is_disclosed(self) -> None:
        context = _context(expect=ExpectStep(oracle=OracleType.CANARY), canary_secret="S3CR3T")
        result = CanaryOracle().evaluate(_run(stdout="the secret is S3CR3T"), context)
        assert result.fired

    def test_fires_on_a_blocked_network_attempt(self) -> None:
        run = _run(stderr="Network is unreachable")
        run = run.model_copy(update={"blocked_network": ("network is unreachable",)})
        context = _context(expect=ExpectStep(oracle=OracleType.CANARY))
        result = CanaryOracle().evaluate(run, context)
        assert result.fired

    def test_does_not_fire_on_a_clean_run(self) -> None:
        context = _context(expect=ExpectStep(oracle=OracleType.CANARY), canary_secret="S3CR3T")
        result = CanaryOracle().evaluate(_run(stdout="nothing"), context)
        assert not result.fired


class TestPropertyOracle:
    def test_fires_when_the_property_is_violated(self) -> None:
        property_run = _run(exit_code=1, stderr="property violated")
        context = _context(expect=ExpectStep(oracle=OracleType.PROPERTY), property_result=property_run)
        result = PropertyOracle().evaluate(_run(), context)
        assert result.fired

    def test_does_not_fire_when_the_property_holds(self) -> None:
        property_run = _run(exit_code=0)
        context = _context(expect=ExpectStep(oracle=OracleType.PROPERTY), property_result=property_run)
        result = PropertyOracle().evaluate(_run(), context)
        assert not result.fired

    def test_without_a_property_script_it_does_not_fire(self) -> None:
        context = _context(expect=ExpectStep(oracle=OracleType.PROPERTY))
        result = PropertyOracle().evaluate(_run(), context)
        assert not result.fired


class TestDifferentialOracle:
    def test_fires_when_only_the_claimed_ref_reproduces(self) -> None:
        context = _context(
            expect=ExpectStep(oracle=OracleType.DIFFERENTIAL),
            comparison_run=_run(stdout="clean"),
            extra={"primary_fired": "1", "comparison_fired": "0"},
        )
        result = DifferentialOracle().evaluate(_run(stderr=ASAN_OUTPUT), context)
        assert result.fired

    def test_does_not_fire_when_both_reproduce(self) -> None:
        context = _context(
            expect=ExpectStep(oracle=OracleType.DIFFERENTIAL),
            comparison_run=_run(stderr=ASAN_OUTPUT),
            extra={"primary_fired": "1", "comparison_fired": "1"},
        )
        result = DifferentialOracle().evaluate(_run(stderr=ASAN_OUTPUT), context)
        assert not result.fired

    def test_without_a_comparison_ref_it_does_not_fire(self) -> None:
        context = _context(expect=ExpectStep(oracle=OracleType.DIFFERENTIAL))
        result = DifferentialOracle().evaluate(_run(), context)
        assert not result.fired


class TestMatching:
    def test_extracts_frames(self) -> None:
        frames = extract_frames(ASAN_OUTPUT)
        assert frames
        assert "parse_header" in frames[0]

    def test_a_matching_signature_and_function(self) -> None:
        matched, reason = matches_claim(
            evidence=("AddressSanitizer: heap-buffer-overflow in parse_header",),
            expect=ExpectStep(signature="heap-buffer-overflow", function="parse_header"),
            claim=Claim(),
        )
        assert matched
        assert "both match" in reason

    def test_a_mismatched_signature(self) -> None:
        matched, reason = matches_claim(
            evidence=("AddressSanitizer: stack-overflow",),
            expect=ExpectStep(signature="heap-buffer-overflow"),
            claim=Claim(),
        )
        assert not matched
        assert "heap-buffer-overflow" in reason

    def test_a_mismatched_function(self) -> None:
        matched, reason = matches_claim(
            evidence=(
                "run 1: sanitizer class heap-buffer-overflow",
                "run 1: frame #1 other_function (hdr.c:12)",
            ),
            expect=ExpectStep(signature="heap-buffer-overflow", function="parse_header"),
            claim=Claim(),
        )
        assert not matched
        assert "parse_header" in reason

    def test_evidence_without_a_stack_does_not_contradict_the_claim(self) -> None:
        # A sanitizer that aborts early prints no stack. That is an
        # absence of evidence, not evidence of a different function, so
        # the signature decides.
        matched, reason = matches_claim(
            evidence=("run 1: sanitizer class heap-buffer-overflow",),
            expect=ExpectStep(signature="heap-buffer-overflow", function="parse_header"),
            claim=Claim(),
        )
        assert matched
        assert "could not be confirmed" in reason

    def test_no_expectation_always_matches(self) -> None:
        matched, _reason = matches_claim(evidence=("anything",), expect=ExpectStep(), claim=Claim())
        assert matched


class TestOracleEngine:
    def _plan(self):
        from verdis.schemas.plan import Plan, RunStep

        return Plan(
            steps=(
                RunStep(cmd="./demo"),
                ExpectStep(oracle=OracleType.SANITIZER, signature="heap-buffer-overflow"),
            )
        )

    def test_evaluates_the_declared_oracle_and_the_always_on_ones(self) -> None:
        engine = OracleEngine()
        outcomes = engine.evaluate(_run(stderr=ASAN_OUTPUT), self._plan(), Claim())
        kinds = {o.oracle for o in outcomes}
        assert OracleType.SANITIZER in kinds
        assert OracleType.CRASH in kinds
        assert OracleType.CANARY in kinds

    def test_aggregates_across_repetitions(self) -> None:
        from verdis.schemas.plan import Plan, RunStep

        plan = Plan(steps=(RunStep(cmd="./demo"), ExpectStep(oracle=OracleType.SANITIZER)))
        run = RunResult(
            status=RunStatus.COMPLETED,
            runs=(
                CommandResult(cmd="./demo", exit_code=0, stderr=ASAN_OUTPUT),
                CommandResult(cmd="./demo", exit_code=0, stderr=ASAN_OUTPUT),
                CommandResult(cmd="./demo", exit_code=0, stderr="clean"),
            ),
        )
        outcomes = OracleEngine().evaluate(run, plan, Claim())
        sanitizer = next(o for o in outcomes if o.oracle is OracleType.SANITIZER)
        assert sanitizer.fired_count == 2
        assert sanitizer.flaky

    def test_a_consistent_result_is_not_flaky(self) -> None:
        from verdis.schemas.plan import Plan, RunStep

        plan = Plan(steps=(RunStep(cmd="./demo"), ExpectStep(oracle=OracleType.SANITIZER)))
        run = RunResult(
            status=RunStatus.COMPLETED,
            runs=(
                CommandResult(cmd="./demo", exit_code=0, stderr=ASAN_OUTPUT),
                CommandResult(cmd="./demo", exit_code=0, stderr=ASAN_OUTPUT),
            ),
        )
        outcomes = OracleEngine().evaluate(run, plan, Claim())
        sanitizer = next(o for o in outcomes if o.oracle is OracleType.SANITIZER)
        assert not sanitizer.flaky
        assert sanitizer.consistently_fired

    def test_the_differential_oracle_runs_only_with_a_comparison(self) -> None:
        from verdis.schemas.plan import Plan, RunStep

        plan = Plan(steps=(RunStep(cmd="./demo"), ExpectStep(oracle=OracleType.SANITIZER)))
        engine = OracleEngine()
        without = engine.evaluate(_run(stderr=ASAN_OUTPUT), plan, Claim())
        # Without a comparison ref there is nothing to compare, so the
        # differential oracle is not evaluated at all.
        assert all(o.oracle is not OracleType.DIFFERENTIAL for o in without)
        with_comparison = engine.evaluate(
            _run(stderr=ASAN_OUTPUT), plan, Claim(), comparison_run=_run(stdout="clean")
        )
        differential = next(o for o in with_comparison if o.oracle is OracleType.DIFFERENTIAL)
        assert differential.fired
