"""Oracle engine: run the oracles and aggregate their results (FR-8.2, FR-8.4).

Each repetition of the PoC is evaluated separately so that flakiness is
detectable: an oracle that fires in some repetitions and not others yields
a flaky outcome, which is INCONCLUSIVE rather than REPRODUCED (FR-8.4).
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ..schemas.claim import Claim
from ..schemas.common import OracleType
from ..schemas.plan import ExpectStep, Plan
from ..schemas.run import CommandResult, OracleResult, RunResult
from .base import Oracle, OracleContext
from .canary import CanaryOracle
from .crash import CrashOracle
from .differential import DifferentialOracle
from .exception import ExceptionOracle
from .output import OutputOracle
from .property_ import PropertyOracle
from .sanitizer import SanitizerOracle

__all__ = ["DEFAULT_ORACLES", "OracleEngine", "OracleOutcome"]

DEFAULT_ORACLES: dict[OracleType, Oracle] = {
    OracleType.CRASH: CrashOracle(),
    OracleType.SANITIZER: SanitizerOracle(),
    OracleType.EXCEPTION: ExceptionOracle(),
    OracleType.CANARY: CanaryOracle(),
    OracleType.DIFFERENTIAL: DifferentialOracle(),
    OracleType.PROPERTY: PropertyOracle(),
    OracleType.OUTPUT: OutputOracle(),
}

#: Oracles that are evaluated for every run, whether or not the plan asked
#: for them, because they state facts about the run that a maintainer needs.
ALWAYS_ON = (
    OracleType.CRASH,
    OracleType.SANITIZER,
    OracleType.EXCEPTION,
    OracleType.CANARY,
    OracleType.DIFFERENTIAL,
)


@dataclass
class OracleOutcome:
    """The aggregate of one oracle across every repetition."""

    oracle: OracleType
    results: tuple[OracleResult, ...] = ()
    fired_count: int = 0
    total: int = 0
    flaky: bool = False

    @property
    def fired(self) -> bool:
        return self.fired_count > 0

    @property
    def consistently_fired(self) -> bool:
        return self.total > 0 and self.fired_count == self.total

    @property
    def matched(self) -> bool:
        return any(r.matched_claim for r in self.results)

    @property
    def evidence(self) -> tuple[str, ...]:
        out: list[str] = []
        for result in self.results:
            for line in result.evidence:
                if line not in out:
                    out.append(line)
        return tuple(out)

    @property
    def matching_reason(self) -> str:
        for result in self.results:
            if result.matched_claim and result.matching_reason:
                return result.matching_reason
        for result in self.results:
            if result.fired and result.matching_reason:
                return result.matching_reason
        return ""

    @property
    def extra(self) -> dict[str, str]:
        """The extras the oracle recorded, merged over every repetition."""
        merged: dict[str, str] = {}
        for result in self.results:
            merged.update(result.extra)
        return merged

    def to_result(self) -> OracleResult:
        """Collapse the per-repetition results into one result."""
        fired = self.fired
        evidence = self.evidence
        matched = self.matched
        reason = self.matching_reason
        if not fired:
            last = self.results[-1] if self.results else None
            return OracleResult(
                oracle=self.oracle,
                fired=False,
                reason=last.reason if last else "the oracle did not run",
                evidence=evidence,
            )
        if self.flaky:
            return OracleResult(
                oracle=self.oracle,
                fired=True,
                reason="",
                evidence=evidence,
                matched_claim=False,
                matching_reason=(
                    f"the oracle fired in {self.fired_count} of {self.total} repetitions, "
                    "so the outcome is flaky"
                ),
                extra={
                    "fired_count": str(self.fired_count),
                    "total": str(self.total),
                },
            )
        return OracleResult(
            oracle=self.oracle,
            fired=True,
            reason="",
            evidence=evidence,
            matched_claim=matched,
            matching_reason=reason,
            extra={"fired_count": str(self.fired_count), "total": str(self.total)},
        )


@dataclass
class OracleEngine:
    """Evaluates every applicable oracle against a run."""

    oracles: dict[OracleType, Oracle] = field(
        default_factory=lambda: dict(DEFAULT_ORACLES)
    )

    def applicable(self, plan: Plan) -> list[OracleType]:
        """The oracles that will be evaluated for this plan."""
        types: list[OracleType] = []
        for expect in plan.expect_steps:
            if expect.oracle not in types:
                types.append(expect.oracle)
        for always in ALWAYS_ON:
            if always not in types:
                types.append(always)
        return types

    def evaluate(
        self,
        run: RunResult,
        plan: Plan,
        claim: Claim,
        *,
        comparison_run: RunResult | None = None,
        canary_secret: str = "",
        property_result: RunResult | None = None,
    ) -> tuple[OracleOutcome, ...]:
        """Evaluate the plan's oracles over every repetition of the run."""
        expects = plan.expect_steps
        primary_expect = expects[0] if expects else ExpectStep()
        types = self.applicable(plan)

        outcomes = list(
            self._evaluate_run(
                run, types, primary_expect, expects, claim, comparison_run,
                canary_secret=canary_secret, property_result=property_result,
            )
        )

        if comparison_run is not None:
            primary_fired = any(o.fired and o.matched for o in outcomes)
            # The comparison run is evaluated with the same oracles, so
            # "did not reproduce at the comparison ref" means what it says.
            comparison_outcomes = self._evaluate_run(
                comparison_run, types, primary_expect, expects, claim, comparison_run
            )
            comparison_fired = any(o.fired and o.matched for o in comparison_outcomes)
            differential = self.oracles[OracleType.DIFFERENTIAL]
            context = OracleContext(
                claim=claim,
                expect=primary_expect,
                comparison_run=comparison_run,
                canary_secret=canary_secret,
                extra={
                    "primary_fired": "1" if primary_fired else "0",
                    "comparison_fired": "1" if comparison_fired else "0",
                },
            )
            result = differential.evaluate(comparison_run, context)
            outcomes.append(
                OracleOutcome(
                    oracle=OracleType.DIFFERENTIAL,
                    results=(result,),
                    fired_count=1 if result.fired else 0,
                    total=1,
                    flaky=False,
                )
            )

        return tuple(outcomes)

    def _evaluate_run(
        self,
        run: RunResult,
        types: list[OracleType],
        primary_expect: ExpectStep,
        expects: tuple[ExpectStep, ...],
        claim: Claim,
        comparison_run: RunResult | None,
        *,
        canary_secret: str = "",
        property_result: RunResult | None = None,
    ) -> list[OracleOutcome]:
        """Evaluate every applicable oracle over every repetition of a run."""
        repetitions = run.runs or (CommandResult(cmd="(no run)"),)
        outcomes: list[OracleOutcome] = []

        for oracle_type in types:
            if oracle_type is OracleType.DIFFERENTIAL:
                # The differential oracle needs both runs, so it is
                # evaluated once at the end, not per repetition.
                continue
            oracle = self.oracles.get(oracle_type)
            if oracle is None:
                continue
            expect = self._expect_for(oracle_type, primary_expect, expects)
            context = OracleContext(
                claim=claim,
                expect=expect,
                comparison_run=comparison_run,
                canary_secret=canary_secret,
                property_result=property_result if oracle_type is OracleType.PROPERTY else None,
            )
            results: list[OracleResult] = []
            for index, command in enumerate(repetitions):
                single = RunResult(
                    status=run.status,
                    ref=run.ref,
                    runs=(command,),
                    oracles=(),
                    resource=run.resource,
                    filesystem_changes=run.filesystem_changes,
                    blocked_network=run.blocked_network,
                    sandbox_profile=run.sandbox_profile,
                    image_digest=run.image_digest,
                )
                result = oracle.evaluate(single, context)
                results.append(result.model_copy(update={"run_index": index}))
            fired_count = sum(1 for r in results if r.fired)
            outcomes.append(
                OracleOutcome(
                    oracle=oracle_type,
                    results=tuple(results),
                    fired_count=fired_count,
                    total=len(results),
                    flaky=0 < fired_count < len(results),
                )
            )
        return outcomes

    @staticmethod
    def _expect_for(
        oracle_type: OracleType,
        primary: ExpectStep,
        expects: tuple[ExpectStep, ...],
    ) -> ExpectStep:
        for expect in expects:
            if expect.oracle is oracle_type:
                return expect
        return primary
