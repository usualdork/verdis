"""The judge: deterministic, ordered decision rules (PRD section 8.2).

The rules, in order:

1. An unsafe attachment stops the run -> ``UNSAFE_ATTACHMENT``.
2. Missing required evidence -> ``NEEDS_INFO``, quoting the project's clause.
3. A build failure, an unsupported environment, a timeout or a flaky
   outcome -> ``INCONCLUSIVE``.
4. A built and executed plan is judged by the oracles:
   an oracle fired and matched the claim -> ``REPRODUCED``;
   no oracle fired -> ``NOT_REPRODUCED``;
   an oracle fired but did not match the claim -> ``NOT_REPRODUCED`` with
   the mismatch stated.
5. Policy exclusions apply after reproduction -> ``OUT_OF_SCOPE``.
6. A duplicate above the threshold -> ``DUPLICATE``.
7. Any ambiguity falls back to ``INCONCLUSIVE``, never to ``REPRODUCED``.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ..oracles.engine import OracleOutcome
from ..schemas.claim import Claim
from ..schemas.common import OracleType, Verdict, VerdictFlag, VerdictTier
from ..schemas.plan import Plan
from ..schemas.policy import PolicyMatch, PolicyVerdict
from ..schemas.preflight import PreflightResult
from ..schemas.run import BuildResult, BuildStatus, RunResult, RunStatus
from ..schemas.verdict import DedupeMatch, EvidencePoint, VerdictResult
from .impact import demonstrated_impact, impact_matches, strongest_claim_impact

__all__ = ["RULES_DOCUMENT", "Judge", "JudgeContext"]

#: What the tool says is missing, when the project has not written a
#: clause of its own. The maintainer can replace these with their own.
_MISSING_EVIDENCE_TEXT = {
    "affected_version": "The report must say which version is affected.",
    "poc": "The report must include a proof of concept.",
    "component": "The report must say which component is affected.",
    "expected_observable": (
        "The report must say what should be observed when the bug is triggered."
    ),
    "default_configuration": "The report must affect the default configuration.",
    "tested_version": "The report must affect a version the project still tests.",
}

RULES_DOCUMENT = """\
1. UNSAFE_ATTACHMENT  - preflight blocked execution of an attachment.
2. NEEDS_INFO         - required evidence is missing (policy clause quoted).
3. DUPLICATE          - a prior report or advisory matched above threshold.
                         A duplicate is a statement about the report, not about
                         the run, so it needs no run of its own.
4. MISSING_SYMBOL     - the report names a function or file the target does
                         not have, so the claim cannot be checked at all.
5. INCONCLUSIVE       - build failure, timeout, flaky result or unsupported
                         environment.
6. REPRODUCED         - an oracle fired at the claimed ref and matched the
                         claim. A reproduced claim that policy excludes is
                         OUT_OF_SCOPE instead.
7. NOT_REPRODUCED     - the PoC ran and the claimed behaviour did not occur.
"""


@dataclass
class JudgeContext:
    """Everything the judge is allowed to look at."""

    report_id: str = ""
    target_ref: str = ""
    claim: Claim | None = None
    policy_matches: tuple[PolicyMatch, ...] = ()
    policy_missing: tuple[str, ...] = ()
    policy_exclusion: PolicyMatch | None = None
    preflight: tuple[PreflightResult, ...] = ()
    build: BuildResult | None = None
    run: RunResult | None = None
    comparison_run: RunResult | None = None
    oracles: tuple[OracleOutcome, ...] = ()
    dedupe_matches: tuple[DedupeMatch, ...] = ()
    plan: Plan | None = None
    model_name: str = ""
    duration_ms: int = 0
    notes: list[str] = field(default_factory=list)
    missing_symbol: str = ""
    """A symbol the report named that is not in the target at all."""


class Judge:
    """Turns evidence into a verdict, following the documented rules."""

    def __init__(self, *, dedupe_threshold: float = 0.82) -> None:
        self.dedupe_threshold = dedupe_threshold

    def judge(self, context: JudgeContext) -> VerdictResult:
        rules = (
            self._rule_unsafe_attachment,
            self._rule_needs_info,
            self._rule_duplicate,
            self._rule_missing_symbol,
            self._rule_inconclusive,
            self._rule_reproduce,
            self._rule_not_reproduced,
        )
        for rule in rules:
            result = rule(context)
            if result is not None:
                return result
        # Rule 7: ambiguity is never REPRODUCED.
        return self._inconclusive(  # pragma: no cover - a rule always answers
            context, "no rule produced a verdict; treated as inconclusive"
        )

    def inconclusive(
        self,
        context: JudgeContext,
        *,
        reason: str,
        next_action: str = "review the evidence bundle and adjust the setup",
        flags: tuple[VerdictFlag, ...] = (),
        evidence: tuple[EvidencePoint, ...] = (),
    ) -> VerdictResult:
        """A public INCONCLUSIVE verdict, for stages that stop the pipeline."""
        return self._inconclusive(
            context,
            reason=reason,
            next_action=next_action,
            flags=flags,
            evidence=evidence,
        )

    # -- rules ----------------------------------------------------------

    def _rule_unsafe_attachment(self, context: JudgeContext) -> VerdictResult | None:
        blocked = [p for p in context.preflight if p.blocked]
        if not blocked:
            return None
        reasons: list[str] = []
        for result in blocked:
            reasons.extend(f"{result.name}: {reason}" for reason in result.reasons)
        return VerdictResult(
            verdict=Verdict.UNSAFE_ATTACHMENT,
            report_id=context.report_id,
            target_ref=context.target_ref,
            why=(
                "attachment preflight blocked execution: "
                + "; ".join(reasons[:6])
            ),
            evidence=tuple(
                EvidencePoint(summary=reason, artifact=result.name)
                for result in blocked
                for reason in result.reasons
            ),
            policy_matches=context.policy_matches,
            next_action=(
                "review the attachment manually, then re-run with an explicit "
                "override if it is safe"
            ),
            not_established=(
                "the report was not reproduced; the PoC never ran",
                "the attachment's behaviour was not analysed beyond static inspection",
            ),
            model_name=context.model_name,
            duration_ms=context.duration_ms,
        )

    def _rule_needs_info(self, context: JudgeContext) -> VerdictResult | None:
        missing = list(context.policy_missing)
        if not missing and context.claim is not None:
            # In no-LLM mode the heuristics leave gaps in the claim, and
            # those gaps are the evidence that is missing. The PRD names
            # three: the affected version, the proof of concept and the
            # steps to reproduce.
            missing = [
                field
                for field in context.claim.missing_fields
                if field in {"affected_version", "poc"}
            ]
        if not missing:
            return None
        clause = next(
            (m for m in context.policy_matches if m.verdict is PolicyVerdict.MISSING_EVIDENCE),
            None,
        )
        quoted = clause.clause.description if clause and clause.clause else ""
        citation = clause.citation if clause else ""
        if not quoted:
            quoted = _MISSING_EVIDENCE_TEXT.get(missing[0], "")
        checklist = ", ".join(missing)
        return VerdictResult(
            verdict=Verdict.NEEDS_INFO,
            report_id=context.report_id,
            target_ref=context.target_ref,
            why=(
                f"required evidence is missing ({checklist})"
                + (f"; the project policy states: {quoted}" if quoted else "")
            ),
            evidence=tuple(
                EvidencePoint(
                    summary=(
                        f"missing: {item}"
                        + (f" — {quoted}" if quoted and item == missing[0] else "")
                    ),
                    artifact=citation,
                )
                for item in missing
            ),
            policy_matches=context.policy_matches,
            next_action="ask the reporter for the missing evidence",
            not_established=(
                "whether the report reproduces was not determined",
            ),
            model_name=context.model_name,
            duration_ms=context.duration_ms,
        )

    def _rule_inconclusive(self, context: JudgeContext) -> VerdictResult | None:
        build = context.build
        if build is not None and build.status is BuildStatus.UNSUPPORTED:
            # There is no recipe for this project: a human has to write one
            # before the report can be reproduced.
            return self._inconclusive(
                context,
                reason=(
                    "there is no build recipe for this project, so the target could "
                    "not be built"
                ),
                flags=(VerdictFlag.NEEDS_HUMAN_RECIPE,),
                next_action=(
                    "write .verdis/recipe.yml with the commands that build this "
                    "project, then re-run the report"
                ),
            )
        if build is not None and build.status in {
            BuildStatus.FAILED,
            BuildStatus.UNSUPPORTED,
        }:
            return self._inconclusive(
                context,
                reason=(
                    f"the build failed at step {build.failure_step or 'unknown'}; "
                    "the PoC never ran"
                ),
                evidence=(
                    EvidencePoint(
                        summary=build.log_excerpt[:400] or "the build produced no output",
                        artifact="build.log",
                    ),
                ),
                next_action=(
                    build.suggested_fix
                    or "add or correct a build recipe in .verdis/recipe.yml"
                ),
            )
        if build is not None and build.status is BuildStatus.SKIPPED and context.run is None:
            return self._inconclusive(
                context,
                reason="the target was not built, so nothing could be executed",
                next_action="provide a build recipe for this project",
            )

        run = context.run
        if run is None:
            return self._inconclusive(
                context,
                reason="the PoC was never executed",
                next_action="check the plan and the sandbox configuration",
            )
        if run.status is RunStatus.TIMEOUT:
            return self._inconclusive(
                context,
                reason="the run hit the time limit and was killed",
                next_action="raise the timeout in the recipe if the PoC legitimately takes longer",
            )
        if run.status is RunStatus.FAILED_TO_RUN:
            return self._inconclusive(
                context,
                reason="the PoC command could not be started inside the sandbox",
                next_action="check the command path in the plan",
            )
        if run.status is RunStatus.BLOCKED:
            return self._inconclusive(
                context,
                reason="the sandbox blocked the run",
                next_action="review the plan against the allowlist",
            )
        flaky = [o for o in context.oracles if o.flaky]
        if flaky:
            names = ", ".join(str(o.oracle) for o in flaky)
            return self._inconclusive(
                context,
                reason=(
                    f"the result was flaky ({names} fired in some repetitions but not "
                    "others), so it cannot be called reproduced or not reproduced"
                ),
                flags=(VerdictFlag.FLAKY,),
                next_action="re-run the PoC several times and check whether the report is stable",
            )
        return None

    def _rule_duplicate(self, context: JudgeContext) -> VerdictResult | None:
        matches = [
            m for m in context.dedupe_matches if m.similarity >= self.dedupe_threshold
        ]
        if not matches:
            return None
        best = max(matches, key=lambda m: m.similarity)
        reasons = "; ".join(best.reasons) or "similar fingerprints"
        return VerdictResult(
            verdict=Verdict.DUPLICATE,
            report_id=context.report_id,
            target_ref=context.target_ref,
            why=(
                f"this report matches {best.candidate_id} with similarity "
                f"{best.similarity:.2f} ({reasons})"
            ),
            evidence=tuple(
                EvidencePoint(
                    summary=f"{m.candidate_id}: similarity {m.similarity:.2f} — "
                    + ("; ".join(m.reasons) or "no stated reason"),
                    artifact=m.url,
                )
                for m in matches[:5]
            ),
            policy_matches=context.policy_matches,
            dedupe_matches=context.dedupe_matches,
            next_action=(
                "check the linked report before spending more time on this one; "
                "the match is a suggestion, not a decision"
            ),
            not_established=(
                "that the two reports describe the same issue; a human decides",
            ),
            model_name=context.model_name,
            duration_ms=context.duration_ms,
        )

    def _rule_not_reproduced(self, context: JudgeContext) -> VerdictResult | None:
        run = context.run
        if run is None:
            return None
        if any(o.fired for o in context.oracles):
            # Something fired; the reproduce rule has already spoken.
            return None
        if run.runs and all(command.exit_code == 127 for command in run.runs):
            # 127 is the shell's way of saying the command is not there.
            # The proof of concept never ran, so nothing was shown either
            # way: this is not a negative result.
            return self._inconclusive(
                context,
                reason="the PoC command was not found in the sandbox",
                next_action=(
                    "check the command in the plan: the build may not have "
                    "produced the binary the report names"
                ),
            )
        return self._not_reproduced(context)

    def _rule_missing_symbol(self, context: JudgeContext) -> VerdictResult | None:
        """The report names a symbol the target does not have.

        A report that says the defect is in ``process_template`` cannot
        be reproduced by a crash in ``parse_header``. Saying REPRODUCED
        there would be a false positive: the maintainer would be told
        their program has the bug the reporter described, and it does
        not.
        """
        if not context.missing_symbol:
            return None
        return self._inconclusive(
            context,
            reason=(
                f"the report names {context.missing_symbol!r}, which is not in the "
                "target, so the behaviour it describes could not be reproduced"
            ),
            next_action=(
                "check the report against the target: the function or file it "
                "names may be spelled differently, or the report may be about a "
                "different version"
            ),
        )

    def _rule_reproduce(self, context: JudgeContext) -> VerdictResult | None:
        run = context.run
        if run is None:
            return None
        fired = tuple(o for o in context.oracles if o.fired)
        if not fired:
            # Nothing fired: the duplicate check gets a turn before the
            # report is called not-reproduced.
            return None

        matching = tuple(o for o in fired if o.matched)
        if not matching:
            mismatch = fired[0]
            return self._not_reproduced(
                context,
                fired=bool(run.any_fired),
                extra_reason=(
                    f"an oracle fired ({mismatch.oracle}) but did not match the claim: "
                    f"{mismatch.matching_reason or 'the evidence does not line up'}"
                ),
                evidence=_evidence_points(context, fired),
            )

        claim = context.claim
        claimed_impact = (
            strongest_claim_impact(claim.impact.summary, claim.vuln_class) if claim else ""
        )
        secret_leaked = any(
            o.extra.get("secret_leaked") == "1" for o in matching
        )
        shown = demonstrated_impact({str(o.oracle) for o in matching}, secret_leaked=secret_leaked)
        tier = (
            VerdictTier.TIER_1
            if impact_matches(claimed_impact, shown)
            else VerdictTier.TIER_2
        )
        flags: list[VerdictFlag] = []
        if context.plan is not None and not context.plan.default_config:
            flags.append(VerdictFlag.NON_DEFAULT_CONFIG)
        elif context.plan is not None:
            flags.append(VerdictFlag.DEFAULT_CONFIG_ONLY)
        differential = next(
            (o for o in context.oracles if o.oracle is OracleType.DIFFERENTIAL), None
        )
        if differential is not None and differential.fired:
            flags.append(VerdictFlag.FIXED_AT_HEAD)

        why = self._reproduce_why(context, matching, tier, shown, claimed_impact)
        flags_tuple = tuple(flags)

        # Policy exclusions apply *after* reproduction (PRD 8.2): the
        # maintainer still sees that it worked, and then sees that the
        # project does not act on this class of report.
        exclusion = context.policy_exclusion
        if exclusion is not None:
            return self._out_of_scope(context, exclusion, evidence=_evidence_points(context, matching))

        return VerdictResult(
            verdict=Verdict.REPRODUCED,
            report_id=context.report_id,
            target_ref=context.target_ref,
            tier=tier,
            flags=flags_tuple,
            why=why,
            evidence=_evidence_points(context, matching),
            policy_matches=context.policy_matches,
            dedupe_matches=context.dedupe_matches,
            next_action=(
                "confirm the severity and decide on a fix"
                if tier is VerdictTier.TIER_1
                else "confirm the severity; the claimed impact was not demonstrated"
            ),
            not_established=self._not_established(context, tier),
            build=context.build,
            run=context.run,
            comparison_run=context.comparison_run,
            model_name=context.model_name,
            duration_ms=context.duration_ms,
        )

    def _out_of_scope(
        self,
        context: JudgeContext,
        exclusion: PolicyMatch,
        *,
        evidence: tuple[EvidencePoint, ...] = (),
    ) -> VerdictResult:
        clause = exclusion.clause
        quote = (clause.quote or clause.description) if clause else ""
        citation = exclusion.citation
        return VerdictResult(
            verdict=Verdict.OUT_OF_SCOPE,
            report_id=context.report_id,
            target_ref=context.target_ref,
            why=(
                "the claim reproduced but the project policy excludes it"
                + (f": {quote}" if quote else "")
            ),
            evidence=evidence
            + (
                (
                    EvidencePoint(
                        summary=f"policy clause: {quote}" if quote else "policy exclusion matched",
                        artifact=citation,
                    ),
                )
                if quote
                else ()
            ),
            policy_matches=context.policy_matches,
            dedupe_matches=context.dedupe_matches,
            next_action=(
                "reply to the reporter citing the clause; a maintainer decides whether "
                "to make an exception"
            ),
            not_established=(
                "that the behaviour is harmless; it was excluded by policy, not by "
                "evidence",
            ),
            build=context.build,
            run=context.run,
            comparison_run=context.comparison_run,
            model_name=context.model_name,
            duration_ms=context.duration_ms,
        )

    # -- helpers --------------------------------------------------------

    def _not_reproduced(
        self,
        context: JudgeContext,
        *,
        fired: bool = False,
        extra_reason: str = "",
        evidence: tuple[EvidencePoint, ...] = (),
    ) -> VerdictResult:
        run = context.run
        ran_as_intended = run.ran_as_intended if run else False
        base = (
            "the PoC ran and no oracle fired"
            if not fired
            else "the claimed behaviour was not observed"
        )
        if not ran_as_intended:
            base = (
                "the PoC did not execute as intended inside the sandbox, so the "
                "absence of a crash proves nothing"
            )
        why = base + (f"; {extra_reason}" if extra_reason else "")
        points = list(evidence)
        if not points and run is not None:
            points.append(
                EvidencePoint(
                    summary=(
                        f"the command ran {len(run.runs)} time(s) and exited with "
                        f"{run.exit_codes} without triggering any oracle"
                    ),
                    artifact="run.log",
                )
            )
        return VerdictResult(
            verdict=Verdict.NOT_REPRODUCED,
            report_id=context.report_id,
            target_ref=context.target_ref,
            why=why,
            evidence=tuple(points),
            policy_matches=context.policy_matches,
            dedupe_matches=context.dedupe_matches,
            next_action=(
                "reply with what was tried and invite the reporter to confirm the "
                "steps; a human may still want to look at this"
            ),
            not_established=(
                "that the code is not vulnerable; only that this PoC, in this "
                "environment, did not show the claimed behaviour",
            ),
            build=context.build,
            run=context.run,
            comparison_run=context.comparison_run,
            model_name=context.model_name,
            duration_ms=context.duration_ms,
        )

    def _reproduce_why(
        self,
        context: JudgeContext,
        matching: tuple[OracleOutcome, ...],
        tier: VerdictTier,
        shown: str,
        claimed: str,
    ) -> str:
        primary = matching[0]
        head = (
            f"the {primary.oracle} oracle fired and matched the claim"
        )
        if tier is VerdictTier.TIER_1:
            return f"{head}; the claimed impact ({claimed or 'unspecified'}) was demonstrated"
        return (
            f"{head}; the behaviour was demonstrated ({shown or 'behaviour only'}) "
            f"but the claimed impact ({claimed or 'unspecified'}) was not proven"
        )

    @staticmethod
    def _not_established(context: JudgeContext, tier: VerdictTier) -> tuple[str, ...]:
        items = [
            "exploitability beyond what the evidence shows",
            "behaviour on configurations other than the one tested",
        ]
        if tier is VerdictTier.TIER_2:
            items.insert(0, "that the claimed impact occurs; only the behaviour was shown")
        if context.comparison_run is None:
            items.append("that the bug is still present at a later revision")
        return tuple(items)

    def _inconclusive(
        self,
        context: JudgeContext,
        reason: str,
        *,
        evidence: tuple[EvidencePoint, ...] = (),
        next_action: str = "review the evidence bundle and adjust the setup",
        flags: tuple[VerdictFlag, ...] = (),
    ) -> VerdictResult:
        return VerdictResult(
            verdict=Verdict.INCONCLUSIVE,
            report_id=context.report_id,
            target_ref=context.target_ref,
            flags=flags,
            why=reason,
            evidence=evidence,
            policy_matches=context.policy_matches,
            next_action=next_action,
            not_established=(
            (
                "whether the report reproduces; the run was not conclusive"
                if context.run is not None
                else "whether the report reproduces; the claim could not be checked"
            ),
        ),
            build=context.build,
            run=context.run,
            model_name=context.model_name,
            duration_ms=context.duration_ms,
        )


def _evidence_points(
    context: JudgeContext, outcomes: tuple[OracleOutcome, ...]
) -> tuple[EvidencePoint, ...]:
    points: list[EvidencePoint] = []
    for outcome in outcomes:
        for line in outcome.evidence[:4]:
            points.append(
                EvidencePoint(
                    summary=line,
                    artifact="run.log",
                    detail=outcome.matching_reason,
                )
            )
    if not points and context.run is not None:
        points.append(
            EvidencePoint(
                summary="the run produced output but no oracle matched the claim",
                artifact="run.log",
            )
        )
    return tuple(points[:8])
