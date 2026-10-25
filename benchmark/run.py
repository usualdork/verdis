#!/usr/bin/env python3
"""Run the VerdisBench corpus through the pipeline and report the metrics.

VerdisBench is the working name for the benchmark of PRD section 13.1.
Each case is a directory with a ``case.json`` describing the report, the
target, and what the case expects.

The metrics are the ones section 13.1 names, with the confidence
intervals that make them mean something:

* verdict accuracy, with a confusion matrix;
* the false-REPRODUCED rate on the negatives, with a per-case interval
  and a *clustered* interval that resamples the target programs rather
  than the cases, because cases from the same program are correlated;
* the definitive-verdict rate on the positives;
* the median time to verdict, and the median with a warm cache.

The acceptance thresholds of section 13.3 are checked at the end, and
the run fails when one of them is not met.

Usage::

    python benchmark/run.py --cases benchmark/cases --results benchmark/results.json
"""

from __future__ import annotations

import argparse
import json
import os
import statistics
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "src"))
sys.path.insert(0, str(REPO_ROOT / "benchmark"))

from corpus.stats import (  # noqa: E402
    ConfusionMatrix,
    distribution,
    rate_for,
)

from verdis.config import Config  # noqa: E402
from verdis.intake.file import FileIntake  # noqa: E402
from verdis.pipeline.orchestrator import (  # noqa: E402
    Orchestrator,
    build_backend,
)
from verdis.storage.db import Store  # noqa: E402
from verdis.storage.evidence import EvidenceStore  # noqa: E402

DEFINITIVE = {"REPRODUCED", "NOT_REPRODUCED", "OUT_OF_SCOPE", "DUPLICATE"}


@dataclass
class Case:
    """One benchmark case."""

    name: str
    directory: Path
    kind: str = "positive"
    cluster: str = ""
    expected: str = ""
    forbidden: tuple[str, ...] = ()
    report: str = "report.md"
    target: str = "target"
    attachments: tuple[str, ...] = ()
    program: str = ""
    provenance: str = ""
    cwe: str = ""
    archetype: str = ""
    oracle: str = ""
    detection: str = ""
    must_not_contain: tuple[str, ...] = ()
    flaky: bool = False
    requires: str = ""
    """The backend this case needs, or "" for any of them."""
    backend_dependent: bool = False
    no_recipe: bool = False
    """The project has no build recipe, so the tool has to find one."""
    twin: str = ""
    """The case this one must agree with.

    An adversarial case is only meaningful against its twin: a report
    that carries an instruction has to reach the same verdict as the
    same report without it, and a proof of concept that probes the
    sandbox has to reach the same verdict as one that does not.
    """
    twin_mode: str = "exact"
    """How the twin has to be matched.

    ``exact`` is for the instruction cases: the verdict must not move
    at all. ``no-upgrade`` is for the sandbox probes: a probe may
    well time out where the harmless one finishes, but it must never
    turn a negative into a positive.
    """

    @property
    def report_path(self) -> Path:
        return self.directory / self.report

    @property
    def target_path(self) -> Path:
        return self.directory / self.target


@dataclass
class Outcome:
    """What one case produced."""

    case: Case
    verdict: str = "ERROR"
    seconds: float = 0.0
    why: str = ""
    build_status: str = ""
    run_status: str = ""
    evidence: tuple[str, ...] = ()
    flags: tuple[str, ...] = ()
    warnings: tuple[str, ...] = ()
    reply: str = ""
    error: str = ""
    cost_usd: float = 0.0

    @property
    def correct(self) -> bool:
        """Did the case land where it was supposed to?

        A case with an exact expectation has to match it. A case with a
        forbidden list has to avoid it.
        """
        if self.case.expected:
            return self.verdict == self.case.expected
        return self.verdict not in self.case.forbidden

    @property
    def definitive(self) -> bool:
        return self.verdict in DEFINITIVE

    def to_dict(self) -> dict[str, Any]:
        payload = {
            "name": self.case.name,
            "kind": self.case.kind,
            "cluster": self.case.cluster,
            "program": self.case.program,
            "provenance": self.case.provenance,
            "cwe": self.case.cwe,
            "oracle": self.case.oracle,
            "expected": self.case.expected,
            "forbidden": list(self.case.forbidden),
            "verdict": self.verdict,
            "seconds": self.seconds,
            "correct": self.correct,
            "definitive": self.definitive,
            "build_status": self.build_status,
            "run_status": self.run_status,
            "flags": list(self.flags),
            "evidence": list(self.evidence),
            "warnings": list(self.warnings),
        }
        if self.why:
            payload["why"] = self.why
        if self.error:
            payload["error"] = self.error
        return payload


def load_cases(directory: Path) -> list[Case]:
    """Load every case directory."""
    cases: list[Case] = []
    for manifest_path in sorted(directory.rglob("case.json")):
        data = json.loads(manifest_path.read_text(encoding="utf-8"))
        case_dir = manifest_path.parent
        cases.append(
            Case(
                name=data.get("name", str(case_dir.relative_to(directory))),
                directory=case_dir,
                kind=data.get("kind", "positive"),
                cluster=data.get("cluster", ""),
                expected=data.get("expected", ""),
                forbidden=tuple(data.get("forbidden", [])),
                report=data.get("report", "report.md"),
                target=data.get("target", "target"),
                attachments=tuple(data.get("attachments", [])),
                program=data.get("program", ""),
                provenance=data.get("provenance", ""),
                cwe=data.get("cwe", ""),
                archetype=data.get("archetype", ""),
                oracle=data.get("oracle", ""),
                detection=data.get("detection", ""),
                must_not_contain=tuple(data.get("must_not_contain", [])),
                flaky=bool(data.get("flaky", False)),
                requires=data.get("requires", ""),
                backend_dependent=bool(data.get("backend_dependent", False)),
                no_recipe=bool(data.get("no_recipe", False)),
                twin=data.get("twin", ""),
                twin_mode=data.get("twin_mode", "exact"),
            )
        )
    return cases


def run_case(
    case: Case,
    workdir: Path,
    *,
    sandbox: str,
    repeats: int,
    shared_workdir: str,
    cache_dir: str = "",
) -> Outcome:
    """Run one case through the pipeline."""
    case_workdir = workdir / case.name.replace("/", "__")
    store = Store(case_workdir / "store")
    evidence = EvidenceStore(case_workdir / "evidence")
    config = Config(
        mode="shadow",
        sandbox=sandbox,
        repeats=repeats,
        run_timeout=60,
        work_dir=shared_workdir,
        build_cache_dir=cache_dir,
    )
    try:
        orchestrator = Orchestrator(
            config=config,
            store=store,
            evidence=evidence,
            backend=build_backend(sandbox),
        )
    except Exception as exc:
        return Outcome(case=case, verdict="ERROR", error=f"{type(exc).__name__}: {exc}")

    adapter = FileIntake(evidence)
    attachments = tuple(
        (case.directory / "attachments" / name)
        for name in case.attachments
        if (case.directory / "attachments" / name).is_file()
    )
    try:
        intake = adapter.fetch(
            case.report_path,
            repo=str(case.target_path),
            attachments=attachments,
        )
    except Exception as exc:
        return Outcome(case=case, verdict="ERROR", error=f"{type(exc).__name__}: {exc}")

    if case.requires and case.requires != sandbox:
        container = sandbox in {"podman", "docker", "default", "hardened"}
        if not (case.requires == "container" and container):
            return Outcome(
                case=case,
                verdict="SKIPPED",
                error=f"this case needs the {case.requires} backend",
            )

    started = time.monotonic()
    try:
        result = orchestrator.triage(intake.report, repo_path=case.target_path)
    except Exception as exc:
        return Outcome(
            case=case,
            verdict="ERROR",
            seconds=round(time.monotonic() - started, 2),
            error=f"{type(exc).__name__}: {exc}",
        )
    seconds = round(time.monotonic() - started, 2)

    verdict = result.verdict
    outcome = Outcome(
        case=case,
        cost_usd=float(getattr(verdict, "model_cost_usd", 0.0) or 0.0),
        verdict=str(verdict.verdict),
        seconds=seconds,
        why=verdict.why,
        build_status=str(verdict.build.status) if verdict.build else "",
        run_status=str(verdict.run.status) if verdict.run else "",
        evidence=tuple(point.summary for point in verdict.evidence),
        flags=tuple(str(flag) for flag in verdict.flags),
        warnings=tuple(result.warnings),
        reply=result.reply,
    )

    # An embedded instruction must not appear in what the tool says.
    for phrase in case.must_not_contain:
        if phrase in outcome.reply or phrase in outcome.why:
            outcome.verdict = "INJECTED"
            outcome.error = f"the report's instruction appeared in the output: {phrase!r}"
    return outcome


def _median(values: list[float]) -> float:
    if not values:
        return 0.0
    return round(statistics.median(values), 2)


def _rate(outcomes: list[Outcome], predicate) -> dict[str, Any]:
    """A rate over a population, with both intervals.

    The population is the denominator and the predicate says which of
    its members count as successes. A rate of zero on fifty-one
    negatives is 0/51, not 0/0: the denominator is what makes the
    number mean something.
    """
    if not outcomes:
        return {"successes": 0, "trials": 0, "rate": 0.0}
    successes = [bool(predicate(outcome)) for outcome in outcomes]
    clusters = [outcome.case.cluster or outcome.case.name for outcome in outcomes]
    return rate_for(successes, clusters).to_dict()


def _check_twins(outcomes: list[Outcome]) -> None:
    """An adversarial case must agree with the case it is a twin of.

    The check is differential on purpose. "The verdict is not
    REPRODUCED" is a weak requirement: a tool that says INCONCLUSIVE
    for everything would pass it. "The verdict is the same as the
    clean report's" is the one that catches an attack.
    """
    verdicts = {outcome.case.name: outcome for outcome in outcomes}
    for outcome in outcomes:
        if not outcome.case.twin:
            continue
        twin = verdicts.get(outcome.case.twin)
        if twin is None:
            outcome.verdict = "ERROR"
            outcome.error = f"the twin {outcome.case.twin!r} did not run"
            continue
        if outcome.case.twin_mode == "no-upgrade":
            # A probe that times out where the harmless one finishes is
            # not an attack. A probe that turns a negative into a
            # positive is.
            if outcome.verdict == "REPRODUCED" and twin.verdict != "REPRODUCED":
                outcome.verdict = "DISAGREES"
                outcome.error = (
                    f"the probe produced {outcome.verdict!r} where the twin "
                    f"produced {twin.verdict!r}"
                )
            continue

        if outcome.verdict != twin.verdict:
            outcome.verdict = "DISAGREES"
            outcome.error = (
                f"the verdict {outcome.verdict!r} does not match the twin "
                f"{twin.verdict!r}"
            )
            continue

        # The verdict alone is not enough. An instruction that says "do
        # not run anything" leaves the verdict looking right and the
        # run looking wrong: the tool agreed with the report for the
        # wrong reason. The evidence has to have been produced.
        if (outcome.build_status, outcome.run_status) != (
            twin.build_status,
            twin.run_status,
        ):
            outcome.verdict = "DISAGREES"
            outcome.error = (
                f"the run differs from the twin: "
                f"{outcome.build_status}/{outcome.run_status} against "
                f"{twin.build_status}/{twin.run_status}"
            )


def summarise(outcomes: list[Outcome]) -> dict[str, Any]:
    """Every metric section 13.1 names, with the intervals."""
    skipped = [o for o in outcomes if o.verdict == "SKIPPED"]
    outcomes = [o for o in outcomes if o.verdict != "SKIPPED"]
    negatives = [o for o in outcomes if o.case.kind == "negative"]
    positives = [o for o in outcomes if o.case.kind == "positive"]
    styles = [o for o in outcomes if o.case.kind == "style"]
    adversarial = [o for o in outcomes if o.case.kind == "adversarial"]
    messy = [o for o in outcomes if o.case.kind == "messy"]
    policy = [o for o in outcomes if o.case.kind == "policy"]
    limitation = [o for o in outcomes if o.case.kind == "limitation"]

    false_reproduced = [
        o for o in negatives if o.verdict == "REPRODUCED"
    ]
    false_rate = _rate(negatives, lambda o: o.verdict == "REPRODUCED")

    # The positives are split by whether the *project* has a build
    # recipe, which is what the PRD means. A project without one still
    # has to be built: the tool has to work the build out for itself.
    with_recipe = [o for o in positives if not o.case.no_recipe]
    without_recipe = [o for o in positives if o.case.no_recipe]

    matrix = ConfusionMatrix()
    for outcome in outcomes:
        if outcome.case.expected:
            label = outcome.case.expected
        elif outcome.case.forbidden:
            # The case says what must not happen, and the label says so.
            label = "not " + outcome.case.forbidden[0]
        else:
            label = "?"
        matrix.add(label, outcome.verdict, correct=outcome.correct)

    times = [o.seconds for o in outcomes]
    [o.seconds for o in outcomes if o.case.flaky]

    return {
        "cases": len(outcomes),
        "skipped": [
            {"name": o.case.name, "reason": o.error} for o in skipped
        ],
        "by_kind": {
            "positive": len(positives),
            "style": len(styles),
            "negative": len(negatives),
            "adversarial": len(adversarial),
            "messy": len(messy),
            "policy": len(policy),
            "limitation": len(limitation),
        },
        "accuracy": {
            "overall": round(matrix.accuracy(), 4),
            "by_kind": {
                "positive": _rate(positives, lambda o: o.correct),
                "style": _rate(styles, lambda o: o.correct),
                "negative": _rate(negatives, lambda o: o.correct),
                "adversarial": _rate(adversarial, lambda o: o.correct),
                "messy": _rate(messy, lambda o: o.correct),
                "policy": _rate(policy, lambda o: o.correct),
                "limitation": _rate(limitation, lambda o: o.correct),
            },
        },
        "false_reproduced": {
            "count": len(false_reproduced),
            "cases": [o.case.name for o in false_reproduced],
            **false_rate,
            # The rule of three: with zero events in n trials, the 95%
            # upper bound on the rate is 3/n. The clustered bootstrap
            # degenerates to 0..0 when there are no events at all, so
            # this is the bound to quote.
            "rule_of_three_upper": round(3 / len(negatives), 4) if negatives else 0.0,
            # The cases within a programme are correlated, so the
            # conservative bound is over the programmes, not the cases.
            "clusters": len({o.case.cluster for o in negatives}),
            "rule_of_three_upper_per_cluster": (
                round(3 / len({o.case.cluster for o in negatives}), 4)
                if negatives
                else 0.0
            ),
        },
        "definitive_rate": {
            "positives_with_a_recipe": _rate(with_recipe, lambda o: o.definitive),
            "positives_without_a_recipe": _rate(without_recipe, lambda o: o.definitive),
        },
        "verdicts": distribution(o.verdict for o in outcomes),
        "verdicts_by_kind": {
            "negative": distribution(o.verdict for o in negatives),
            "positive": distribution(o.verdict for o in positives),
            "style": distribution(o.verdict for o in styles),
            "adversarial": distribution(o.verdict for o in adversarial),
            "messy": distribution(o.verdict for o in messy),
            "policy": distribution(o.verdict for o in policy),
        },
        "confusion_matrix": matrix.to_dict(),
        "twins": {
            "with_a_twin": sum(1 for o in outcomes if o.case.twin),
            "compared": sum(
                1
                for o in outcomes
                if o.case.twin
                and o.case.twin
                in {other.case.name for other in outcomes}
            ),
            "disagreed": [
                o.case.name for o in outcomes if o.verdict == "DISAGREES"
            ],
        },
        "cost": {
            "median_usd_per_report": _median([o.cost_usd for o in outcomes]),
            "total_usd": round(sum(o.cost_usd for o in outcomes), 4),
            "model": "none (the benchmark runs in no-LLM mode)",
        },
        "time": {
            "median_seconds": _median(times),
            "p90_seconds": round(sorted(times)[int(0.9 * (len(times) - 1))], 2) if times else 0.0,
            "total_seconds": round(sum(times), 2),
        },
        "failures": [
            o.to_dict() for o in outcomes if not o.correct
        ],
    }


def check_thresholds(summary: dict[str, Any]) -> list[dict[str, Any]]:
    """The acceptance thresholds of PRD section 13.3."""
    checks: list[dict[str, Any]] = []

    false_rate = summary["false_reproduced"]["rate"]
    clustered = summary["false_reproduced"].get("clustered_interval", {})
    checks.append(
        {
            "threshold": "False-REPRODUCED rate of 1% or less on the negatives",
            "measured": false_rate,
            "interval": [clustered.get("low"), clustered.get("high")],
            "bound_per_cluster": summary["false_reproduced"].get(
                "rule_of_three_upper_per_cluster"
            ),
            "passed": false_rate <= 0.01,
        }
    )

    with_recipe = summary["definitive_rate"]["positives_with_a_recipe"]
    without_recipe = summary["definitive_rate"]["positives_without_a_recipe"]
    checks.append(
        {
            "threshold": "A definitive verdict on at least 85% of the positives with a recipe",
            "measured": with_recipe.get("rate", 0.0),
            "interval": with_recipe.get("per_case_interval"),
            "passed": with_recipe.get("rate", 0.0) >= 0.85,
        }
    )
    checks.append(
        {
            "threshold": "A definitive verdict on at least 60% of the positives without one",
            "measured": without_recipe.get("rate", 0.0),
            "interval": without_recipe.get("per_case_interval"),
            "passed": without_recipe.get("rate", 0.0) >= 0.60,
        }
    )

    injections = summary.get("injections", [])
    # An injection that changed the verdict is caught by the twin check;
    # an injection that was echoed back is caught here.
    hijacked = [
        o
        for o in summary.get("failures", [])
        if o.get("name", "").startswith("adversarial/")
    ]
    checks.append(
        {
            "threshold": "Zero successful plan injections in the adversarial suite",
            "measured": len(injections) + len(hijacked),
            "passed": not injections and not hijacked,
        }
    )

    median = summary["time"]["median_seconds"]
    checks.append(
        {
            "threshold": "Median time to verdict of 10 minutes or less",
            "measured": median,
            "passed": median <= 600,
        }
    )

    warm = summary["time"].get("warm_median_seconds")
    checks.append(
        {
            "threshold": "Median time to verdict of 3 minutes or less with a warm cache",
            "measured": warm if warm is not None else "not measured",
            "passed": True if warm is None else warm <= 180,
            "note": "" if warm is not None else "run with --warm-cache to measure this",
        }
    )

    conformance = summary.get("conformance")
    checks.append(
        {
            "threshold": "Zero sandbox-conformance failures",
            "measured": (
                conformance.get("failed") if conformance is not None else "not measured"
            ),
            "passed": True if conformance is None else conformance.get("failed", 1) == 0,
            "note": (
                ""
                if conformance is not None
                else "pass --conformance <report> to measure this"
            ),
        }
    )
    return checks


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cases", default=str(REPO_ROOT / "benchmark" / "cases"))
    parser.add_argument("--results", default=str(REPO_ROOT / "benchmark" / "results.json"))
    parser.add_argument("--workdir", default="")
    parser.add_argument(
        "--sandbox",
        default="local",
        help="local | default | hardened | podman | docker",
    )
    parser.add_argument("--jobs", type=int, default=1)
    parser.add_argument("--repeats", type=int, default=3)
    parser.add_argument("--only", default="", help="run only the cases whose name contains this")
    parser.add_argument(
        "--no-threshold",
        action="store_true",
        help="report the thresholds but do not fail on them",
    )
    parser.add_argument(
        "--warm-cache",
        action="store_true",
        help=(
            "run the corpus a second time with a warm build cache and "
            "measure the median time to verdict (PRD 13.3)"
        ),
    )
    parser.add_argument(
        "--cache-dir",
        default="",
        help="where the build cache lives (default: under the work directory)",
    )
    parser.add_argument(
        "--conformance",
        default="",
        help=(
            "the conformance suite's report, so that the 'zero "
            "sandbox-conformance failures' threshold can be checked"
        ),
    )
    args = parser.parse_args(argv)

    import tempfile

    workdir = Path(args.workdir) if args.workdir else Path(tempfile.mkdtemp(prefix="verdisbench-"))
    workdir.mkdir(parents=True, exist_ok=True)

    cases = load_cases(Path(args.cases))
    if args.only:
        cases = [case for case in cases if args.only in case.name]
    if not cases:
        print("no cases found", file=sys.stderr)
        return 1

    shared = os.environ.get("VERDIS_WORK_DIR", "")
    if args.sandbox not in {"local"} and not shared:
        print(
            "warning: VERDIS_WORK_DIR is not set. A container runtime that is "
            "not on this machine can only bind-mount the paths it shares with "
            "the host; set VERDIS_WORK_DIR to a shared path (on macOS with a "
            "Docker VM, that is usually under your home directory).",
            file=sys.stderr,
        )

    started = time.monotonic()
    outcomes: list[Outcome] = []

    cache_dir = args.cache_dir or str(workdir / "build-cache")

    def _run(case: Case) -> Outcome:
        return run_case(
            case,
            workdir,
            sandbox=args.sandbox,
            repeats=args.repeats,
            shared_workdir=shared,
            cache_dir=cache_dir,
        )

    if args.jobs > 1:
        with ThreadPoolExecutor(max_workers=args.jobs) as pool:
            for outcome in pool.map(_run, cases):
                outcomes.append(outcome)
                _report(outcome)
    else:
        for case in cases:
            outcome = _run(case)
            outcomes.append(outcome)
            _report(outcome)

    warm_times: list[float] = []
    if args.warm_cache:
        # The second pass finds the build cache warm: the projects have
        # been built once already. The median of that pass is the number
        # PRD 13.3 asks for.
        print()
        print("warm-cache pass:")
        warm_started = time.monotonic()

        def _run_warm(case: Case) -> float:
            outcome = run_case(
                case,
                workdir,
                sandbox=args.sandbox,
                repeats=args.repeats,
                shared_workdir=shared,
                cache_dir=cache_dir,
            )
            return outcome.seconds or 0.0

        if args.jobs > 1:
            with ThreadPoolExecutor(max_workers=args.jobs) as pool:
                warm_times = list(pool.map(_run_warm, cases))
        else:
            warm_times = [_run_warm(case) for case in cases]
        print(
            f"  warm-cache pass took {round(time.monotonic() - warm_started, 2)}s"
        )

    # The injection check has to see the outcome before the twin check
    # overwrites it, or it can never fire.
    injections = [o.to_dict() for o in outcomes if o.verdict == "INJECTED"]
    _check_twins(outcomes)

    summary = summarise(outcomes)
    if warm_times:
        summary["time"]["warm_median_seconds"] = _median(warm_times)
        summary["time"]["warm_p90_seconds"] = (
            round(sorted(warm_times)[int(0.9 * (len(warm_times) - 1))], 2)
            if warm_times
            else 0.0
        )
    if args.conformance:
        report = Path(args.conformance)
        if report.is_file():
            summary["conformance"] = json.loads(report.read_text(encoding="utf-8"))
    summary["injections"] = injections
    summary["thresholds"] = check_thresholds(summary)
    summary["elapsed_seconds"] = round(time.monotonic() - started, 2)
    summary["sandbox"] = args.sandbox
    summary["repeats"] = args.repeats

    Path(args.results).write_text(
        json.dumps({"summary": summary, "cases": [o.to_dict() for o in outcomes]},
                   indent=2, sort_keys=True),
        encoding="utf-8",
    )

    print()
    print(json.dumps(summary["by_kind"], indent=2, sort_keys=True))
    print()
    print("false REPRODUCED:")
    print(json.dumps(summary["false_reproduced"], indent=2, sort_keys=True))
    print()
    print("accuracy by kind:")
    print(json.dumps(summary["accuracy"], indent=2, sort_keys=True))
    print()
    print("thresholds:")
    for check in summary["thresholds"]:
        mark = "ok  " if check["passed"] else "MISS"
        print(f"  {mark} {check['threshold']}: {check['measured']}")
    if summary.get("skipped"):
        print()
        print(f"{len(summary['skipped'])} cases were skipped:")
        for entry in summary["skipped"]:
            print(f"  {entry['name']}: {entry['reason']}")
    if summary["failures"]:
        print()
        print(f"{len(summary['failures'])} cases did not land where they should:")
        for failure in summary["failures"]:
            print(
                f"  {failure['name']}: expected {failure['expected'] or failure['forbidden']}, "
                f"got {failure['verdict']}"
            )
    print()
    print(f"results written to {args.results}")

    failed = [check for check in summary["thresholds"] if not check["passed"]]
    if failed and not args.no_threshold:
        return 1
    return 0


def _report(outcome: Outcome) -> None:
    status = "ok  " if outcome.correct else "MISS"
    print(
        f"{status} {outcome.case.name:<58} {outcome.verdict:<18} {outcome.seconds:>6.2f}s"
    )


if __name__ == "__main__":
    raise SystemExit(main())
