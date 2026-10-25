"""Statistics for the benchmark.

The number that matters is the false-REPRODUCED rate, and a rate on its
own says very little. Two things are needed to make it mean something:

**How many cases.** A rate of 0% on 10 cases is compatible with a true
rate of 26%. The rule of three says that with 0 events in *n* trials, the
95% upper bound is 3/n, so measuring a 1% rate needs a few hundred
negatives.

**How independent the cases are.** The cases are not independent: they
come from a few dozen target programs, and two cases derived from the
same program share a defect, a build and a shape. A confidence interval
that treats them as independent is too narrow. The interval here is
computed by resampling *programs*, not cases, so the clustering is in
the arithmetic.
"""

from __future__ import annotations

import math
import random
from collections import Counter, defaultdict
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from typing import Any

__all__ = [
    "Bootstrap",
    "ConfusionMatrix",
    "Rate",
    "cluster_bootstrap",
    "wilson_interval",
]


def wilson_interval(successes: int, trials: int, z: float = 1.959963984540054) -> tuple[float, float]:
    """The Wilson score interval for a binomial proportion.

    Better than the normal approximation when the count is small or the
    proportion is near zero, which is exactly the regime a
    false-positive rate lives in.
    """
    if trials <= 0:
        return (0.0, 0.0)
    proportion = successes / trials
    denominator = 1 + z * z / trials
    centre = (proportion + z * z / (2 * trials)) / denominator
    spread = (
        z
        * math.sqrt(
            proportion * (1 - proportion) / trials + z * z / (4 * trials * trials)
        )
        / denominator
    )
    return (max(0.0, centre - spread), min(1.0, centre + spread))


@dataclass
class Bootstrap:
    """A clustered bootstrap interval.

    The clusters are the units of resampling: a case is drawn by drawing
    its cluster and then taking one of the cluster's cases. That is the
    conservative choice, because the cases within a cluster are the ones
    that are correlated.
    """

    point: float
    low: float
    high: float
    clusters: int
    samples: int
    seed: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "point": round(self.point, 4),
            "low": round(self.low, 4),
            "high": round(self.high, 4),
            "clusters": self.clusters,
            "samples": self.samples,
        }


def cluster_bootstrap(
    groups: dict[str, list[bool]],
    *,
    samples: int = 2000,
    seed: int = 20260101,
    z: float = 1.959963984540054,
) -> Bootstrap:
    """A bootstrap interval for a rate, resampling the clusters.

    ``groups`` maps a cluster name to the outcomes of the cases in it.
    """
    names = sorted(groups)
    if not names:
        return Bootstrap(point=0.0, low=0.0, high=0.0, clusters=0, samples=samples)

    flat = [outcome for name in names for outcome in groups[name]]
    point = sum(flat) / len(flat) if flat else 0.0

    generator = random.Random(seed)
    rates: list[float] = []
    for _ in range(samples):
        picked: list[bool] = []
        for _ in range(len(names)):
            chosen = generator.choice(names)
            picked.extend(groups[chosen])
        if picked:
            rates.append(sum(picked) / len(picked))
    rates.sort()
    if not rates:
        return Bootstrap(point=point, low=point, high=point, clusters=len(names), samples=0)

    low = rates[int(0.025 * (len(rates) - 1))]
    high = rates[int(0.975 * (len(rates) - 1))]
    return Bootstrap(
        point=point,
        low=low,
        high=high,
        clusters=len(names),
        samples=samples,
        seed=seed,
    )


@dataclass
class Rate:
    """A rate, with the two intervals that describe it."""

    successes: int
    trials: int
    per_case: tuple[float, float] = (0.0, 0.0)
    clustered: Bootstrap | None = None

    @property
    def point(self) -> float:
        return self.successes / self.trials if self.trials else 0.0

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "successes": self.successes,
            "trials": self.trials,
            "rate": round(self.point, 4),
            "per_case_interval": [
                round(self.per_case[0], 4),
                round(self.per_case[1], 4),
            ],
        }
        if self.clustered is not None:
            payload["clustered_interval"] = self.clustered.to_dict()
        return payload


def rate_for(
    outcomes: Sequence[bool], clusters: Sequence[str]
) -> Rate:
    """A rate with a per-case interval and a clustered one."""
    successes = sum(1 for outcome in outcomes if outcome)
    trials = len(outcomes)
    grouped: dict[str, list[bool]] = defaultdict(list)
    for outcome, cluster in zip(outcomes, clusters, strict=True):
        grouped[cluster].append(outcome)
    return Rate(
        successes=successes,
        trials=trials,
        per_case=wilson_interval(successes, trials),
        clustered=cluster_bootstrap(dict(grouped)),
    )


@dataclass
class ConfusionMatrix:
    """What was expected against what was produced."""

    counts: dict[tuple[str, str], int] = field(default_factory=dict)
    correct: dict[tuple[str, str], int] = field(default_factory=dict)

    def add(self, expected: str, actual: str, *, correct: bool = True) -> None:
        key = (expected or "?", actual or "?")
        self.counts[key] = self.counts.get(key, 0) + 1
        if correct:
            self.correct[key] = self.correct.get(key, 0) + 1

    @property
    def verdicts(self) -> list[str]:
        return sorted({actual for _expected, actual in self.counts})

    def row(self, expected: str) -> dict[str, int]:
        return {
            actual: count
            for (row_expected, actual), count in sorted(self.counts.items())
            if row_expected == expected
        }

    def to_dict(self) -> dict[str, Any]:
        verdicts = self.verdicts
        return {
            "verdicts": verdicts,
            "rows": {
                expected: dict(self.row(expected).items())
                for expected in sorted({row for row, _actual in self.counts})
            },
            "correct": {
                expected: {
                    actual: count
                    for (row, actual), count in sorted(self.correct.items())
                    if row == expected
                }
                for expected in sorted({row for row, _actual in self.counts})
            },
            "totals": {
                actual: sum(
                    count for (_row, other), count in self.counts.items() if other == actual
                )
                for actual in verdicts
            },
        }

    def accuracy(self) -> float:
        """The share of cases that landed where they should.

        A case counts as correct when the runner's own predicate says
        so, not when the two labels happen to be equal: a case with no
        exact expectation is satisfied by *not* producing the forbidden
        verdict, and its row label says so.
        """
        total = sum(self.counts.values())
        if not total:
            return 0.0
        good = sum(self.correct.values())
        return good / total


def distribution(values: Iterable[str]) -> dict[str, int]:
    """How often each verdict came out."""
    return dict(sorted(Counter(values).items()))
