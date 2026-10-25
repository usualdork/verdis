"""Tests for the per-report budget and for not re-running a report."""

from __future__ import annotations

from pathlib import Path

from verdis.config import Config
from verdis.pipeline.orchestrator import Orchestrator
from verdis.sandbox.local import LocalBackend
from verdis.schemas.common import ReportSource, Verdict
from verdis.schemas.report import Report, Target
from verdis.storage.db import Store
from verdis.storage.evidence import EvidenceStore

REPORT = """\
# Heap buffer overflow in parse_header

**Version**: 2.3.1
**Class**: CWE-122

```
./build/parse_demo poc.bin
```
"""


def _report() -> Report:
    return Report(
        id="VDS-0001",
        source=ReportSource.FILE,
        body=REPORT,
        target=Target(repo=".", ref="v1"),
    )


class TestDuplicateRuns:
    def test_a_report_is_not_triaged_twice(self, tmp_path: Path) -> None:
        store = Store(tmp_path / "store")
        orchestrator = Orchestrator(
            config=Config(sandbox="local", repeats=1),
            store=store,
            evidence=EvidenceStore(tmp_path / "evidence"),
            backend=LocalBackend(),
        )
        report = _report()
        first = orchestrator.triage(report, repo_path=tmp_path, target_ref="v1")
        assert first.verdict.verdict is Verdict.INCONCLUSIVE

        second = orchestrator.triage(report, repo_path=tmp_path, target_ref="v1")
        # The stored verdict comes back without a second run.
        assert second.verdict.verdict is first.verdict.verdict
        assert any("already been triaged" in w for w in second.warnings)

    def test_a_different_ref_is_triaged_again(self, tmp_path: Path) -> None:
        store = Store(tmp_path / "store")
        orchestrator = Orchestrator(
            config=Config(sandbox="local", repeats=1),
            store=store,
            evidence=EvidenceStore(tmp_path / "evidence"),
            backend=LocalBackend(),
        )
        report = _report()
        orchestrator.triage(report, repo_path=tmp_path, target_ref="v1")
        second = orchestrator.triage(report, repo_path=tmp_path, target_ref="v2")
        assert not any("already been triaged" in w for w in second.warnings)

    def test_without_a_store_nothing_is_remembered(self, tmp_path: Path) -> None:
        orchestrator = Orchestrator(
            config=Config(sandbox="local", repeats=1),
            store=None,
            evidence=EvidenceStore(tmp_path / "evidence"),
            backend=LocalBackend(),
        )
        report = _report()
        orchestrator.triage(report, repo_path=tmp_path, target_ref="v1")
        second = orchestrator.triage(report, repo_path=tmp_path, target_ref="v1")
        assert not any("already been triaged" in w for w in second.warnings)


class TestReportBudget:
    def test_a_spent_budget_stops_the_report(self, tmp_path: Path) -> None:
        # The report used up its budget, which says nothing about the
        # claim: the verdict is INCONCLUSIVE, not an exception.
        orchestrator = Orchestrator(
            config=Config(
                sandbox="local", repeats=1, report_budget_seconds=0.0
            ),
            store=None,
            evidence=EvidenceStore(tmp_path / "evidence"),
            backend=LocalBackend(),
        )
        outcome = orchestrator.triage(_report(), repo_path=tmp_path)
        assert outcome.verdict.verdict is Verdict.INCONCLUSIVE
        assert "budget" in outcome.verdict.why
