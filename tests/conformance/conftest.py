"""The conformance suite writes down what it found.

The benchmark has to check the acceptance threshold "zero
sandbox-conformance failures" (PRD 13.3). That threshold is about this
suite, so the suite reports its own result and the benchmark reads it.

The path comes from ``VERDIS_CONFORMANCE_REPORT``. Without it nothing
is written: the suite is still just a suite.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

_REPORT_ENV = "VERDIS_CONFORMANCE_REPORT"

_OUTCOMES = {"passed": 0, "failed": 0, "skipped": 0}


def pytest_runtest_logreport(report: pytest.TestReport) -> None:
    """Count what happened, so the summary can be written."""
    if report.when == "call":
        if report.passed:
            _OUTCOMES["passed"] += 1
        elif report.skipped:
            _OUTCOMES["skipped"] += 1
    if report.failed:
        _OUTCOMES["failed"] += 1


def pytest_sessionfinish(session: pytest.Session, exitstatus: int) -> None:
    """Write the summary, if a path was asked for."""
    path = os.environ.get(_REPORT_ENV, "")
    if not path:
        return

    summary = {
        "passed": _OUTCOMES["passed"],
        "failed": _OUTCOMES["failed"],
        "skipped": _OUTCOMES["skipped"],
        "exit_status": int(exitstatus),
        "profile": "sandbox conformance suite",
    }
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
