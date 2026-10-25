"""Tests for the VerdisBench corpus and the runner (PRD 13.1, 13.3).

The benchmark is only worth what its cases are worth, so the cases
themselves are tested: every one has a manifest, a report and a target,
and the runner produces the metrics the PRD asks for.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture(scope="module")
def built_cases(tmp_path_factory) -> Path:
    """Build the benchmark corpus in a temporary directory."""
    sys.path.insert(0, str(REPO_ROOT / "benchmark"))
    from corpus import build as builder

    target = tmp_path_factory.mktemp("cases")
    builder.build(target)
    return target


def _cases(root: Path) -> list[Path]:
    return sorted(path.parent for path in root.rglob("case.json"))


class TestTheCorpus:
    def test_it_builds_every_case(self, built_cases: Path) -> None:
        cases = _cases(built_cases)
        assert cases
        names = {json.loads((case / "case.json").read_text())["name"] for case in cases}
        assert any(name.startswith("heap-overflow-memcpy/positive/") for name in names)

    def test_each_case_has_a_manifest(self, built_cases: Path) -> None:
        for case in _cases(built_cases):
            manifest = case / "case.json"
            assert manifest.is_file()
            data = json.loads(manifest.read_text(encoding="utf-8"))
            assert data["kind"] in {
                "positive",
                "negative",
                "style",
                "adversarial",
                "messy",
                "policy",
                "limitation",
            }

    def test_each_case_states_what_it_expects(self, built_cases: Path) -> None:
        for case in _cases(built_cases):
            data = json.loads((case / "case.json").read_text(encoding="utf-8"))
            assert data["expected"] or data["forbidden"], data["name"]

    def test_each_case_has_a_report(self, built_cases: Path) -> None:
        for case in _cases(built_cases):
            assert (case / "report.md").is_file()

    def test_each_case_has_a_target(self, built_cases: Path) -> None:
        for case in _cases(built_cases):
            assert (case / "target").is_dir()

    def test_the_provenance_of_every_case_is_stated(self, built_cases: Path) -> None:
        for case in _cases(built_cases):
            data = json.loads((case / "case.json").read_text(encoding="utf-8"))
            if "program" in data:
                assert data["provenance"] in {"reduction", "upstream"}

    def test_the_corpus_has_negatives_enough_to_measure_a_rate(
        self, built_cases: Path
    ) -> None:
        kinds = [
            json.loads((case / "case.json").read_text())["kind"]
            for case in _cases(built_cases)
        ]
        assert kinds.count("negative") >= 100

    def test_the_adversarial_cases_have_a_twin(self, built_cases: Path) -> None:
        for case in _cases(built_cases):
            data = json.loads((case / "case.json").read_text(encoding="utf-8"))
            if data["kind"] == "adversarial" and "probe" not in data["name"]:
                assert data.get("twin"), data["name"]


class TestTheRunner:
    @pytest.fixture(scope="class")
    def results(self, built_cases: Path, tmp_path_factory) -> dict:
        """Run a small slice of the corpus."""
        results_path = tmp_path_factory.mktemp("results") / "results.json"
        subprocess.run(
            [
                sys.executable,
                str(REPO_ROOT / "benchmark" / "run.py"),
                "--cases",
                str(built_cases),
                "--results",
                str(results_path),
                "--workdir",
                str(tmp_path_factory.mktemp("work")),
                "--only",
                "heap-overflow-memcpy",
            ],
            capture_output=True,
            text=True,
            timeout=1800,
            check=True,
        )
        return json.loads(results_path.read_text(encoding="utf-8"))

    def test_the_positive_case_reproduces(self, results: dict) -> None:
        by_name = {case["name"]: case for case in results["cases"]}
        assert by_name["heap-overflow-memcpy/positive/clear"]["verdict"] == "REPRODUCED"

    def test_the_benign_input_does_not_reproduce(self, results: dict) -> None:
        by_name = {case["name"]: case for case in results["cases"]}
        assert (
            by_name["heap-overflow-memcpy/negative/benign-00"]["verdict"]
            == "NOT_REPRODUCED"
        )

    def test_the_vague_report_asks_for_more_information(self, results: dict) -> None:
        by_name = {case["name"]: case for case in results["cases"]}
        assert by_name["heap-overflow-memcpy/style/vague"]["verdict"] == "NEEDS_INFO"

    def test_the_metrics_are_reported(self, results: dict) -> None:
        summary = results["summary"]
        assert "false_reproduced" in summary
        assert "per_case_interval" in summary["false_reproduced"]
        assert "clustered_interval" in summary["false_reproduced"]
        assert "rule_of_three_upper" in summary["false_reproduced"]
        assert "confusion_matrix" in summary
        assert "twins" in summary

    def test_the_thresholds_are_checked(self, results: dict) -> None:
        thresholds = results["summary"]["thresholds"]
        assert thresholds
        assert all("threshold" in check for check in thresholds)
        assert all("passed" in check for check in thresholds)
