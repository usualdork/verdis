"""SARIF emitter, so verdicts can be shown in code scanning tools (PRD 10.1)."""

from __future__ import annotations

import json

from ..schemas.common import Verdict
from ..schemas.verdict import VerdictResult

__all__ = ["render_sarif", "sarif_document"]

_SARIF_VERSION = "2.1.0"
_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"

_LEVELS = {
    Verdict.REPRODUCED: "error",
    Verdict.OUT_OF_SCOPE: "note",
    Verdict.DUPLICATE: "note",
    Verdict.NOT_REPRODUCED: "note",
    Verdict.INCONCLUSIVE: "note",
    Verdict.NEEDS_INFO: "note",
    Verdict.UNSAFE_ATTACHMENT: "warning",
}


def sarif_document(verdict: VerdictResult) -> dict[str, object]:
    """Build a SARIF document describing the verdict."""
    rules: list[dict[str, object]] = []
    results: list[dict[str, object]] = []

    rule_id = f"verdis/{str(verdict.verdict).lower()}"
    rules.append(
        {
            "id": rule_id,
            "name": str(verdict.verdict),
            "shortDescription": {"text": verdict.why or str(verdict.verdict)},
            "fullDescription": {
                "text": "\n".join(
                    [verdict.why]
                    + [f"Not established: {item}" for item in verdict.not_established]
                )
            },
            "defaultConfiguration": {"level": _LEVELS.get(verdict.verdict, "note")},
            "properties": {"tags": ["security", "triage", "verdis"]},
        }
    )

    for point in verdict.evidence:
        results.append(
            {
                "ruleId": rule_id,
                "level": _LEVELS.get(verdict.verdict, "note"),
                "message": {"text": point.summary},
                "locations": [],
                "partialFingerprints": {"verdisPoint": point.summary[:64]},
            }
        )

    return {
        "$schema": _SCHEMA,
        "version": _SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Verdis",
                        "informationUri": "https://github.com/usualdork/verdis",
                        "rules": rules,
                    }
                },
                "results": results,
                "invocations": [
                    {
                        "executionSuccessful": verdict.verdict is not Verdict.INCONCLUSIVE,
                        "properties": {
                            "reportId": verdict.report_id,
                            "targetRef": verdict.target_ref,
                        },
                    }
                ],
            }
        ],
    }


def render_sarif(verdict: VerdictResult) -> str:
    """The verdict as SARIF JSON text."""
    return json.dumps(sarif_document(verdict), indent=2, sort_keys=True)
