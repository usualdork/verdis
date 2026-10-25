"""Output oracle: a regex or an exit code, when the claim states an observable.

Used when the report says "the command prints ``SUCCESS``" or "exits with
code 3". It is the weakest oracle and is only used when the claim names an
output-level observable.
"""

from __future__ import annotations

import re

from ..schemas.common import OracleType
from ..schemas.run import OracleResult, RunResult
from .base import Oracle, OracleContext

__all__ = ["OutputOracle"]


class OutputOracle(Oracle):
    """Fires when the output matches the stated expectation."""

    oracle_type = OracleType.OUTPUT

    def evaluate(self, run: RunResult, context: OracleContext) -> OracleResult:
        expect = context.expect
        evidence: list[str] = []

        if expect.regex:
            try:
                pattern = re.compile(expect.regex, re.MULTILINE)
            except re.error as exc:
                return OracleResult(
                    oracle=OracleType.OUTPUT,
                    fired=False,
                    reason=f"the expected regex does not compile: {exc}",
                )
            for index, command in enumerate(run.runs):
                for line in command.combined.splitlines():
                    if pattern.search(line):
                        evidence.append(f"run {index + 1}: output matched {expect.regex!r}")
                        evidence.append(f"run {index + 1}: {line.strip()[:200]}")
                        break
                if evidence:
                    break

        if expect.exit_code is not None and not evidence:
            for index, command in enumerate(run.runs):
                if command.exit_code == expect.exit_code:
                    evidence.append(
                        f"run {index + 1} exited with the expected code {expect.exit_code}"
                    )
                    break

        if not evidence and expect.signature:
            # The report named a string rather than a pattern: look for
            # it as it was written.
            needle = expect.signature.strip()
            for index, command in enumerate(run.runs):
                for line in command.combined.splitlines():
                    if needle in line:
                        evidence.append(
                            f"run {index + 1}: the output contained {needle!r}"
                        )
                        evidence.append(f"run {index + 1}: {line.strip()[:200]}")
                        break
                if evidence:
                    break

        if not evidence:
            return OracleResult(
                oracle=OracleType.OUTPUT,
                fired=False,
                reason="the output did not match the stated expectation",
            )
        return self._result(
            OracleType.OUTPUT,
            fired=True,
            reason="the output matched the stated expectation",
            evidence=tuple(evidence),
            context=context,
        )
