"""Canary oracle: planted secrets and outbound-request attempts (FR-8.2).

The sandbox plants canary files, fake secrets and a local listener, so file
reads, command execution and outbound-request attempts become provable
events instead of guesses.
"""

from __future__ import annotations

from ..schemas.common import OracleType
from ..schemas.run import OracleResult, RunResult
from .base import Oracle, OracleContext

__all__ = ["CanaryOracle"]


class CanaryOracle(Oracle):
    """Fires when the PoC touched a canary or tried to reach the network."""

    oracle_type = OracleType.CANARY

    def evaluate(self, run: RunResult, context: OracleContext) -> OracleResult:
        evidence: list[str] = []

        secret = context.canary_secret.strip()
        leaked = False
        if secret:
            blob = f"{run.stdout}\n{run.stderr}"
            leaked = secret in blob
            if leaked:
                evidence.append(
                    "the fake secret planted in the sandbox appeared in the output, "
                    "so the PoC read it"
                )
            else:
                evidence.append("the fake secret planted in the sandbox was not disclosed")

        for hit in run.canary_hits:
            evidence.append(f"the sandbox recorded an outbound connection attempt to {hit}")

        for attempt in run.blocked_network:
            evidence.append(
                f"the sandbox recorded a blocked outbound network attempt ({attempt})"
            )

        if not evidence:
            return OracleResult(
                oracle=OracleType.CANARY,
                fired=False,
                reason="no canary was touched and no outbound attempt was recorded",
            )

        fired = bool(run.canary_hits) or bool(run.blocked_network) or leaked
        if not fired:
            return OracleResult(
                oracle=OracleType.CANARY,
                fired=False,
                reason="the canary was present but nothing touched it",
                evidence=tuple(evidence),
            )
        result = self._result(
            OracleType.CANARY,
            fired=True,
            reason="a canary was touched during the run",
            evidence=tuple(evidence),
            context=context,
        )
        return result.model_copy(update={"extra": {"secret_leaked": "1" if leaked else "0"}})
