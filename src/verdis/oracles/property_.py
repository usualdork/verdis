"""Property oracle: a maintainer-supplied assertion script (FR-8.2).

The property script is run inside the same sandbox as the PoC. A non-zero
exit means the property was violated by the claimed behaviour.
"""

from __future__ import annotations

from ..schemas.common import OracleType
from ..schemas.run import OracleResult, RunResult
from .base import Oracle, OracleContext

__all__ = ["PropertyOracle"]


class PropertyOracle(Oracle):
    """Fires when the maintainer's assertion script fails."""

    oracle_type = OracleType.PROPERTY

    def evaluate(self, run: RunResult, context: OracleContext) -> OracleResult:
        result = context.property_result
        if result is None:
            return OracleResult(
                oracle=OracleType.PROPERTY,
                fired=False,
                reason="no property script was supplied or it did not run",
            )
        evidence: list[str] = []
        if result.exit_code not in (0, None):
            evidence.append(
                f"the property script exited with {result.exit_code}, so the property "
                "was violated"
            )
            if result.stderr.strip():
                evidence.append(f"property script said: {result.stderr.strip()[:200]}")
            if result.stdout.strip():
                evidence.append(f"property script said: {result.stdout.strip()[:200]}")
            return self._result(
                OracleType.PROPERTY,
                fired=True,
                reason="the property was violated",
                evidence=tuple(evidence),
                context=context,
            )
        evidence.append("the property script passed, so the property was not violated")
        return OracleResult(
            oracle=OracleType.PROPERTY,
            fired=False,
            reason="the property held",
            evidence=tuple(evidence),
        )
