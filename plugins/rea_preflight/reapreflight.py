"""REA preflight plugin: inspect a native binary read-only with REA.

The plugin is an optional addition to the built-in static analysis. It
uses the `REA <https://github.com/hermes-agent/rea>`_ reverse-engineering
tools over MCP to look at a native binary, an Android package or an
Electron app.

**REA is not a sandbox.** The plugin therefore runs inside the same
sandbox as everything else, and the binary it inspects is a file that has
already been quarantined by preflight. The plugin never executes the
target.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

from verdis.schemas.preflight import PreflightFinding, RiskLevel

__all__ = ["ReaPreflight", "ReaUnavailable", "main"]


class ReaUnavailable(RuntimeError):
    """Raised when REA is not installed or not configured."""


@dataclass
class ReaPreflight:
    """Inspect a binary with REA, read-only, inside the sandbox."""

    binary: str = "rea"
    timeout: int = 300

    def available(self) -> bool:
        """True when the REA binary is on PATH and we are sandboxed.

        REA is not a sandbox: it runs the code it inspects. The plugin
        therefore refuses to run unless it has been told it is inside the
        sandbox, which is where the tool always puts it.
        """
        if os.environ.get("VERDIS_SANDBOXED", "") not in {"1", "true", "yes"}:
            return False
        return shutil.which(self.binary) is not None

    def describe(self, path: Path) -> dict[str, object]:
        """Return a structured description of a binary."""
        if not self.available():
            raise ReaUnavailable(
                f"{self.binary} is not available inside the sandbox; the REA plugin is "
                "optional and the built-in analysis still runs without it. REA is not "
                "a sandbox, so it must never run on the host."
            )
        if not path.is_file():
            raise ReaUnavailable(f"{path} does not exist")

        result = subprocess.run(
            [self.binary, "describe", str(path), "--json"],
            capture_output=True,
            text=True,
            timeout=self.timeout,
            check=False,
        )
        if result.returncode != 0:
            raise ReaUnavailable(
                f"REA could not describe {path.name}: {result.stderr.strip()[:200]}"
            )
        try:
            return json.loads(result.stdout)
        except json.JSONDecodeError as exc:
            raise ReaUnavailable(f"REA returned output that is not JSON: {exc}") from exc

    def findings(self, path: Path) -> list[PreflightFinding]:
        """Turn a REA description into preflight findings."""
        description = self.describe(path)
        findings: list[PreflightFinding] = []

        imports = description.get("imports", []) or []
        network = sorted(
            {
                str(name)
                for name in imports
                if str(name)
                in {
                    "socket", "connect", "connect_ex", "sendto", "recvfrom",
                    "getaddrinfo", "gethostbyname", "SSL_connect",
                }
            }
        )
        if network:
            findings.append(
                PreflightFinding(
                    code="rea-network-imports",
                    severity=RiskLevel.MEDIUM,
                    message="REA found network imports in the binary",
                    evidence=", ".join(network[:8]),
                    weight=20,
                )
            )

        strings = description.get("strings", []) or []
        credential_hits = [
            value
            for value in strings
            if any(marker in str(value) for marker in ("/etc/shadow", ".ssh/", ".aws/"))
        ]
        if credential_hits:
            findings.append(
                PreflightFinding(
                    code="rea-credential-strings",
                    severity=RiskLevel.HIGH,
                    message="REA found strings that reference credential locations",
                    evidence=str(credential_hits[0])[:120],
                    weight=35,
                )
            )

        if description.get("packed"):
            findings.append(
                PreflightFinding(
                    code="rea-packed",
                    severity=RiskLevel.MEDIUM,
                    message="REA reports that the binary is packed or obfuscated",
                    weight=20,
                )
            )

        return findings


def main(argv: list[str] | None = None) -> int:
    """Inspect a binary and print the findings as JSON."""
    import sys

    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv:
        print("usage: rea_preflight <binary>", file=sys.stderr)
        return 2
    plugin = ReaPreflight()
    try:
        findings = plugin.findings(Path(argv[0]))
    except ReaUnavailable as exc:
        print(json.dumps({"error": str(exc)}))
        return 1
    print(json.dumps([f.model_dump(mode="json") for f in findings], indent=2))
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
