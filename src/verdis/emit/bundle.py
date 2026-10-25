"""Evidence bundle assembly (PRD 8.3).

The bundle is the currency of the tool: a maintainer can take it, run
``./rerun.sh`` on another machine and get the same verdict.
"""

from __future__ import annotations

import json
import platform
import shutil
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ..schemas.bundle import BundleManifest, EnvironmentInfo, ModelInfo
from ..schemas.common import to_jsonable
from ..schemas.plan import Plan
from ..schemas.policy import PolicyMatch
from ..schemas.run import BuildResult, RunResult
from ..schemas.verdict import VerdictResult
from ..storage.evidence import EvidenceStore
from .card import render_card
from .json_verdict import render_json
from .reply import render_reply

__all__ = ["RERUN_SCRIPT", "BundleBuilder"]

RERUN_SCRIPT = """\
#!/bin/sh
# Reproduce the run behind this verdict.
#
# This script re-runs the same plan against the same target and writes a
# fresh evidence bundle next to the one it lives in. It needs the same
# prerequisites the original run needed: a container runtime, and the
# target repository at the recorded ref.
#
#   VERDIS_REPO     the target repository (default: the current directory)
#   VERDIS_REF      the ref to run against (default: the recorded one)
#   VERDIS_SANDBOX  the sandbox backend (default: the recorded one)
#   VERDIS_BUNDLE   where to write the fresh bundle
set -eu

BUNDLE_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
REPORT="$BUNDLE_DIR/original/report.md"
VERDIS_REPO=${VERDIS_REPO:-.}
VERDIS_REF=$(sed -n 's/.*"target_ref": "\\([^"]*\\)".*/\\1/p' "$BUNDLE_DIR/verdict.json" | head -n 1)
VERDIS_BUNDLE=${VERDIS_BUNDLE:-$BUNDLE_DIR/rerun-output}

if [ ! -f "$REPORT" ]; then
    echo "the original report is missing from this bundle: $REPORT" >&2
    exit 2
fi

echo "Re-running $REPORT against $VERDIS_REPO at ${VERDIS_REF:-HEAD}"
echo "Writing the fresh bundle to $VERDIS_BUNDLE"

exec verdis triage "$REPORT" \\
  --repo "$VERDIS_REPO" \\
  --ref "${VERDIS_REF:-HEAD}" \\
  --bundle-out "$VERDIS_BUNDLE" \\
  --sandbox "${VERDIS_SANDBOX:-default}" \\
  "$@"
"""


@dataclass
class BundleBuilder:
    """Writes the evidence bundle for one report."""

    store: EvidenceStore

    def build(
        self,
        *,
        report_id: str,
        verdict: VerdictResult,
        claim: Any = None,
        plan: Plan | None = None,
        policy_matches: tuple[PolicyMatch, ...] = (),
        build_result: BuildResult | None = None,
        run_result: RunResult | None = None,
        comparison_run: RunResult | None = None,
        original_body: str = "",
        reporter: str = "",
        model: ModelInfo | None = None,
        environment: EnvironmentInfo | None = None,
        extra: dict[str, Any] | None = None,
    ) -> BundleManifest:
        """Write the bundle and return its manifest."""
        files: dict[str, str | bytes] = {}

        files["original/report.md"] = original_body or ""
        if claim is not None:
            files["claim.json"] = json.dumps(to_jsonable(claim), indent=2, sort_keys=True)
        if plan is not None:
            files["plan.json"] = json.dumps(to_jsonable(plan), indent=2, sort_keys=True)
            files["plan.txt"] = plan.to_text() + "\n"
        if policy_matches:
            files["policy_matches.json"] = json.dumps(
                to_jsonable(policy_matches), indent=2, sort_keys=True
            )
        if build_result is not None:
            files["build.json"] = json.dumps(to_jsonable(build_result), indent=2, sort_keys=True)
            files["build.log"] = "\n".join(build_result.logs) + "\n"
        if run_result is not None:
            files["run.json"] = json.dumps(to_jsonable(run_result), indent=2, sort_keys=True)
            files["run.log"] = run_result.combined_output + "\n"
            files["oracles.json"] = json.dumps(
                to_jsonable(list(run_result.oracles)), indent=2, sort_keys=True
            )
            if run_result.filesystem_changes:
                files["fs_changes.json"] = json.dumps(
                    list(run_result.filesystem_changes), indent=2
                )
            if run_result.blocked_network:
                files["blocked_network.json"] = json.dumps(
                    list(run_result.blocked_network), indent=2
                )
        if comparison_run is not None:
            files["comparison_run.json"] = json.dumps(
                to_jsonable(comparison_run), indent=2, sort_keys=True
            )
        if extra:
            files["extra.json"] = json.dumps(to_jsonable(extra), indent=2, sort_keys=True)

        files["verdict.json"] = render_json(verdict)
        files["verdict.md"] = render_card(verdict)
        files["draft_reply.md"] = render_reply(verdict, reporter=reporter)
        files["rerun.sh"] = RERUN_SCRIPT
        files["environment.json"] = json.dumps(
            to_jsonable(environment or self.default_environment()),
            indent=2,
            sort_keys=True,
        )

        manifest = self.store.write_bundle(
            report_id,
            files,
            manifest_extra={
                "verdict": str(verdict.verdict),
                "target": {
                    "repo": getattr(getattr(verdict, "target", None), "repo", ""),
                    "ref": verdict.target_ref,
                },
                "reporter": reporter,
                "original_sha256": _sha256_text(original_body),
            },
            environment=environment or self.default_environment(),
            model=model or ModelInfo(),
        )
        rerun = self.store.bundle_dir(report_id) / "rerun.sh"
        if rerun.exists():
            rerun.chmod(0o755)
        return manifest

    @staticmethod
    def default_environment() -> EnvironmentInfo:
        """Record what we know about the environment."""
        return EnvironmentInfo(
            sandbox_profile="default",
            sandbox_backend="",
            kernel=platform.release(),
            os=f"{platform.system()} {platform.release()}",
            tool_versions={
                "python": platform.python_version(),
                "verdis": _tool_version(),
            },
        )

    def copy_original(self, report_id: str, source_path: str) -> None:
        """Copy the stored original into the bundle for convenience."""
        if not source_path or not Path(source_path).is_file():
            return
        target = self.store.bundle_dir(report_id) / "original" / "report.md"
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source_path, target)


def _sha256_text(text: str) -> str:
    from ..schemas.common import sha256_text

    return sha256_text(text or "")


def _tool_version() -> str:
    from .. import __version__

    return __version__


_ = sys
