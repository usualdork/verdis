#!/usr/bin/env python3
"""The Verdis GitHub Action entry point.

The action triages a report and, depending on the mode, does nothing
(shadow), posts a comment (comment) or applies a label (label). It never
closes a report, never labels one invalid and never bans anybody.
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
from pathlib import Path

import httpx

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "src"))

from verdis.config import Config  # noqa: E402
from verdis.emit.card import render_card  # noqa: E402
from verdis.emit.json_verdict import render_json  # noqa: E402
from verdis.pipeline.orchestrator import Orchestrator  # noqa: E402
from verdis.schemas.common import Verdict  # noqa: E402
from verdis.storage.db import Store  # noqa: E402
from verdis.storage.evidence import EvidenceStore  # noqa: E402

OUTPUT_FILE = Path(os.environ.get("GITHUB_OUTPUT", "/dev/stdout"))


def _set_output(name: str, value: str) -> None:
    with OUTPUT_FILE.open("a", encoding="utf-8") as handle:
        handle.write(f"{name}={value}\n")


def _github_token() -> str:
    return os.environ.get("GITHUB_TOKEN", "")


def _post_comment(body: str) -> None:
    """Post a comment on the issue that triggered the workflow."""
    token = _github_token()
    if not token:
        print("no GITHUB_TOKEN; not commenting")
        return
    payload = {
        "body": body,
        "verdis": "This comment was produced by an automated triage run. "
        "A human maintainer makes every final decision.",
    }
    event_path = os.environ.get("GITHUB_EVENT_PATH")
    if not event_path or not Path(event_path).is_file():
        print("no GITHUB_EVENT_PATH; not commenting")
        return
    event = json.loads(Path(event_path).read_text(encoding="utf-8"))
    issue = event.get("issue", {})
    number = issue.get("number")
    repository = event.get("repository", {}).get("full_name")
    if not number or not repository:
        print("the event carries no issue; not commenting")
        return
    url = f"https://api.github.com/repos/{repository}/issues/{number}/comments"
    try:
        response = httpx.post(
            url,
            headers={
                "Authorization": f"Bearer {token}",
                "Accept": "application/vnd.github+json",
            },
            json=payload,
            timeout=60,
        )
    except httpx.HTTPError as exc:
        print(f"could not post the comment: {exc}")
        return
    if response.status_code >= 300:
        print(f"could not post the comment: {response.status_code} {response.text[:200]}")


def _apply_label(label: str) -> None:
    """Apply a label to the issue that triggered the workflow."""
    token = _github_token()
    if not token:
        print("no GITHUB_TOKEN; not labelling")
        return
    event_path = os.environ.get("GITHUB_EVENT_PATH")
    if not event_path or not Path(event_path).is_file():
        return
    event = json.loads(Path(event_path).read_text(encoding="utf-8"))
    issue = event.get("issue", {})
    number = issue.get("number")
    repository = event.get("repository", {}).get("full_name")
    if not number or not repository:
        return
    url = f"https://api.github.com/repos/{repository}/issues/{number}/labels"
    try:
        response = httpx.post(
            url,
            headers={
                "Authorization": f"Bearer {token}",
                "Accept": "application/vnd.github+json",
            },
            json={"labels": [label]},
            timeout=60,
        )
    except httpx.HTTPError as exc:
        print(f"could not apply the label: {exc}")
        return
    if response.status_code >= 300:
        print(
            f"could not apply the label: {response.status_code} {response.text[:200]}"
        )


def main() -> int:
    """Run the action."""
    mode = os.environ.get("INPUT_MODE", "shadow").strip().lower()
    sandbox = os.environ.get("INPUT_SANDBOX", "default").strip().lower()
    provider = os.environ.get("INPUT_MODEL_PROVIDER", "none").strip().lower()
    budget = int(os.environ.get("INPUT_BUDGET_TOKENS", "20000") or 20000)
    label = os.environ.get("INPUT_LABEL", "verdis:triage")
    report_path = (
        os.environ.get("INPUT_REPORT_PATH", "").strip()
        or os.environ.get("VERDIS_REPORT", "").strip()
        or "report.md"
    )

    config = Config(
        mode=mode if mode in {"shadow", "comment", "label"} else "shadow",
        sandbox=sandbox if sandbox in {"default", "hardened", "local"} else "default",
        post_comment=mode == "comment",
        apply_labels=mode == "label",
    )
    config.llm.provider = provider
    config.llm.budget_tokens = budget

    workspace = Path(os.environ.get("GITHUB_WORKSPACE", "."))
    store = Store(workspace / ".verdis" / "store")
    evidence = EvidenceStore(workspace / ".verdis" / "evidence")

    # The scratch directory has to be somewhere the runtime can see, and
    # somewhere the project is not: the build stages a copy of the
    # project, and a work directory inside the project would be copied
    # into itself.
    work_dir = os.environ.get("VERDIS_WORK_DIR", "").strip() or str(
        Path(tempfile.gettempdir()) / "verdis-action-work"
    )
    Path(work_dir).mkdir(parents=True, exist_ok=True)
    config.work_dir = work_dir

    from verdis.intake.file import FileIntake

    report_file = Path(report_path)
    if not report_file.is_absolute():
        report_file = workspace / report_file
    if not report_file.is_file():
        print(f"no report at {report_file}")
        _set_output("verdict", "NEEDS_INFO")
        return 0

    outcome = FileIntake(evidence).fetch(report_file, repo=str(workspace))
    orchestrator = Orchestrator(
        config=config, store=store, evidence=evidence, backend=None
    )
    print(f"sandbox backend: {orchestrator.backend.name}")
    result = orchestrator.triage(outcome.report, repo_path=workspace)

    verdict = result.verdict
    _set_output("verdict", str(verdict.verdict))
    _set_output("tier", str(verdict.tier) if verdict.tier else "")
    _set_output("bundle-path", result.bundle_path)

    print(render_card(verdict, bundle_path=result.bundle_path).rstrip())
    print()
    print(render_json(verdict).rstrip())

    if mode == "comment":
        _post_comment(render_card(verdict, bundle_path=result.bundle_path))
    elif mode == "label":
        _apply_label(label)

    # The only opt-in that sends a reply without a human reading it, and
    # only for the verdict that asks for more information (PRD 8.5).
    if config.auto_reply_needs_info and verdict.verdict == Verdict.NEEDS_INFO:
        _post_comment(result.reply)

    # The action never fails the workflow on a non-definitive verdict: an
    # inconclusive run is information, not a build failure.
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
