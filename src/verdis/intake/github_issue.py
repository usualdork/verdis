"""GitHub issue intake for issues carrying a security label (FR-1.1)."""

from __future__ import annotations

import os
from typing import Any

import httpx

from ..schemas.common import ReportSource
from ..schemas.report import Target
from ..storage.evidence import EvidenceStore, build_report
from .base import IntakeOutcome
from .github import DEFAULT_API, GitHubError

__all__ = ["GitHubIssueIntake"]


class GitHubIssueIntake:
    """Reads issues labelled as security reports."""

    name = "github_issue"
    source = ReportSource.GITHUB_ISSUE

    def __init__(self, store: EvidenceStore, *, api_url: str = DEFAULT_API) -> None:
        self.store = store
        self.api_url = api_url.rstrip("/")

    def list_issues(
        self,
        *,
        owner: str,
        repo_name: str,
        label: str = "security",
        token: str = "",
        per_page: int = 100,
        client: httpx.Client | None = None,
    ) -> list[dict[str, Any]]:
        token = token or os.environ.get("GITHUB_TOKEN", "")
        headers = {"Accept": "application/vnd.github+json"}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        owned = client or httpx.Client(base_url=self.api_url, timeout=30.0, headers=headers)
        try:
            response = owned.get(
                f"/repos/{owner}/{repo_name}/issues",
                params={"labels": label, "per_page": per_page, "state": "all"},
            )
            if response.status_code >= 400:
                raise GitHubError(
                    f"GitHub returned {response.status_code}: {response.text[:200]}"
                )
            payload = response.json()
        finally:
            if client is None:
                owned.close()
        if not isinstance(payload, list):
            return []
        return [item for item in payload if isinstance(item, dict) and "pull_request" not in item]

    def normalize(self, payload: dict[str, Any], *, repo: str, ref: str = "") -> IntakeOutcome:
        body = str(payload.get("body") or "")
        subject = str(payload.get("title") or "")
        reporter = str(payload.get("user", {}).get("login") or "")
        labels: tuple[str, ...] = ()
        for label in payload.get("labels", []) or []:
            if isinstance(label, dict):
                name = str(label.get("name", "")).strip()
                if name:
                    labels = (*labels, name)
            elif isinstance(label, str) and label.strip():
                labels = (*labels, label.strip())
        target = Target(repo=repo, ref=ref)
        report = build_report(
            body=body,
            source=self.source,
            reporter=reporter,
            subject=subject,
            target=target,
            labels=labels,
            metadata={"github_number": str(payload.get("number", ""))},
        )
        self.store.ensure_report(report.id)
        body_path, stored = self.store.store_original(report.id, body, subject=subject)
        report = report.model_copy(update={"attachments": stored})
        return IntakeOutcome(report=report, attachments=stored, body_path=body_path)

    def fetch(
        self,
        *,
        owner: str,
        repo_name: str,
        repo: str = "",
        label: str = "security",
        token: str = "",
        ref: str = "",
        client: httpx.Client | None = None,
    ) -> list[IntakeOutcome]:
        outcomes: list[IntakeOutcome] = []
        for payload in self.list_issues(
            owner=owner, repo_name=repo_name, label=label, token=token, client=client
        ):
            outcomes.append(self.normalize(payload, repo=repo or f"{owner}/{repo_name}", ref=ref))
        return outcomes
