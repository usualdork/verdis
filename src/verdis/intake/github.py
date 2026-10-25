"""GitHub private vulnerability report intake (FR-1.1).

FR-1.6 asks the Phase 0 spike to verify which GitHub events and APIs
expose private reports to automation. That surface has changed over time,
so the endpoint is configurable and the default is the organisation-level
listing endpoint. When no event is available, scheduled polling is the
fallback, which is what this adapter does.
"""

from __future__ import annotations

import os
from typing import Any

import httpx

from ..schemas.common import ReportSource
from ..schemas.report import Target
from ..storage.evidence import EvidenceStore, build_report
from .base import IntakeOutcome
from .limits import ConcurrencyLimiter

__all__ = ["GitHubError", "GitHubPrivateReportIntake"]

DEFAULT_API = "https://api.github.com"


class GitHubError(RuntimeError):
    """Raised when the GitHub API cannot be used."""


class GitHubPrivateReportIntake:
    """Polls private vulnerability reports and normalises them."""

    name = "github"
    source = ReportSource.GITHUB_PRIVATE_REPORT

    def __init__(
        self,
        store: EvidenceStore,
        *,
        api_url: str = DEFAULT_API,
        limiter: ConcurrencyLimiter | None = None,
    ) -> None:
        self.store = store
        self.api_url = api_url.rstrip("/")
        self.limiter = limiter or ConcurrencyLimiter()

    # -- API ------------------------------------------------------------

    def _client(self, token: str) -> httpx.Client:
        if not token:
            raise GitHubError("a GitHub token is required for this intake")
        return httpx.Client(
            base_url=self.api_url,
            timeout=30.0,
            headers={
                "Authorization": f"Bearer {token}",
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
            },
        )

    def list_reports(
        self,
        *,
        owner: str,
        token: str = "",
        per_page: int = 100,
        client: httpx.Client | None = None,
    ) -> list[dict[str, Any]]:
        """List private vulnerability reports visible to the token."""
        owned = client or self._client(token)
        try:
            response = owned.get(
                f"/orgs/{owner}/private-vulnerability-reports",
                params={"per_page": per_page},
            )
            if response.status_code == 404:
                # Older or smaller installations expose the list per repository.
                response = owned.get(
                    f"/repos/{owner}/private-vulnerability-reports",
                    params={"per_page": per_page},
                )
            if response.status_code >= 400:
                raise GitHubError(
                    f"GitHub returned {response.status_code}: {response.text[:200]}"
                )
            payload = response.json()
        finally:
            if client is None:
                owned.close()
        if isinstance(payload, dict):
            payload = payload.get("items", [])
        return [item for item in payload if isinstance(item, dict)]

    # -- normalisation --------------------------------------------------

    def normalize(
        self,
        payload: dict[str, Any],
        *,
        repo: str,
        ref: str = "",
    ) -> IntakeOutcome:
        """Turn one API payload into a normalized report."""
        body = str(payload.get("body") or payload.get("description") or "")
        subject = str(payload.get("title") or payload.get("summary") or "")
        reporter = str(
            payload.get("reporter")
            or payload.get("user", {}).get("login")
            or payload.get("credit", {}).get("user", {}).get("login")
            or ""
        )
        attachments: list[tuple[str, bytes]] = []
        for item in payload.get("attachments", []) or []:
            if isinstance(item, dict) and item.get("filename") and item.get("content"):
                import base64

                try:
                    attachments.append(
                        (str(item["filename"]), base64.b64decode(str(item["content"])))
                    )
                except (ValueError, TypeError):
                    continue
        target = Target(
            repo=repo,
            ref=ref or str(payload.get("vulnerable_version") or ""),
            component=str(payload.get("component") or ""),
        )
        report = build_report(
            body=body,
            source=self.source,
            reporter=reporter,
            subject=subject,
            target=target,
            metadata={
                "github_number": str(payload.get("number", "")),
                "github_state": str(payload.get("state", "")),
            },
        )
        self.store.ensure_report(report.id)
        body_path, stored = self.store.store_original(
            report.id, body, attachments=tuple(attachments), subject=subject
        )
        report = report.model_copy(update={"attachments": stored})
        return IntakeOutcome(report=report, attachments=stored, body_path=body_path)

    def fetch(
        self,
        *,
        owner: str,
        repo: str,
        token: str = "",
        ref: str = "",
        client: httpx.Client | None = None,
    ) -> list[IntakeOutcome]:
        """Fetch and normalise every visible private report."""
        token = token or os.environ.get("GITHUB_TOKEN", "")
        outcomes: list[IntakeOutcome] = []
        with self.limiter.slot(self.source.value):
            for payload in self.list_reports(owner=owner, token=token, client=client):
                outcomes.append(self.normalize(payload, repo=repo, ref=ref))
        return outcomes
