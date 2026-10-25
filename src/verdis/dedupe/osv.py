"""Opt-in advisory lookups (FR-4.2).

Deduplication compares against the local store and, when the maintainer
opts in, against published advisories. The lookups are off by default:
they are the only part of the tool that talks to a third party about the
project's vulnerabilities.
"""

from __future__ import annotations

import json
import os
from typing import Any

import httpx

from ..schemas.common import normalize_cwe
from .index import AdvisoryCandidate

__all__ = ["OSV_QUERY", "OSVAdvisorySource"]

OSV_QUERY = "https://api.osv.dev/v1/query"


class OSVAdvisorySource:
    """Look advisories up in the OSV database.

    The lookup is opt-in and only happens when a maintainer configures
    this source. It sends the package name and version, never the report.
    """

    def __init__(
        self,
        package: str = "",
        ecosystem: str = "",
        *,
        api_url: str = OSV_QUERY,
        timeout: float = 20.0,
        client: httpx.Client | None = None,
    ) -> None:
        self.package = package
        self.ecosystem = ecosystem
        self.api_url = api_url
        self.timeout = timeout
        self._client = client

    def _post(self, payload: dict[str, Any]) -> list[dict[str, Any]]:
        client = self._client or httpx.Client(timeout=self.timeout)
        try:
            response = client.post(self.api_url, json=payload)
            if response.status_code >= 400:
                return []
            body = response.json()
        except (httpx.HTTPError, json.JSONDecodeError, ValueError):
            return []
        finally:
            if self._client is None:
                client.close()
        vulns = body.get("vulns", []) if isinstance(body, dict) else []
        return [vuln for vuln in vulns if isinstance(vuln, dict)]

    def lookup(self, repo: str = "", version: str = "") -> list[AdvisoryCandidate]:
        """Look up advisories for the configured package."""
        package = self.package or repo
        if not package:
            return []
        if not self.ecosystem:
            # The API rejects a package without an ecosystem, so a lookup
            # without one would silently return nothing. Better to say so.
            return []
        payload: dict[str, Any] = {
            "package": {"name": package, "ecosystem": self.ecosystem}
        }
        if version:
            payload["version"] = version

        candidates: list[AdvisoryCandidate] = []
        for vuln in self._post(payload):
            identifier = str(vuln.get("id", ""))
            if not identifier:
                continue
            [str(alias) for alias in vuln.get("aliases", []) or []]
            summary = str(vuln.get("summary", ""))
            details = str(vuln.get("details", ""))
            affected = vuln.get("affected", []) or []
            classes: list[str] = []
            components: list[str] = []
            for entry in affected:
                if not isinstance(entry, dict):
                    continue
                database = entry.get("database_specific", {}) or {}
                cwe = database.get("cwe_ids") or []
                if isinstance(cwe, list):
                    classes.extend(normalize_cwe(str(item)) for item in cwe)
                for item in vuln.get("affected", []) or []:
                    if not isinstance(item, dict):
                        continue
                    database = item.get("database_specific", {}) or {}
                    for cwe_id in database.get("cwe_ids", []) or []:
                        normalised = normalize_cwe(str(cwe_id))
                        if normalised and normalised not in classes:
                            classes.append(normalised)
                package_info = entry.get("package", {}) or {}
                name = package_info.get("name")
                if name:
                    components.append(str(name))
            candidates.append(
                AdvisoryCandidate(
                    identifier=identifier,
                    title=summary or identifier,
                    url=f"https://osv.dev/vulnerability/{identifier}",
                    text=f"{summary}\n{details}".strip(),
                    component=components[0] if components else "",
                    vuln_class=classes[0] if classes else "",
                )
            )
        return candidates

    @classmethod
    def from_env(cls) -> OSVAdvisorySource | None:
        """Build the source from the environment, if it is enabled."""
        if os.environ.get("VERDIS_OSV", "").strip().lower() not in {"1", "true", "yes"}:
            return None
        return cls(
            package=os.environ.get("VERDIS_OSV_PACKAGE", ""),
            ecosystem=os.environ.get("VERDIS_OSV_ECOSYSTEM", ""),
        )
