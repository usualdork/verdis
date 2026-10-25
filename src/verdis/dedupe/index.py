"""Duplicate detection (FR-4).

Two passes, as the PRD requires: a cheap text-based pass before the run and
a strong stack-signature pass after it. Matches are always suggestions; the
tool never merges reports on its own (FR-4.5).
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from ..schemas.common import normalize_cwe
from ..schemas.verdict import DedupeMatch
from ..storage.db import DedupeEntry, Store
from .fingerprint import (
    DedupeFingerprint,
    cosine_similarity,
    hashed_embedding,
    jaccard,
    token_set,
)

__all__ = ["AdvisoryCandidate", "AdvisorySource", "DedupeEngine", "LocalAdvisorySource"]


@dataclass(frozen=True)
class AdvisoryCandidate:
    """A published advisory that a report might duplicate."""

    identifier: str
    title: str = ""
    url: str = ""
    text: str = ""
    component: str = ""
    vuln_class: str = ""


class AdvisorySource(Protocol):
    """A source of published advisories."""

    def lookup(self, repo: str = "", version: str = "") -> list[AdvisoryCandidate]:
        ...


class LocalAdvisorySource:
    """Advisories from a local JSON file, for offline use."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)

    def lookup(self, repo: str = "", version: str = "") -> list[AdvisoryCandidate]:
        if not self.path.is_file():
            return []
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return []
        out: list[AdvisoryCandidate] = []
        for item in data if isinstance(data, list) else []:
            if not isinstance(item, dict):
                continue
            identifier = str(item.get("id", "")).strip()
            if not identifier:
                continue
            out.append(
                AdvisoryCandidate(
                    identifier=identifier,
                    title=str(item.get("title", "")),
                    url=str(item.get("url", "")),
                    text=str(item.get("description", "")),
                    component=str(item.get("component", "")),
                    vuln_class=str(item.get("class", "")),
                )
            )
        return out


@dataclass
class DedupeEngine:
    """Compares a report against the local store and optional advisories."""

    store: Store
    threshold: float = 0.82
    advisory_source: AdvisorySource | None = None

    # -- indexing -------------------------------------------------------

    def index(
        self,
        *,
        report_id: str,
        fingerprint: DedupeFingerprint,
        body: str,
        title: str = "",
        subject: str = "",
    ) -> None:
        """Store a fingerprint so later reports can be compared with it."""
        self.store.upsert_dedupe(
            DedupeEntry(
                report_id=report_id,
                class_component=fingerprint.class_component,
                stack_signature=fingerprint.stack_signature,
                poc_hash=fingerprint.poc_hash,
                text_digest=fingerprint.text_digest,
                title=title or subject,
                body_text=body,
                embedding=json.dumps(list(fingerprint.embedding)),
            )
        )

    # -- searching ------------------------------------------------------

    def search(
        self,
        fingerprint: DedupeFingerprint,
        body: str,
        *,
        exclude_report_id: str = "",
        mode: str = "post",
        repo: str = "",
        version: str = "",
    ) -> list[DedupeMatch]:
        """Return candidate duplicates, strongest first.

        ``mode="pre"`` uses only cheap text signals; ``mode="post"`` also
        uses the stack signature and the PoC hash.
        """
        candidates: list[tuple[float, list[str], DedupeMatch]] = []

        for entry in self.store.all_dedupe_entries():
            if entry.report_id == exclude_report_id:
                continue
            score, reasons = self._score(entry, fingerprint, body, mode=mode)
            if score <= 0:
                continue
            candidates.append(
                (
                    score,
                    reasons,
                    DedupeMatch(
                        candidate_id=entry.report_id,
                        similarity=round(score, 4),
                        reasons=tuple(reasons),
                        source="local",
                        title=entry.title,
                    ),
                )
            )

        if self.advisory_source is not None:
            for advisory in self.advisory_source.lookup(repo=repo, version=version):
                score, reasons = self._score_advisory(advisory, fingerprint, body, mode)
                if score <= 0:
                    continue
                candidates.append(
                    (
                        score,
                        reasons,
                        DedupeMatch(
                            candidate_id=advisory.identifier,
                            similarity=round(score, 4),
                            reasons=tuple(reasons),
                            source="advisory",
                            title=advisory.title,
                            url=advisory.url,
                        ),
                    )
                )

        candidates.sort(key=lambda item: item[0], reverse=True)
        return [match for _score, _reasons, match in candidates]

    # -- scoring --------------------------------------------------------

    def _score(
        self,
        entry: DedupeEntry,
        fingerprint: DedupeFingerprint,
        body: str,
        *,
        mode: str,
    ) -> tuple[float, list[str]]:
        reasons: list[str] = []
        signals = 0

        class_match = bool(
            entry.class_component
            and fingerprint.class_component
            and entry.class_component == fingerprint.class_component
        )
        if class_match:
            signals += 1
            reasons.append("same vulnerability class and component")

        text_score = 0.0
        if entry.body_text:
            text_score = cosine_similarity(
                fingerprint.embedding, hashed_embedding(entry.body_text)
            )
            overlap = jaccard(token_set(body), token_set(entry.body_text))
            text_score = max(text_score, overlap)
            if text_score >= 0.6:
                signals += 1
                reasons.append(f"similar report text ({text_score:.2f})")

        if mode == "pre":
            score = (0.4 if class_match else 0.0) + 0.6 * text_score
            return (min(score, 1.0), reasons) if score > 0 else (0.0, reasons)

        stack_match = bool(
            entry.stack_signature
            and fingerprint.stack_signature
            and entry.stack_signature == fingerprint.stack_signature
        )
        if stack_match:
            signals += 1
            reasons.append("same crash or sanitizer stack signature")

        poc_match = bool(
            entry.poc_hash and fingerprint.poc_hash and entry.poc_hash == fingerprint.poc_hash
        )
        if poc_match:
            signals += 1
            reasons.append("same PoC bytes")

        score = max(
            0.9 * (1.0 if stack_match else 0.0),
            0.85 * (1.0 if poc_match else 0.0),
            # A shared class and component plus a very similar text is a
            # strong signal; text on its own never reaches the threshold.
            (
                0.4 + 0.5 * text_score
                if class_match and text_score >= 0.75
                else 0.0
            ),
            0.6 * text_score,
        )
        if signals >= 2 and (stack_match or poc_match or class_match):
            score += 0.1
        return (min(score, 1.0), reasons) if score > 0 else (0.0, reasons)

    def _score_advisory(
        self,
        advisory: AdvisoryCandidate,
        fingerprint: DedupeFingerprint,
        body: str,
        mode: str,
    ) -> tuple[float, list[str]]:
        reasons: list[str] = []
        text = f"{advisory.title} {advisory.text}"
        text_score = cosine_similarity(fingerprint.embedding, hashed_embedding(text))
        class_match = bool(
            advisory.vuln_class
            and fingerprint.vuln_class
            and normalize_cwe(advisory.vuln_class) == fingerprint.vuln_class
        )
        component_match = bool(
            advisory.component
            and fingerprint.component
            and advisory.component.lower() in fingerprint.component
        )
        if class_match:
            reasons.append("same vulnerability class")
        if component_match:
            reasons.append(f"same component ({advisory.component})")
        if text_score >= 0.6:
            reasons.append(f"similar text to the advisory ({text_score:.2f})")
        score = 0.6 * text_score
        if class_match:
            score += 0.25
        if component_match:
            score += 0.15
        return (min(score, 1.0), reasons) if score > 0 else (0.0, reasons)
