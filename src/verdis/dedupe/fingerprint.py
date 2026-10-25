"""Fingerprints and similarity for duplicate detection (FR-4.1).

Fingerprints are deterministic and content-addressed. Similarity is
computed locally with no network access and no external model, so the
no-LLM mode still deduplicates.
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass, field

from ..oracles.frames import extract_frame_symbols
from ..schemas.common import (
    normalize_cwe,
    normalize_identifier,
    normalize_text,
    sha256_bytes,
    sha256_text,
)

__all__ = [
    "DedupeFingerprint",
    "cosine_similarity",
    "extract_stack_signature",
    "hashed_embedding",
    "jaccard",
    "normalize_poc_bytes",
    "token_set",
]

_TOKEN_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]+|\d+")
_STOPWORDS = frozenset(
    ["a", "an", "the", "and", "or", "but", "if", "then", "when", "while", "of", "to", "in", "on", "for", "with", "without", "from", "by", "as", "is", "are", "was", "were", "be", "been", "being", "this", "that", "these", "those", "it", "its", "it's", "we", "our", "us", "you", "your", "they", "their", "he", "she", "his", "her", "at", "into", "over", "under", "again", "further", "once", "here", "there", "all", "any", "both", "each", "few", "more", "most", "other", "some", "such", "no", "nor", "not", "only", "own", "same", "so", "than", "too", "very", "can", "will", "just", "should", "now", "report", "bug", "vulnerability", "issue", "poc", "proof", "concept", "reproduce", "steps", "version", "affected"]
)


def token_set(text: str) -> frozenset[str]:
    """Content tokens of a text, with stopwords removed."""
    tokens = {
        token.lower()
        for token in _TOKEN_RE.findall(text or "")
        if len(token) > 2 and token.lower() not in _STOPWORDS
    }
    return frozenset(tokens)


def jaccard(left: frozenset[str], right: frozenset[str]) -> float:
    """Jaccard similarity of two token sets."""
    if not left and not right:
        return 1.0
    if not left or not right:
        return 0.0
    intersection = len(left & right)
    union = len(left | right)
    return intersection / union if union else 0.0


def hashed_embedding(text: str, dims: int = 256) -> tuple[float, ...]:
    """A deterministic hashed bag-of-words embedding.

    No model, no network, no randomness: the same text always produces the
    same vector, on every machine.
    """
    vector = [0.0] * dims
    for token in token_set(text):
        digest = sha256_text(token)
        index = int(digest[:8], 16) % dims
        sign = 1.0 if int(digest[8:10], 16) % 2 == 0 else -1.0
        vector[index] += sign
    norm = math.sqrt(sum(value * value for value in vector))
    if norm == 0:
        return tuple(vector)
    return tuple(value / norm for value in vector)


def cosine_similarity(left: tuple[float, ...], right: tuple[float, ...]) -> float:
    """Cosine similarity of two equal-length vectors."""
    if not left or not right or len(left) != len(right):
        return 0.0
    dot = sum(a * b for a, b in zip(left, right, strict=True))
    norm_left = math.sqrt(sum(a * a for a in left))
    norm_right = math.sqrt(sum(b * b for b in right))
    if norm_left == 0 or norm_right == 0:
        return 0.0
    return max(0.0, min(1.0, dot / (norm_left * norm_right)))


def extract_stack_signature(output: str, limit: int = 6) -> str:
    """A stable signature of a crash or sanitizer stack.

    Symbol names are kept; addresses and line numbers are dropped, because
    they change between builds of the same code.
    """
    symbols = list(extract_frame_symbols(output or "", limit=limit))
    if not symbols:
        for pattern in (
            r"AddressSanitizer:\s*([\w-]+)",
            r"UndefinedBehaviorSanitizer:\s*([\w -]+)",
            r"runtime error:\s*([^\n]{0,60})",
        ):
            found = re.search(pattern, output or "")
            if found is not None:
                symbols.append(found.group(1).strip())
                break
    if not symbols:
        return ""
    return "|".join(symbols)


def normalize_poc_bytes(data: bytes) -> bytes:
    """Normalise PoC bytes before hashing.

    Trailing whitespace and NUL padding are removed so that the same
    logical file hashes the same way, while the content still matters.
    """
    return data.rstrip(b"\x00").rstrip()


@dataclass(frozen=True)
class DedupeFingerprint:
    """The fingerprint of one report (FR-4.1)."""

    report_id: str
    class_component: str = ""
    stack_signature: str = ""
    poc_hash: str = ""
    text_digest: str = ""
    embedding: tuple[float, ...] = field(default=())
    vuln_class: str = ""
    component: str = ""

    @classmethod
    def build(
        cls,
        *,
        report_id: str,
        vuln_class: str = "",
        component: str = "",
        body: str = "",
        poc_bytes: bytes | None = None,
        stack_output: str = "",
    ) -> DedupeFingerprint:
        class_component = ""
        if vuln_class or component:
            class_component = sha256_text(
                f"{normalize_cwe(vuln_class)}::{normalize_identifier(component)}"
            )
        stack = extract_stack_signature(stack_output)
        poc_hash = (
            sha256_bytes(normalize_poc_bytes(poc_bytes)) if poc_bytes is not None else ""
        )
        text_digest = sha256_text(normalize_text(body))
        return cls(
            report_id=report_id,
            class_component=class_component,
            stack_signature=stack,
            poc_hash=poc_hash,
            text_digest=text_digest,
            embedding=hashed_embedding(body),
            vuln_class=normalize_cwe(vuln_class),
            component=normalize_identifier(component),
        )

    def to_row(self) -> dict[str, str]:
        return {
            "report_id": self.report_id,
            "class_component": self.class_component,
            "stack_signature": self.stack_signature,
            "poc_hash": self.poc_hash,
            "text_digest": self.text_digest,
        }
