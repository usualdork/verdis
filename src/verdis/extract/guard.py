"""Prompt-injection heuristics for report text (PRD 11.4 item 1).

The tool never obeys report text. This module exists to *flag* instruction-
like content so the pipeline can refuse to plan from it and so the maintainer
can see that a report tried.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

__all__ = ["InjectionFinding", "analyze_text", "summarize"]


@dataclass(frozen=True)
class InjectionFinding:
    """One instruction-like construct found in untrusted text."""

    kind: str
    quote: str
    offset: int
    severity: str = "medium"

    def to_dict(self) -> dict[str, object]:
        return {
            "kind": self.kind,
            "quote": self.quote,
            "offset": self.offset,
            "severity": self.severity,
        }


_PATTERNS: tuple[tuple[str, re.Pattern[str], str], ...] = (
    (
        "instruction_override",
        re.compile(
            r"(?i)\b(ignore|disregard|forget|override|bypass|skip)\b[^.\n]{0,40}\b"
            r"(previous|prior|above|earlier|all)\b[^.\n]{0,40}\b"
            r"(instruction|prompt|rule|direction)s?\b"
        ),
        "high",
    ),
    (
        "instruction_substitution",
        re.compile(
            r"(?i)\b(ignore|disregard|forget|override|bypass|skip)\b[^.\n]{0,60}\b"
            r"(above|previous|prior|earlier|instead)\b"
        ),
        "medium",
    ),
    (
        "role_reassignment",
        re.compile(
            r"(?i)\b(you are now|act as|pretend to be|new instructions?|system prompt|"
            r"developer mode|dan mode)\b"
        ),
        "high",
    ),
    (
        "policy_leak",
        re.compile(r"(?i)\b(reveal|print|output|show me)\b[^.\n]{0,40}\b"
                  r"(your |the )?(system prompt|instructions|policy|rules)\b"),
        "high",
    ),
    (
        "exfiltration",
        re.compile(
            r"(?i)\b(send|post|upload|exfiltrat\w*|curl|wget)\b[^.\n]{0,60}"
            r"(attacker\.com|evil\.com|https?://[^\s]+|/etc/passwd|~/\.ssh|"
            r"AWS_SECRET|api[_-]?key)"
        ),
        "high",
    ),
    (
        "tool_invocation",
        re.compile(r"(?i)\b(call|invoke|execute|run)\b[^.\n]{0,30}\b(function|tool|command)\b"),
        "medium",
    ),
    (
        "verdict_pressure",
        re.compile(
            r"(?i)\b(mark|classify|label|set)\b[^.\n]{0,30}\b"
            r"(as\s+)?(critical|high|reproduced|valid|duplicate|spam|invalid)\b"
        ),
        "medium",
    ),
)


def analyze_text(text: str) -> list[InjectionFinding]:
    """Return every instruction-like construct found in ``text``."""
    findings: list[InjectionFinding] = []
    for kind, pattern, severity in _PATTERNS:
        for match in pattern.finditer(text):
            findings.append(
                InjectionFinding(
                    kind=kind,
                    quote=match.group(0)[:200],
                    offset=match.start(),
                    severity=severity,
                )
            )
    findings.sort(key=lambda f: (f.offset, f.kind))
    return findings


def summarize(text: str) -> dict[str, object]:
    """A compact, storable summary of injection findings."""
    findings = analyze_text(text)
    return {
        "count": len(findings),
        "kinds": sorted({f.kind for f in findings}),
        "max_severity": (
            "high" if any(f.severity == "high" for f in findings)
            else ("medium" if findings else "none")
        ),
        "findings": [f.to_dict() for f in findings],
    }
