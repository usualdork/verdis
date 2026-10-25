"""Impact levels, used to decide between Tier 1 and Tier 2 (PRD 8.1).

Tier 1 means the claimed *impact* was demonstrated. Tier 2 means the
behaviour was demonstrated but the impact was not proven. The mapping is
deliberately small and explicit so the rule can be documented and audited.
"""

from __future__ import annotations

import re

__all__ = ["IMPACT_LEVELS", "demonstrated_impact", "impact_level", "impact_matches"]

#: Higher is stronger.
IMPACT_LEVELS: dict[str, int] = {
    "crash": 1,
    "denial of service": 1,
    "memory corruption": 1,
    "crash or memory corruption": 1,
    "": 0,
    "code execution": 2,
    "remote code execution": 2,
    "arbitrary code execution": 2,
    "sql injection": 2,
    "command injection": 2,
    "file read": 2,
    "information disclosure": 2,
    "path traversal": 2,
    "authentication bypass": 3,
    "privilege escalation": 3,
    "arbitrary file write": 3,
    "account takeover": 3,
}

_CANONICALISE = {
    "rce": "remote code execution",
    "remote code execution": "remote code execution",
    "arbitrary code execution": "arbitrary code execution",
    "code execution": "code execution",
    "dos": "denial of service",
    "denial of service": "denial of service",
    "info leak": "information disclosure",
    "information disclosure": "information disclosure",
    "file disclosure": "information disclosure",
    "memory corruption": "memory corruption",
    "crash": "crash",
    "crash or memory corruption": "crash or memory corruption",
    "privilege escalation": "privilege escalation",
    "authentication bypass": "authentication bypass",
}


def _canon(text: str) -> str:
    lowered = " ".join((text or "").lower().split())
    if lowered in _CANONICALISE:
        return _CANONICALISE[lowered]
    for key, value in _CANONICALISE.items():
        if key in lowered:
            return value
    return lowered


def impact_level(text: str) -> int:
    """Numeric strength of an impact statement (0 when unknown)."""
    canon = _canon(text)
    if canon in IMPACT_LEVELS:
        return IMPACT_LEVELS[canon]
    best = 0
    for phrase, level in IMPACT_LEVELS.items():
        if phrase and phrase in canon:
            best = max(best, level)
    return best


def demonstrated_impact(oracle_names: set[str], *, secret_leaked: bool = False) -> str:
    """What the oracles actually demonstrated."""
    names = {n.lower() for n in oracle_names}
    if secret_leaked:
        return "information disclosure"
    if "sanitizer" in names:
        return "memory corruption"
    if "crash" in names:
        return "crash"
    if "exception" in names:
        return "crash"
    if "canary" in names:
        return "information disclosure"
    if "output" in names:
        # The report said what to look for and it appeared. That shows
        # the behaviour, not the class of impact the report claims.
        return "output-level behaviour"
    if "property" in names:
        return "a violated property"
    if "differential" in names:
        return "a difference between two revisions"
    return ""


def impact_matches(claimed: str, demonstrated: str) -> bool:
    """Is the demonstrated impact at least as strong as the claimed one?"""
    claimed_level = impact_level(claimed)
    demonstrated_level = impact_level(demonstrated)
    if claimed_level == 0:
        return True
    return demonstrated_level >= claimed_level


_CWE_IMPACT_HINTS: dict[str, str] = {
    "CWE-78": "code execution",
    "CWE-89": "sql injection",
    "CWE-22": "file read",
    "CWE-200": "information disclosure",
    "CWE-269": "privilege escalation",
    "CWE-287": "authentication bypass",
    "CWE-918": "information disclosure",
    "CWE-400": "denial of service",
    "CWE-122": "memory corruption",
    "CWE-121": "memory corruption",
    "CWE-120": "memory corruption",
    "CWE-416": "memory corruption",
    "CWE-190": "memory corruption",
    "CWE-476": "crash",
    "CWE-798": "information disclosure",
    "CWE-22 ": "file read",
}


def cwe_impact_hint(cwe: str) -> str:
    """A conservative impact hint derived from the CWE class."""
    return _CWE_IMPACT_HINTS.get((cwe or "").upper(), "")


def strongest_claim_impact(claimed: str, cwe: str) -> str:
    """The claimed impact, using the CWE only when the report is vague."""
    if claimed and impact_level(claimed) > 0:
        return claimed
    return cwe_impact_hint(cwe) or claimed


_ = re
