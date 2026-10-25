"""Policy loading and derivation (FR-3.1, FR-3.2).

``.verdis/policy.yml`` is the authoritative source. When it is absent,
hints are derived from ``SECURITY.md`` and ``THREAT_MODEL.md`` and are
labelled "derived, unverified" until a maintainer confirms them.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import yaml

from ..schemas.common import sha256_text
from ..schemas.policy import (
    EvidenceRequirements,
    Policy,
    PolicyClause,
    PolicyOrigin,
)

__all__ = [
    "PolicyLoadError",
    "derive_policy_from_docs",
    "load_policy",
    "load_policy_file",
    "matches_version",
    "policy_from_dict",
    "policy_to_dict",
]

POLICY_FILENAME = Path(".verdis/policy.yml")
SECURITY_DOCS = ("SECURITY.md", "docs/SECURITY.md", ".github/SECURITY.md")
THREAT_MODEL_DOCS = ("THREAT_MODEL.md", "docs/THREAT_MODEL.md", "SECURITY_THREAT_MODEL.md")


class PolicyLoadError(ValueError):
    """Raised when a policy file exists but cannot be understood."""


# -- version patterns ---------------------------------------------------


def _version_tuple(version: str) -> tuple[int, ...]:
    parts = re.findall(r"\d+", version)
    return tuple(int(p) for p in parts) or (0,)


def matches_version(pattern: str, version: str) -> bool:
    """Does ``version`` satisfy the support pattern ``pattern``?

    Supported forms: ``2.x``, ``2.*``, ``2.3``, ``2.3.1``, ``>=2.0``,
    ``<3.0``, ``2.0-2.5``, ``2.3.1`` (exact) and ``latest``.
    """
    pattern = (pattern or "").strip()
    version = (version or "").strip()
    if not pattern:
        return False
    if not version:
        return False
    if pattern.lower() in {"all", "*", "any", "latest", "main", "master"}:
        return True

    if "||" in pattern:
        return any(matches_version(part, version) for part in pattern.split("||"))

    for op in (">=", "<=", ">", "<", "=="):
        if pattern.startswith(op):
            bound = pattern[len(op) :].strip()
            left, right = _version_tuple(version), _version_tuple(bound)
            width = max(len(left), len(right))
            left = left + (0,) * (width - len(left))
            right = right + (0,) * (width - len(right))
            match = {
                ">=": left >= right,
                "<=": left <= right,
                ">": left > right,
                "<": left < right,
                "==": left == right,
            }[op]
            return match

    if "-" in pattern and not pattern.startswith("-"):
        low, _, high = pattern.partition("-")
        return matches_version(f">={low.strip()}", version) and matches_version(
            f"<={high.strip()}", version
        )

    if "x" in pattern.lower() or "*" in pattern:
        prefix = re.split(r"[x*]", pattern, maxsplit=1)[0].strip().rstrip(".")
        if not prefix:
            return True
        return version == prefix or version.startswith(prefix + ".") or version.startswith(prefix + "-")

    if re.fullmatch(r"\d+(\.\d+)*", pattern):
        return version == pattern or version.startswith(pattern + ".")

    return False


# -- explicit policy file ----------------------------------------------


def policy_from_dict(data: dict[str, Any], *, source_file: str = "") -> Policy:
    """Build a :class:`Policy` from a parsed YAML mapping."""
    if not isinstance(data, dict):
        raise PolicyLoadError("policy file must contain a YAML mapping")

    supported = _as_str_tuple(data.get("supported_versions", ()))
    in_scope = _as_str_tuple(data.get("in_scope", ()))
    out_of_scope = _as_str_tuple(data.get("out_of_scope", ()))

    excluded: list[PolicyClause] = []
    for index, item in enumerate(data.get("excluded_classes", ()) or ()):
        if isinstance(item, str):
            excluded.append(
                PolicyClause(
                    id=f"excluded-{index + 1}",
                    kind="excluded",
                    description=item,
                    file=source_file,
                    origin=PolicyOrigin.EXPLICIT,
                )
            )
            continue
        if not isinstance(item, dict):
            raise PolicyLoadError(f"excluded_classes[{index}] must be a mapping or string")
        clause = PolicyClause(
            id=str(item.get("id") or f"excluded-{index + 1}"),
            kind="excluded",
            description=str(item.get("description", "")),
            file=source_file,
            heading=str(item.get("heading", "")),
            quote=str(item.get("quote", "")),
            component_patterns=_as_str_tuple(item.get("components", ())),
            version_patterns=_as_str_tuple(item.get("versions", ())),
            origin=PolicyOrigin.EXPLICIT,
        )
        excluded.append(clause)

    evidence_data = data.get("evidence_requirements", {}) or {}
    if not isinstance(evidence_data, dict):
        raise PolicyLoadError("evidence_requirements must be a mapping")
    evidence = EvidenceRequirements(
        poc_required=bool(evidence_data.get("poc_required", True)),
        default_config_only=bool(evidence_data.get("default_config_only", True)),
        min_tested_version=str(evidence_data.get("min_tested_version", "") or ""),
        requires_steps=bool(evidence_data.get("requires_steps", True)),
    )

    sla_data = data.get("sla", {}) or {}
    if not isinstance(sla_data, dict):
        raise PolicyLoadError("sla must be a mapping")
    sla = {str(k): str(v) for k, v in sla_data.items()}

    return Policy(
        supported_versions=supported,
        in_scope=in_scope,
        out_of_scope=out_of_scope,
        excluded_classes=tuple(excluded),
        evidence=evidence,
        sla=sla,
        severity_rubric=str(data.get("severity_rubric", "") or ""),
        source_files=(source_file,) if source_file else (),
        derived=False,
        confirmed=True,
        notes=_as_str_tuple(data.get("notes", ())),
    )


def policy_to_dict(policy: Policy) -> dict[str, Any]:
    """Inverse of :func:`policy_from_dict`, used by ``policy init``."""
    return {
        "supported_versions": list(policy.supported_versions),
        "in_scope": list(policy.in_scope),
        "excluded_classes": [
            {
                "id": clause.id,
                "description": clause.description,
                "components": list(clause.component_patterns),
                "versions": list(clause.version_patterns),
            }
            for clause in policy.excluded_classes
        ],
        "evidence_requirements": {
            "poc_required": policy.evidence.poc_required,
            "default_config_only": policy.evidence.default_config_only,
            "min_tested_version": policy.evidence.min_tested_version,
        },
        "sla": dict(policy.sla),
    }


def _as_str_tuple(value: Any) -> tuple[str, ...]:
    if value is None:
        return ()
    if isinstance(value, str):
        return (value,)
    if isinstance(value, (list, tuple)):
        return tuple(str(item).strip() for item in value if str(item).strip())
    raise PolicyLoadError(f"expected a list of strings, got {type(value).__name__}")


def load_policy_file(path: str | Path) -> Policy:
    """Load and validate ``.verdis/policy.yml``."""
    path = Path(path)
    try:
        raw = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise PolicyLoadError(f"cannot read policy file {path}: {exc}") from exc
    try:
        data = yaml.safe_load(raw)
    except yaml.YAMLError as exc:
        raise PolicyLoadError(f"invalid YAML in {path}: {exc}") from exc
    if data is None:
        data = {}
    if not isinstance(data, dict):
        raise PolicyLoadError(f"{path} must contain a YAML mapping at the top level")
    return policy_from_dict(data, source_file=str(path))


# -- derivation from project docs --------------------------------------


_HEADING_RE = re.compile(r"^(?P<hashes>#{1,6})\s+(?P<title>.+?)\s*$")
_LIST_RE = re.compile(r"^\s*(?:[-*+]|\d+\.)\s+(?P<text>.+?)\s*$")

_VERSION_HINTS = (
    "supported version",
    "supported versions",
    "versions in scope",
    "we support",
    "maintained versions",
)
_IN_SCOPE_HINTS = ("in scope", "scope", "we accept", "vulnerabilities we accept")
_OUT_SCOPE_HINTS = (
    "out of scope",
    "not accepted",
    "we do not accept",
    "not in scope",
    "we won't accept",
    "disclosure",
)
_EVIDENCE_HINTS = ("requirements for reports", "report requirements", "what to include", "proof of concept")
_POC_HINTS = ("proof of concept", "poc", "reproduction steps", "reproduce")
_DEFAULT_CONFIG_HINTS = ("default configuration", "default config", "default settings")


def _read_sections(path: Path) -> list[tuple[str, int, int, list[str]]]:
    """Split a markdown file into ``(heading, start_line, end_line, lines)`` sections."""
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    lines = text.splitlines()
    sections: list[tuple[str, int, int, list[str]]] = []
    current_heading = ""
    current_start = 0
    current: list[str] = []
    for index, line in enumerate(lines, start=1):
        heading_match = _HEADING_RE.match(line)
        if heading_match:
            if current or current_heading:
                sections.append((current_heading, current_start, index - 1, current))
            current_heading = heading_match.group("title").strip()
            current_start = index
            current = []
        else:
            current.append(line)
    if current or current_heading:
        sections.append((current_heading, current_start, len(lines), current))
    return sections


def derive_policy_from_docs(repo_path: str | Path) -> Policy | None:
    """Derive policy hints from ``SECURITY.md`` / ``THREAT_MODEL.md``."""
    repo_path = Path(repo_path)
    supported: list[str] = []
    in_scope: list[str] = []
    out_of_scope: list[str] = []
    excluded_clauses: list[PolicyClause] = []
    poc_required = True
    default_config_only = False
    sources: list[str] = []

    candidates = [repo_path / name for name in SECURITY_DOCS + THREAT_MODEL_DOCS]
    for path in candidates:
        if not path.is_file():
            continue
        sources.append(str(path))
        for heading, start, end, lines in _read_sections(path):
            lowered_heading = heading.lower()
            bullets: list[tuple[int, str]] = []
            for line_no, line in zip(range(start + 1, end + 1), lines, strict=False):
                match = _LIST_RE.match(line)
                if match is not None:
                    bullets.append((line_no, match.group("text")))
            if any(hint in lowered_heading for hint in _VERSION_HINTS):
                for _, bullet in bullets:
                    match = re.search(r"\b(\d+(?:\.\d+)*(?:\.[xX*])?)\b", bullet)
                    if match:
                        supported.append(match.group(1))
            is_out_of_scope = any(hint in lowered_heading for hint in _OUT_SCOPE_HINTS)
            is_in_scope = (
                not is_out_of_scope
                and any(hint in lowered_heading for hint in _IN_SCOPE_HINTS)
            )
            if is_in_scope:
                for line_no, bullet in bullets:
                    in_scope.append(bullet)
                    excluded_clauses.append(
                        PolicyClause(
                            id=f"derived-in-scope-{len(in_scope)}",
                            kind="in_scope",
                            description=bullet,
                            file=str(path),
                            heading=heading,
                            line_start=line_no,
                            line_end=line_no,
                            quote=bullet,
                            origin=PolicyOrigin.UNVERIFIED,
                        )
                    )
            if is_out_of_scope:
                for line_no, bullet in bullets:
                    out_of_scope.append(bullet)
                    excluded_clauses.append(
                        PolicyClause(
                            id=f"derived-out-of-scope-{len(out_of_scope)}",
                            kind="excluded",
                            description=bullet,
                            file=str(path),
                            heading=heading,
                            line_start=line_no,
                            line_end=line_no,
                            quote=bullet,
                            origin=PolicyOrigin.UNVERIFIED,
                        )
                    )
            if any(hint in lowered_heading for hint in _EVIDENCE_HINTS):
                for line_no, bullet in bullets:
                    lowered = bullet.lower()
                    if any(hint in lowered for hint in _POC_HINTS):
                        poc_required = True
                    if any(hint in lowered for hint in _DEFAULT_CONFIG_HINTS):
                        default_config_only = True
                    excluded_clauses.append(
                        PolicyClause(
                            id=f"derived-evidence-{line_no}",
                            kind="evidence",
                            description=bullet,
                            file=str(path),
                            heading=heading,
                            line_start=line_no,
                            line_end=line_no,
                            quote=bullet,
                            requires_poc=poc_required if "poc" in lowered else None,
                            origin=PolicyOrigin.UNVERIFIED,
                        )
                    )

    if not sources:
        return None

    return Policy(
        supported_versions=tuple(dict.fromkeys(supported)),
        in_scope=tuple(dict.fromkeys(in_scope)),
        out_of_scope=tuple(dict.fromkeys(out_of_scope)),
        excluded_classes=tuple(excluded_clauses),
        evidence=EvidenceRequirements(
            poc_required=poc_required,
            default_config_only=default_config_only,
        ),
        source_files=tuple(sources),
        derived=True,
        confirmed=False,
        notes=("derived from project documentation; unverified until a maintainer confirms",),
    )


def load_policy(repo_path: str | Path) -> tuple[Policy, str]:
    """Load the policy for a repository.

    Returns ``(policy, origin)`` where origin is ``"policy.yml"`` or
    ``"derived"``.
    """
    repo_path = Path(repo_path)
    policy_path = repo_path / POLICY_FILENAME
    if policy_path.is_file():
        return load_policy_file(policy_path), "policy.yml"
    derived = derive_policy_from_docs(repo_path)
    if derived is not None:
        return derived, "derived"
    return Policy(confirmed=False, notes=("no policy found; using permissive defaults",)), "default"


def policy_fingerprint(policy: Policy) -> str:
    """Stable hash of a policy, used to invalidate cached decisions."""
    return sha256_text(policy.canonical_json())
