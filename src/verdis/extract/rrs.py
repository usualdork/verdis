"""RRS block extraction and emission (FR-2.4, section 9.4).

The block is parsed with a YAML parser and validated against the RRS schema.
No model is involved, which is what lets the no-LLM mode work end to end.
"""

from __future__ import annotations

import re
from typing import Any

import yaml
from pydantic import ValidationError

from ..schemas.common import sha256_text
from ..schemas.rrs import RRS, RRSInput, RRSPlanStep, RRSTarget

__all__ = [
    "RRSParseError",
    "emit_rrs",
    "emit_rrs_block",
    "find_rrs_blocks",
    "parse_rrs",
    "parse_rrs_document",
]

_FENCE_RE = re.compile(
    r"^[ \t]*```[ \t]*(?P<info>[^\n`]*)\n(?P<body>.*?)^[ \t]*```[ \t]*$",
    re.MULTILINE | re.DOTALL,
)

_RRS_INFO_RE = re.compile(r"(?i)\b(rrs|yaml|yml)\b")


class RRSParseError(ValueError):
    """Raised when an RRS block is present but malformed."""


def find_rrs_blocks(text: str) -> list[tuple[str, str]]:
    """Return ``(info_string, body)`` for every fenced block in ``text``."""
    return [(m.group("info").strip(), m.group("body")) for m in _FENCE_RE.finditer(text)]


def _looks_like_an_rrs_block(body: str) -> bool:
    """Does this block claim to be an RRS block?

    A broken block that says it is one has to be reported: the reporter
    pasted it to make the report machine-readable, and silently ignoring
    it would waste their time and ours.
    """
    return bool(re.search(r"(?m)^\s*rrs\s*:", body or ""))


def _looks_like_rrs(info: str, document: Any) -> bool:
    if "rrs" in info.lower():
        return True
    return isinstance(document, dict) and "rrs" in document


def parse_rrs_document(document: Any) -> RRS:
    """Validate a parsed YAML document as an RRS block."""
    if not isinstance(document, dict):
        raise RRSParseError("RRS block must be a YAML mapping")
    version = str(document.get("rrs", document.get("version", ""))).strip()
    if not version:
        raise RRSParseError("RRS block is missing its 'rrs' version key")
    payload: dict[str, Any] = dict(document)
    payload.pop("rrs", None)
    payload["version"] = version
    payload["raw"] = document
    try:
        return RRS.model_validate(payload)
    except ValidationError as exc:  # pragma: no cover - exercised via tests
        raise RRSParseError(f"invalid RRS block: {exc}") from exc


def parse_rrs(text: str) -> RRS | None:
    """Find and parse the first valid RRS block in ``text``.

    Returns ``None`` when the report carries no RRS block. Raises
    :class:`RRSParseError` when a block is present but broken, so that a
    malformed spec is visible instead of silently ignored.
    """
    saw_candidate = False
    first_error: RRSParseError | None = None
    for info, body in find_rrs_blocks(text):
        if "rrs" not in info.lower() and not _info_is_yaml(info):
            continue
        try:
            document = yaml.safe_load(body)
        except yaml.YAMLError as exc:
            if "rrs" in info.lower() or _looks_like_an_rrs_block(body):
                raise RRSParseError(f"RRS block is not valid YAML: {exc}") from exc
            continue
        if not _looks_like_rrs(info, document):
            continue
        saw_candidate = True
        try:
            return parse_rrs_document(document)
        except RRSParseError as exc:
            first_error = exc
    if first_error is not None:
        raise first_error
    if saw_candidate:  # pragma: no cover - defensive
        raise RRSParseError("RRS block could not be parsed")

    # A bare YAML document (the form `verdis preflight` writes) also
    # counts, as long as it declares the RRS version.
    bare = _parse_bare_document(text)
    if bare is not None:
        return parse_rrs_document(bare)
    return None


def _parse_bare_document(text: str) -> dict[str, Any] | None:
    stripped = text.strip()
    if not stripped or stripped.startswith("```"):
        return None
    try:
        document = yaml.safe_load(stripped)
    except yaml.YAMLError:
        return None
    if isinstance(document, dict) and "rrs" in document:
        return document
    return None


def _info_is_yaml(info: str) -> bool:
    return bool(_RRS_INFO_RE.search(info))


def emit_rrs(
    *,
    repo: str,
    ref: str,
    vuln_class: str = "",
    component: str = "",
    impact: str = "",
    commands: tuple[str, ...] = (),
    inputs: tuple[tuple[str, str], ...] = (),
    oracle: str = "",
    signature: str = "",
    default_config: bool = True,
) -> str:
    """Render an RRS block in the Appendix D shape."""
    document: dict[str, Any] = {
        "rrs": "0.1",
        "target": {"repo": repo, "ref": ref},
    }
    claim: dict[str, Any] = {}
    if vuln_class:
        claim["class"] = vuln_class
    if component:
        claim["component"] = component
    if impact:
        claim["impact"] = impact
    if claim:
        document["claim"] = claim
    steps: list[dict[str, str]] = [{"build": "default"}]
    steps.extend({"run": command} for command in commands)
    document["steps"] = steps
    if inputs:
        document["inputs"] = [
            {"path": path, "sha256": digest} for path, digest in inputs
        ]
    expect: dict[str, Any] = {}
    if oracle:
        expect["oracle"] = oracle
    if signature:
        expect["signature"] = signature
    if expect:
        document["expect"] = expect
    document["config"] = {"default": default_config}
    return yaml.safe_dump(document, sort_keys=False, default_flow_style=False)


def emit_rrs_block(**kwargs: Any) -> str:
    """Render an RRS block as a fenced Markdown block, ready to paste."""
    body = emit_rrs(**kwargs)
    return f"```yaml\n{body}```\n"


def rrs_from_report_metadata(
    *,
    repo: str,
    ref: str,
    commands: tuple[str, ...] = (),
    attachment_hashes: dict[str, str] | None = None,
) -> RRS:
    """Build an RRS object from local knowledge (used by reporter mode)."""
    inputs = tuple(
        RRSInput(path=name, sha256=digest) for name, digest in (attachment_hashes or {}).items()
    )
    return RRS(
        version="0.1",
        target=RRSTarget(repo=repo, ref=ref),
        steps=tuple(RRSPlanStep(action="run", value=command) for command in commands),
        inputs=inputs,
    )


def rrs_fingerprint(rrs: RRS) -> str:
    """Stable hash of an RRS block, used for dedupe fingerprints (FR-4.1)."""
    return sha256_text(rrs.model_dump_json())
