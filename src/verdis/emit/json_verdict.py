"""JSON verdict emitter (machine-readable output, PRD 9.5)."""

from __future__ import annotations

import json

from ..schemas.common import to_jsonable
from ..schemas.verdict import VerdictResult

__all__ = ["render_json", "verdict_to_dict"]


def verdict_to_dict(verdict: VerdictResult) -> dict[str, object]:
    """The verdict as a plain dictionary."""
    payload: dict[str, object] = to_jsonable(verdict)
    return payload


def render_json(verdict: VerdictResult, *, indent: int = 2) -> str:
    """The verdict as JSON text."""
    return json.dumps(verdict_to_dict(verdict), indent=indent, sort_keys=True)
