"""The verdict card (PRD 8.4, Appendix B).

What the maintainer sees first: the verdict, one paragraph on why, three
key evidence points, policy citations, duplicate candidates, a suggested
next action, a link to the bundle, and an explicit statement of what the
verdict does not establish.
"""

from __future__ import annotations

from ..schemas.common import Verdict
from ..schemas.verdict import VerdictResult

__all__ = ["render_card", "render_card_lines"]

_VERDICT_LABEL = {
    Verdict.REPRODUCED: "REPRODUCED",
    Verdict.NOT_REPRODUCED: "NOT_REPRODUCED",
    Verdict.INCONCLUSIVE: "INCONCLUSIVE",
    Verdict.OUT_OF_SCOPE: "OUT_OF_SCOPE",
    Verdict.DUPLICATE: "DUPLICATE",
    Verdict.NEEDS_INFO: "NEEDS_INFO",
    Verdict.UNSAFE_ATTACHMENT: "UNSAFE_ATTACHMENT",
}


def _wrap(text: str, width: int = 76, indent: str = "") -> list[str]:
    """Wrap text to a width, keeping the indent on continuation lines."""
    words = text.split()
    lines: list[str] = []
    current = ""
    for word in words:
        candidate = f"{current} {word}".strip()
        if len(candidate) + len(indent) > width and current:
            lines.append(indent + current)
            current = word
        else:
            current = candidate
    if current:
        lines.append(indent + current)
    return lines or [indent.rstrip()]


def render_card_lines(verdict: VerdictResult, *, bundle_path: str = "") -> list[str]:
    """Render the verdict card as a list of lines."""
    label = _VERDICT_LABEL[verdict.verdict]
    if verdict.tier is not None:
        label = f"{label} ({verdict.tier.value.replace('tier', 'Tier ')})"

    header = f"Verdis verdict: {label}"
    if verdict.report_id:
        header += f"   report {verdict.report_id}"
    if verdict.target_ref:
        header += f"   target {verdict.target_ref}"

    lines: list[str] = [header, ""]

    if verdict.why:
        lines.append("Why:")
        lines.extend(_wrap(verdict.why, indent="     "))
        lines.append("")

    if verdict.evidence:
        lines.append("Evidence:")
        for index, point in enumerate(verdict.evidence[:3], start=1):
            body = point.summary
            if point.artifact:
                body = f"{body} [{point.artifact}]"
            wrapped = _wrap(body, indent="      ")
            lines.append(f"  {index}. {wrapped[0].strip()}")
            lines.extend(wrapped[1:])
        if len(verdict.evidence) > 3:
            lines.append(f"  (+{len(verdict.evidence) - 3} more in the evidence bundle)")
        lines.append("")

    policy_lines = _policy_lines(verdict)
    if policy_lines:
        head, *rest = policy_lines
        lines.append(f"Policy: {head}")
        lines.extend(rest)
        lines.append("")

    lines.append("Duplicates: " + _duplicate_line(verdict))
    lines.append("")

    if verdict.flags:
        lines.append("Flags: " + ", ".join(str(flag) for flag in verdict.flags))
        lines.append("")

    if verdict.next_action:
        lines.append(f"Suggested next action: {verdict.next_action}")
        lines.append("")

    if verdict.model_name:
        cost = f"${verdict.model_cost_usd:.4f}"
        lines.append(f"Model: {verdict.model_name} ({cost} modelled)")
        lines.append("")

    bundle = bundle_path or verdict.bundle_path
    if bundle:
        lines.append(f"Bundle: {bundle}  (run ./rerun.sh to reproduce)")
        lines.append("")

    if verdict.not_established:
        lines.append("Not established: " + "; ".join(verdict.not_established) + ".")
        lines.append("")

    return lines


def _policy_lines(verdict: VerdictResult) -> list[str]:
    if not verdict.policy_matches:
        return ["no policy was matched (no policy file or documentation was found)."]
    lines: list[str] = []
    for match in verdict.policy_matches[:4]:
        citation = match.citation or "policy"
        detail = match.reason or (match.clause.description if match.clause else "")
        lines.append(f"{citation}: {detail}")
    if len(verdict.policy_matches) > 4:
        lines.append(f"(+{len(verdict.policy_matches) - 4} more policy matches)")
    return lines


def _duplicate_line(verdict: VerdictResult) -> str:
    if not verdict.dedupe_matches:
        return "none above threshold."
    best = verdict.dedupe_matches[0]
    reasons = "; ".join(best.reasons[:2])
    return (
        f"closest: {best.candidate_id}, similarity {best.similarity:.2f}"
        + (f" ({reasons})" if reasons else "")
        + ". Matches are suggestions, not decisions."
    )


def render_card(verdict: VerdictResult, *, bundle_path: str = "") -> str:
    """Render the verdict card as Markdown text."""
    return "\n".join(render_card_lines(verdict, bundle_path=bundle_path)).rstrip() + "\n"
