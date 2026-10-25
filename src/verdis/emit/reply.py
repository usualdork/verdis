"""Draft replies (PRD 8.5).

One respectful template per verdict, citing exactly what was tried. Nothing
is accusatory, and every reply is approved by a maintainer before it is
sent.
"""

from __future__ import annotations

from ..schemas.common import Verdict
from ..schemas.verdict import VerdictResult

__all__ = ["render_reply", "render_reply_body"]

_GREETING = "Hello {reporter},\n\n"
_CLOSING = (
    "\nIf anything above does not match what you saw on your side, please reply and "
    "tell us: we will re-run the report ourselves.\n\n"
    "Thanks for taking the time to report this.\n"
)


def _reporter_name(reporter: str) -> str:
    handle = (reporter or "").strip()
    if not handle:
        return "reporter"
    if handle.startswith("@"):
        return handle
    if "<" in handle and ">" in handle:
        return handle.split("<", 1)[1].rstrip(">")
    return handle


def render_reply_body(verdict: VerdictResult) -> str:
    """The body of the draft reply, without the greeting or closing."""
    if verdict.verdict is Verdict.REPRODUCED:
        lines = [
            "We were able to reproduce the reported behaviour.",
            "",
        ]
        for point in verdict.evidence[:3]:
            lines.append(f"- {point.summary}")
        if verdict.flags:
            lines.append("")
            lines.append("Notes: " + ", ".join(str(flag) for flag in verdict.flags) + ".")
        lines.append("")
        lines.append(
            "A human maintainer will follow up with details. Please keep the report "
            "and any proof of concept private until we agree otherwise."
        )
        return "\n".join(lines)

    if verdict.verdict is Verdict.NOT_REPRODUCED:
        lines = [
            "We tried to reproduce this and could not trigger the reported behaviour "
            "in our environment.",
            "",
            "Here is exactly what we did:",
        ]
        if verdict.build is not None and verdict.build.ref:
            lines.append(f"- Built the project at {verdict.build.ref}.")
        if verdict.run is not None:
            lines.append(
                f"- Ran the proof of concept {len(verdict.run.runs)} time(s) inside an "
                "isolated sandbox with no network access."
            )
            codes = ", ".join(str(code) for code in verdict.run.exit_codes)
            lines.append(f"- The command exited with {codes} and no crash or sanitizer "
                         "report was produced.")
        lines.append("")
        lines.append(
            "This does not mean the code is safe: it means this particular proof of "
            "concept did not show the behaviour here. If you can share the exact "
            "output you saw, or the environment you used, we will try again."
        )
        return "\n".join(lines)

    if verdict.verdict is Verdict.INCONCLUSIVE:
        lines = [
            "We could not reach a conclusion from this report yet.",
            "",
            "Here is what happened:",
        ]
        if verdict.build is not None and verdict.build.failure_step:
            lines.append(f"- The build failed at {verdict.build.failure_step}.")
        if verdict.run is not None and verdict.run.status.value == "timeout":
            lines.append("- The proof of concept ran past the time limit and was stopped.")
        lines.append(
            "- Because the run did not complete, we cannot say whether the issue "
            "reproduces."
        )
        lines.append("")
        lines.append(
            "If you can tell us more about how to build and run this (or send the "
            "output you saw), we will pick it up again."
        )
        return "\n".join(lines)

    if verdict.verdict is Verdict.OUT_OF_SCOPE:
        lines = [
            "We reproduced the behaviour you described, but it falls outside the scope "
            "we can act on.",
            "",
        ]
        for match in verdict.policy_matches:
            if match.clause and (match.clause.quote or match.clause.description):
                quote = match.clause.quote or match.clause.description
                lines.append(f'Our policy states: "{quote}" ({match.citation}).')
                break
        lines.append("")
        lines.append(
            "A maintainer will review this and may make an exception. Thank you for "
            "the report either way."
        )
        return "\n".join(lines)

    if verdict.verdict is Verdict.DUPLICATE:
        lines = [
            "This looks very similar to a report we already have.",
            "",
        ]
        best = verdict.dedupe_matches[0] if verdict.dedupe_matches else None
        if best is not None:
            reasons = "; ".join(best.reasons)
            lines.append(
                f"The closest existing report is {best.candidate_id} "
                f"(similarity {best.similarity:.2f}"
                + (f": {reasons}" if reasons else "")
                + ")."
            )
        lines.append("")
        lines.append(
            "A human maintainer will confirm whether these are the same issue. If you "
            "believe it is a different problem, please say so and we will take another "
            "look."
        )
        return "\n".join(lines)

    if verdict.verdict is Verdict.NEEDS_INFO:
        lines = ["We need a little more information before we can start.", ""]
        lines.append("Our policy asks for the following:")
        lines.append("")
        for match in verdict.policy_matches:
            if match.clause and match.clause.description:
                lines.append(f"- {match.clause.description}")
        lines.append("")
        lines.append("A short checklist:")
        lines.append("")
        for missing in ("affected version", "proof of concept", "steps to reproduce",
                        "expected behaviour"):
            lines.append(f"- [ ] {missing}")
        lines.append("")
        lines.append(
            "None of this means the report is not valid; we just need those details to "
            "reproduce it. As soon as we have them we will run it."
        )
        return "\n".join(lines)

    if verdict.verdict is Verdict.UNSAFE_ATTACHMENT:
        lines = [
            "We could not run the attached file, so we have not been able to try the "
            "report yet.",
            "",
            "Our static checks observed the following in the attachment:",
            "",
        ]
        for point in verdict.evidence[:5]:
            lines.append(f"- {point.summary}")
        lines.append("")
        lines.append(
            "This is a safety check on our side, not a judgement about you. If you can "
            "send the proof of concept as a description of the steps and the input it "
            "uses, we will work from that instead."
        )
        return "\n".join(lines)

    # Every verdict has a template above; this is the guard for a verdict
    # added without one.
    return "We have reviewed the report. A maintainer will follow up."  # pragma: no cover


def render_reply(verdict: VerdictResult, *, reporter: str = "") -> str:
    """Render the full draft reply."""
    name = _reporter_name(reporter or verdict.report_id)
    body = render_reply_body(verdict)
    return _GREETING.format(reporter=name) + body + _CLOSING
