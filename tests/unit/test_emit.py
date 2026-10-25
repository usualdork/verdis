"""Tests for the emitters: card, JSON, SARIF, replies and bundles (PRD 8.3-8.5)."""

from __future__ import annotations

import json

from verdis.emit.bundle import BundleBuilder
from verdis.emit.card import render_card
from verdis.emit.json_verdict import render_json
from verdis.emit.reply import render_reply, render_reply_body
from verdis.emit.sarif import render_sarif, sarif_document
from verdis.schemas.common import Verdict, VerdictFlag, VerdictTier
from verdis.schemas.policy import PolicyClause, PolicyMatch, PolicyVerdict
from verdis.schemas.run import BuildResult, BuildStatus, CommandResult, RunResult
from verdis.schemas.verdict import DedupeMatch, EvidencePoint, VerdictResult
from verdis.storage.evidence import EvidenceStore


def _verdict(**kwargs) -> VerdictResult:
    base = {
        "verdict": Verdict.REPRODUCED,
        "tier": VerdictTier.TIER_1,
        "report_id": "VDS-0042",
        "target_ref": "libfoo@v2.3.1",
        "why": "The submitted PoC triggers a heap-buffer-overflow in parse_header().",
        "evidence": (
            EvidencePoint(summary="ASan reports heap-buffer-overflow, frame #1 parse_header"),
            EvidencePoint(summary="The same PoC is clean on v2.3.2"),
            EvidencePoint(summary="No network attempts; no writes outside /work"),
        ),
        "not_established": ("exploitability beyond a crash",),
        "next_action": "confirm severity; consider a coordinated release",
    }
    base.update(kwargs)
    return VerdictResult(**base)


class TestVerdictCard:
    def test_has_the_expected_shape(self) -> None:
        card = render_card(_verdict())
        assert "Verdis verdict: REPRODUCED (Tier 1)" in card
        assert "report VDS-0042" in card
        assert "target libfoo@v2.3.1" in card
        assert "Why:" in card
        assert "Evidence:" in card
        assert "Suggested next action:" in card
        assert "Not established:" in card

    def test_shows_the_model_and_its_cost(self) -> None:
        card = render_card(_verdict(model_name="gpt-4o", model_cost_usd=0.0123))
        assert "Model: gpt-4o" in card
        assert "$0.0123" in card

    def test_says_nothing_about_a_model_when_there_was_none(self) -> None:
        card = render_card(_verdict())
        assert "Model:" not in card

    def test_shows_at_most_three_evidence_points(self) -> None:
        points = tuple(EvidencePoint(summary=f"point {i}") for i in range(6))
        card = render_card(_verdict(evidence=points))
        assert "1. point 0" in card
        assert "point 5" not in card
        assert "more in the evidence bundle" in card

    def test_shows_policy_citations(self) -> None:
        match = PolicyMatch(
            verdict=PolicyVerdict.IN_SCOPE,
            clause=PolicyClause(
                id="v",
                kind="version",
                description="Supported versions: 2.x",
                file="SECURITY.md",
                heading="Supported versions",
                line_start=10,
                line_end=14,
            ),
            reason="version 2.3.1 matches",
        )
        card = render_card(_verdict(policy_matches=(match,)))
        assert "SECURITY.md" in card

    def test_shows_duplicate_candidates(self) -> None:
        match = DedupeMatch(
            candidate_id="GHSA-xxxx-xxxx",
            similarity=0.31,
            reasons=("different function",),
        )
        card = render_card(_verdict(dedupe_matches=(match,)))
        assert "GHSA-xxxx-xxxx" in card
        assert "suggestions, not decisions" in card

    def test_says_when_there_are_no_duplicates(self) -> None:
        card = render_card(_verdict())
        assert "none above threshold" in card

    def test_shows_the_bundle_path(self) -> None:
        card = render_card(_verdict(), bundle_path="bundles/VDS-0042/")
        assert "bundles/VDS-0042/" in card
        assert "rerun.sh" in card

    def test_shows_flags(self) -> None:
        card = render_card(_verdict(flags=(VerdictFlag.FIXED_AT_HEAD,)))
        assert "FIXED_AT_HEAD" in card

    def test_every_verdict_renders(self) -> None:
        for verdict in Verdict:
            kwargs = {"tier": VerdictTier.TIER_1} if verdict is Verdict.REPRODUCED else {}
            card = render_card(VerdictResult(verdict=verdict, report_id="VDS-1", **kwargs))
            assert verdict.value in card


class TestJson:
    def test_is_valid_json(self) -> None:
        payload = json.loads(render_json(_verdict()))
        assert payload["verdict"] == "REPRODUCED"
        assert payload["tier"] == "tier1"

    def test_is_stable(self) -> None:
        assert render_json(_verdict()) == render_json(_verdict())


class TestSarif:
    def test_produces_a_valid_document(self) -> None:
        document = sarif_document(_verdict())
        assert document["version"] == "2.1.0"
        run = document["runs"][0]
        assert run["tool"]["driver"]["name"] == "Verdis"
        assert run["results"]

    def test_is_json_serialisable(self) -> None:
        assert json.loads(render_sarif(_verdict()))

    def test_a_not_reproduced_verdict_is_a_note(self) -> None:
        document = sarif_document(VerdictResult(verdict=Verdict.NOT_REPRODUCED))
        rule = document["runs"][0]["tool"]["driver"]["rules"][0]
        assert rule["defaultConfiguration"]["level"] == "note"


class TestReplies:
    def test_the_reproduced_reply_thanks_the_reporter(self) -> None:
        reply = render_reply(_verdict(), reporter="alice")
        assert "alice" in reply
        assert "reproduce" in reply.lower()
        assert "human maintainer" in reply

    def test_the_not_reproduced_reply_lists_what_was_tried(self) -> None:
        run = RunResult(
            status="completed",
            runs=(CommandResult(cmd="./demo", exit_code=0, stdout="ok"),),
        )
        verdict = VerdictResult(
            verdict=Verdict.NOT_REPRODUCED,
            report_id="VDS-1",
            run=run,
            build=BuildResult(status=BuildStatus.OK, ref="v2.3.1"),
        )
        reply = render_reply(verdict, reporter="bob")
        assert "v2.3.1" in reply
        assert "3 time" not in reply
        assert "could not trigger" in reply
        assert "does not mean the code is safe" in reply

    def test_the_needs_info_reply_has_a_checklist(self) -> None:
        match = PolicyMatch(
            verdict=PolicyVerdict.MISSING_EVIDENCE,
            clause=PolicyClause(
                id="poc",
                kind="evidence",
                description="A working proof of concept is required",
            ),
            missing=("poc",),
        )
        verdict = VerdictResult(
            verdict=Verdict.NEEDS_INFO, report_id="VDS-1", policy_matches=(match,)
        )
        reply = render_reply(verdict)
        assert "- [ ]" in reply
        assert "proof of concept" in reply

    def test_the_out_of_scope_reply_quotes_the_clause(self) -> None:
        match = PolicyMatch(
            verdict=PolicyVerdict.OUT_OF_SCOPE,
            clause=PolicyClause(
                id="x",
                kind="excluded",
                description="Local DoS is out of scope",
                quote="Local DoS is out of scope",
                file="SECURITY.md",
            ),
        )
        verdict = VerdictResult(
            verdict=Verdict.OUT_OF_SCOPE, report_id="VDS-1", policy_matches=(match,)
        )
        reply = render_reply(verdict)
        assert "Local DoS is out of scope" in reply

    def test_the_unsafe_attachment_reply_is_not_accusatory(self) -> None:
        verdict = VerdictResult(
            verdict=Verdict.UNSAFE_ATTACHMENT,
            report_id="VDS-1",
            evidence=(EvidencePoint(summary="script reads credential paths"),),
        )
        reply = render_reply(verdict)
        assert "safety check" in reply
        assert "malicious" not in reply.lower()
        assert "attacker" not in reply.lower()

    def test_the_duplicate_reply_asks_for_confirmation(self) -> None:
        verdict = VerdictResult(
            verdict=Verdict.DUPLICATE,
            report_id="VDS-1",
            dedupe_matches=(
                DedupeMatch(
                    candidate_id="VDS-0007", similarity=0.91, reasons=("same frames",)
                ),
            ),
        )
        reply = render_reply(verdict)
        assert "VDS-0007" in reply
        assert "maintainer will confirm" in reply

    def test_no_reply_is_accusatory(self) -> None:
        for verdict in Verdict:
            kwargs = {"tier": VerdictTier.TIER_1} if verdict is Verdict.REPRODUCED else {}
            body = render_reply_body(VerdictResult(verdict=verdict, **kwargs))
            for word in ("malicious", "attacker", "liar", "spam"):
                assert word not in body.lower()

    def test_every_verdict_has_a_reply(self) -> None:
        for verdict in Verdict:
            kwargs = {"tier": VerdictTier.TIER_1} if verdict is Verdict.REPRODUCED else {}
            reply = render_reply(VerdictResult(verdict=verdict, **kwargs))
            assert reply.strip()
            assert "Hello" in reply

    def test_an_unknown_reporter_still_gets_a_greeting(self) -> None:
        reply = render_reply(_verdict(), reporter="")
        assert "Hello" in reply


class TestBundle:
    def test_writes_every_artifact(self, evidence: EvidenceStore) -> None:
        builder = BundleBuilder(evidence)
        run = RunResult(
            status="completed",
            runs=(CommandResult(cmd="./demo", exit_code=1, stderr="boom"),),
        )
        manifest = builder.build(
            report_id="VDS-0042",
            verdict=_verdict(),
            build_result=BuildResult(status=BuildStatus.OK, ref="v2.3.1", logs=("built",)),
            run_result=run,
            original_body="the original report",
            reporter="alice",
        )
        bundle = evidence.bundle_dir("VDS-0042")
        for name in (
            "manifest.json",
            "verdict.json",
            "verdict.md",
            "draft_reply.md",
            "rerun.sh",
            "environment.json",
            "original/report.md",
        ):
            assert (bundle / name).is_file(), name
        assert manifest.report_id == "VDS-0042"
        assert manifest.files

    def test_the_manifest_hashes_every_file(self, evidence: EvidenceStore) -> None:
        from verdis.schemas.common import sha256_file

        builder = BundleBuilder(evidence)
        builder.build(report_id="VDS-0043", verdict=_verdict(), original_body="x")
        manifest = evidence.read_manifest("VDS-0043")
        assert manifest is not None
        for entry in manifest.files:
            path = evidence.bundle_dir("VDS-0043") / entry.path
            assert sha256_file(str(path)) == entry.sha256

    def test_verification_detects_tampering(self, evidence: EvidenceStore) -> None:
        builder = BundleBuilder(evidence)
        builder.build(report_id="VDS-0044", verdict=_verdict(), original_body="x")
        assert evidence.verify_bundle("VDS-0044") == []
        (evidence.bundle_dir("VDS-0044") / "verdict.md").write_text("tampered", encoding="utf-8")
        problems = evidence.verify_bundle("VDS-0044")
        assert problems
        assert "hash mismatch" in problems[0]

    def test_verification_detects_a_missing_file(self, evidence: EvidenceStore) -> None:
        builder = BundleBuilder(evidence)
        builder.build(report_id="VDS-0045", verdict=_verdict(), original_body="x")
        (evidence.bundle_dir("VDS-0045") / "verdict.md").unlink()
        problems = evidence.verify_bundle("VDS-0045")
        assert any("missing" in problem for problem in problems)

    def test_rerun_script_is_executable(self, evidence: EvidenceStore) -> None:
        builder = BundleBuilder(evidence)
        builder.build(report_id="VDS-0046", verdict=_verdict(), original_body="x")
        script = evidence.bundle_dir("VDS-0046") / "rerun.sh"
        assert script.stat().st_mode & 0o111
