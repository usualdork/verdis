"""Tests for the published data model (PRD section 10.3)."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from verdis.schemas import (
    Claim,
    Report,
    SourceSpan,
    Target,
    Verdict,
    VerdictResult,
    VerdictTier,
    normalize_cwe,
    normalize_identifier,
    normalize_text,
    stable_id,
)
from verdis.schemas.common import ReportSource


class TestSourceSpan:
    def test_rejects_inverted_range(self) -> None:
        with pytest.raises(ValidationError):
            SourceSpan(start=10, end=2)

    def test_overlaps(self) -> None:
        a = SourceSpan(start=0, end=10)
        b = SourceSpan(start=5, end=15)
        c = SourceSpan(start=10, end=20)
        assert a.overlaps(b)
        assert not a.overlaps(c)

    def test_is_frozen(self) -> None:
        span = SourceSpan(start=0, end=1)
        with pytest.raises(ValidationError):
            span.start = 5  # type: ignore[misc]


class TestReportId:
    def test_is_content_addressed(self) -> None:
        target = Target(repo="repo", ref="v1")
        first = Report.compute_id("body", target, ReportSource.FILE)
        second = Report.compute_id("body", target, ReportSource.FILE)
        assert first == second
        assert first.startswith("VDS-")

    def test_changes_with_body(self) -> None:
        target = Target(repo="repo", ref="v1")
        assert Report.compute_id("a", target, ReportSource.FILE) != Report.compute_id(
            "b", target, ReportSource.FILE
        )

    def test_changes_with_ref(self) -> None:
        assert Report.compute_id(
            "body", Target(repo="r", ref="v1"), ReportSource.FILE
        ) != Report.compute_id("body", Target(repo="r", ref="v2"), ReportSource.FILE)

    def test_changes_with_source(self) -> None:
        target = Target(repo="r", ref="v1")
        assert Report.compute_id("body", target, ReportSource.FILE) != Report.compute_id(
            "body", target, ReportSource.IMAP
        )


class TestVerdictResult:
    def test_reproduced_requires_a_tier(self) -> None:
        with pytest.raises(ValidationError, match="must carry a tier"):
            VerdictResult(verdict=Verdict.REPRODUCED)

    def test_other_verdicts_reject_a_tier(self) -> None:
        with pytest.raises(ValidationError, match="only REPRODUCED"):
            VerdictResult(verdict=Verdict.NOT_REPRODUCED, tier=VerdictTier.TIER_1)

    def test_reproduced_with_tier_is_valid(self) -> None:
        result = VerdictResult(verdict=Verdict.REPRODUCED, tier=VerdictTier.TIER_1)
        assert result.is_definitive

    @pytest.mark.parametrize(
        "verdict",
        [
            Verdict.REPRODUCED,
            Verdict.NOT_REPRODUCED,
            Verdict.OUT_OF_SCOPE,
            Verdict.DUPLICATE,
        ],
    )
    def test_definitive_verdicts(self, verdict: Verdict) -> None:
        kwargs = {"tier": VerdictTier.TIER_1} if verdict is Verdict.REPRODUCED else {}
        assert VerdictResult(verdict=verdict, **kwargs).is_definitive

    @pytest.mark.parametrize(
        "verdict",
        [Verdict.INCONCLUSIVE, Verdict.NEEDS_INFO, Verdict.UNSAFE_ATTACHMENT],
    )
    def test_non_definitive_verdicts(self, verdict: Verdict) -> None:
        assert not VerdictResult(verdict=verdict).is_definitive


class TestClaim:
    def test_class_is_normalized(self) -> None:
        claim = Claim(vuln_class="cwe 122")
        assert claim.vuln_class == "CWE-122"

    def test_missing_fields_default_to_empty(self) -> None:
        claim = Claim()
        assert claim.missing_fields == ()
        assert not claim.has_poc
        assert claim.is_complete

    def test_spans_are_optional(self) -> None:
        claim = Claim()
        assert claim.span_for("component") is None


class TestNormalisation:
    @pytest.mark.parametrize(
        ("raw", "expected"),
        [
            ("CWE-122", "CWE-122"),
            ("cwe 122", "CWE-122"),
            ("CWE_787", "CWE-787"),
            ("787", "CWE-787"),
            ("not a cwe", ""),
            ("", ""),
            ("CWE-0", ""),
        ],
    )
    def test_normalize_cwe(self, raw: str, expected: str) -> None:
        assert normalize_cwe(raw) == expected

    def test_normalize_identifier(self) -> None:
        assert normalize_identifier("Parse Header()") == "parse_header"
        assert normalize_identifier("src/hdr.c") == "src/hdr.c"

    def test_normalize_text(self) -> None:
        assert normalize_text("  a   b\n c ") == "a b c"

    def test_stable_id_is_deterministic(self) -> None:
        assert stable_id("RG", "a", "b") == stable_id("RG", "a", "b")
        assert stable_id("RG", "a", "b") != stable_id("RG", "b", "a")
