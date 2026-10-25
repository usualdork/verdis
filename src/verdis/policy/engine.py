"""Policy evaluation: map a claim onto the project's own rules (FR-3.3, FR-3.4).

Every outcome carries a citation so a reply can quote the maintainer's own
words rather than the tool's paraphrase.
"""

from __future__ import annotations

import fnmatch
import re
from dataclasses import dataclass, field

from ..schemas.claim import Claim
from ..schemas.common import normalize_identifier, normalize_text
from ..schemas.policy import Policy, PolicyClause, PolicyMatch, PolicyVerdict
from .loader import matches_version

__all__ = ["PolicyAssessment", "PolicyEngine", "component_matches_pattern"]


def _words(value: str) -> tuple[str, ...]:
    """Split an identifier into comparable words."""
    parts = re.split(r"[^a-z0-9]+", (value or "").lower())
    return tuple(part for part in parts if part)


def _shares_stem(left: str, right: str) -> bool:
    """Do two words share a stem of at least four characters?"""
    if not left or not right:
        return False
    shorter, longer = (left, right) if len(left) <= len(right) else (right, left)
    if len(shorter) < 4:
        return False
    return longer.startswith(shorter)


def component_matches_pattern(pattern: str, *values: str) -> bool:
    """Does any of ``values`` match the component pattern?

    Matching is deliberately generous: maintainers write ``parser``,
    ``network-client`` and ``src/net/`` and expect all of them to work.
    """
    pattern_norm = normalize_identifier(pattern)
    if not pattern_norm:
        return False
    pattern_words = _words(pattern_norm)
    for value in values:
        value_norm = normalize_identifier(value)
        if not value_norm:
            continue
        if fnmatch.fnmatch(value_norm, pattern_norm):
            return True
        if pattern_norm in value_norm or value_norm in pattern_norm:
            return True
        if pattern_norm.replace("_", "/") in value_norm.replace("_", "/"):
            return True
        value_words = _words(value_norm)
        for pattern_word in pattern_words:
            for value_word in value_words:
                if _shares_stem(pattern_word, value_word):
                    return True
    return False


@dataclass
class PolicyAssessment:
    """The result of checking one claim against one policy."""

    matches: list[PolicyMatch] = field(default_factory=list)
    exclusions: list[PolicyMatch] = field(default_factory=list)
    evidence_gaps: list[PolicyMatch] = field(default_factory=list)
    version_supported: bool | None = None
    component_in_scope: bool | None = None
    notes: list[str] = field(default_factory=list)

    @property
    def out_of_scope(self) -> bool:
        return bool(self.exclusions) or self.component_in_scope is False

    @property
    def missing_evidence(self) -> list[str]:
        missing: list[str] = []
        for match in self.evidence_gaps:
            missing.extend(match.missing)
        return missing

    @property
    def all_matches(self) -> list[PolicyMatch]:
        return [*self.matches, *self.exclusions, *self.evidence_gaps]

    def first_exclusion(self) -> PolicyMatch | None:
        """The first explicit exclusion, if there is one."""
        return self.exclusions[0] if self.exclusions else None

    def first_out_of_scope(self) -> PolicyMatch | None:
        """The first reason the policy puts this report out of scope.

        An unsupported version counts. The PRD gives it as the example
        of an out-of-scope claim ("the affected version is not
        supported"), and a report about a version the project does not
        maintain is not something the project can act on.
        """
        if self.exclusions:
            return self.exclusions[0]
        for match in self.matches:
            if match.verdict is PolicyVerdict.UNSUPPORTED_VERSION:
                return match
        return None


class PolicyEngine:
    """Deterministic claim-to-policy mapping."""

    def __init__(self, policy: Policy) -> None:
        self.policy = policy

    def check(self, claim: Claim) -> PolicyAssessment:
        assessment = PolicyAssessment()

        self._check_version(claim, assessment)
        self._check_scope(claim, assessment)
        self._check_exclusions(claim, assessment)
        self._check_evidence(claim, assessment)
        return assessment

    # -- version --------------------------------------------------------

    def _check_version(self, claim: Claim, assessment: PolicyAssessment) -> None:
        patterns = self.policy.supported_versions
        if not patterns:
            assessment.version_supported = None
            return
        version = claim.affected_version
        if not version:
            assessment.version_supported = None
            assessment.notes.append(
                "no affected version stated; version support could not be checked"
            )
            return
        source = self.policy.source_files[0] if self.policy.source_files else ""
        for pattern in patterns:
            if matches_version(pattern, version):
                assessment.version_supported = True
                assessment.matches.append(
                    PolicyMatch(
                        verdict=PolicyVerdict.IN_SCOPE,
                        clause=PolicyClause(
                            id=f"supported-version:{pattern}",
                            kind="version",
                            description=f"Supported versions: {pattern}",
                            version_patterns=(pattern,),
                            file=source,
                        ),
                        reason=f"version {version} matches supported pattern {pattern}",
                    )
                )
                return
        assessment.version_supported = False
        assessment.matches.append(
            PolicyMatch(
                verdict=PolicyVerdict.UNSUPPORTED_VERSION,
                clause=PolicyClause(
                    id="supported-versions",
                    kind="version",
                    description="Supported versions: " + ", ".join(patterns),
                    version_patterns=patterns,
                    file=source,
                ),
                reason=f"version {version} does not match any supported version pattern",
            )
        )

    # -- component scope ------------------------------------------------

    def _check_scope(self, claim: Claim, assessment: PolicyAssessment) -> None:
        in_scope = self.policy.in_scope
        if not in_scope:
            assessment.component_in_scope = None
            return
        component = claim.component
        values = (component.name, component.file, component.key)
        if not any(values):
            assessment.component_in_scope = None
            assessment.notes.append("no component identified; scope could not be checked")
            return
        for pattern in in_scope:
            if component_matches_pattern(pattern, *values):
                assessment.component_in_scope = True
                assessment.matches.append(
                    PolicyMatch(
                        verdict=PolicyVerdict.IN_SCOPE,
                        clause=PolicyClause(
                            id=f"in-scope:{pattern}",
                            kind="in_scope",
                            description=f"In scope: {pattern}",
                            component_patterns=(pattern,),
                        ),
                        reason=f"component matches in-scope pattern {pattern!r}",
                    )
                )
                return
        assessment.component_in_scope = False
        assessment.exclusions.append(
            PolicyMatch(
                verdict=PolicyVerdict.OUT_OF_SCOPE,
                clause=PolicyClause(
                    id="in-scope-list",
                    kind="excluded",
                    description="In scope: " + ", ".join(in_scope),
                    component_patterns=in_scope,
                ),
                reason="component does not match any in-scope pattern",
            )
        )

    # -- exclusions -----------------------------------------------------

    def _check_exclusions(self, claim: Claim, assessment: PolicyAssessment) -> None:
        haystack = self._claim_text(claim)
        for clause in self.policy.excluded_classes:
            if self._exclusion_hits(clause, claim, haystack):
                assessment.exclusions.append(
                    PolicyMatch(
                        verdict=PolicyVerdict.OUT_OF_SCOPE,
                        clause=clause,
                        reason=clause.description or "matches an excluded class",
                    )
                )

    @staticmethod
    def _claim_text(claim: Claim) -> str:
        parts = [
            claim.impact.summary,
            claim.component.name,
            claim.component.file,
            claim.vuln_class,
            *claim.preconditions,
            *claim.config_assumptions,
        ]
        return normalize_text(" ".join(p for p in parts if p)).lower()

    def _exclusion_hits(self, clause: PolicyClause, claim: Claim, haystack: str) -> bool:
        if (
            clause.version_patterns
            and claim.affected_version
            and not any(
                matches_version(p, claim.affected_version) for p in clause.version_patterns
            )
        ):
            return False
        if clause.component_patterns:
            values = (claim.component.name, claim.component.file)
            return any(component_matches_pattern(p, *values) for p in clause.component_patterns)
        description = normalize_text(clause.description).lower()
        if not description:
            return False
        keywords = [k for k in re.split(r"[^a-z0-9]+", description) if len(k) > 3]
        if not keywords:
            return False
        hits = sum(1 for k in keywords if k in haystack)
        return hits >= max(2, len(keywords) // 2)

    # -- evidence -------------------------------------------------------

    def _check_evidence(self, claim: Claim, assessment: PolicyAssessment) -> None:
        requirements = self.policy.evidence
        if requirements.poc_required and not claim.has_poc:
            assessment.evidence_gaps.append(
                PolicyMatch(
                    verdict=PolicyVerdict.MISSING_EVIDENCE,
                    clause=PolicyClause(
                        id="evidence:poc-required",
                        kind="evidence",
                        description="A proof of concept is required",
                        requires_poc=True,
                    ),
                    reason="the report contains no proof of concept",
                    missing=("poc",),
                )
            )
        if requirements.default_config_only and claim.non_default_config:
            assessment.evidence_gaps.append(
                PolicyMatch(
                    verdict=PolicyVerdict.MISSING_EVIDENCE,
                    clause=PolicyClause(
                        id="evidence:default-config-only",
                        kind="evidence",
                        description="The default configuration must be affected",
                        default_config_only=True,
                    ),
                    reason="the claim only affects a non-default configuration",
                    missing=("default_configuration",),
                )
            )
        if (
            requirements.min_tested_version
            and claim.affected_version
            and not matches_version(
                f">={requirements.min_tested_version}", claim.affected_version
            )
        ):
                assessment.evidence_gaps.append(
                    PolicyMatch(
                        verdict=PolicyVerdict.MISSING_EVIDENCE,
                        clause=PolicyClause(
                            id="evidence:min-tested-version",
                            kind="evidence",
                            description=(
                                f"Only versions from {requirements.min_tested_version} onwards "
                                "are tested"
                            ),
                            min_version=requirements.min_tested_version,
                        ),
                        reason=(
                            f"version {claim.affected_version} is older than the minimum "
                            f"tested version {requirements.min_tested_version}"
                        ),
                        missing=("tested_version",),
                    )
                )
