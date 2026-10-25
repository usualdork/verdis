"""Tests for the policy loader, derivation and engine (FR-3)."""

from __future__ import annotations

from pathlib import Path

import pytest

from verdis.policy.engine import PolicyEngine, component_matches_pattern
from verdis.policy.loader import (
    PolicyLoadError,
    derive_policy_from_docs,
    load_policy,
    load_policy_file,
    matches_version,
    policy_from_dict,
)
from verdis.schemas.claim import Claim, ClaimComponent, PoCCommand
from verdis.schemas.policy import Policy, PolicyOrigin, PolicyVerdict


class TestVersionMatching:
    @pytest.mark.parametrize(
        ("pattern", "version", "expected"),
        [
            ("2.x", "2.3.1", True),
            ("2.x", "3.0.0", False),
            ("2.*", "2.0", True),
            ("2.3", "2.3.1", True),
            ("2.3.1", "2.3.1", True),
            ("2.3.1", "2.3.2", False),
            (">=2.0", "2.0.0", True),
            (">=2.0", "1.9.9", False),
            ("<3.0", "2.9.9", True),
            ("<3.0", "3.0.0", False),
            ("2.0-2.5", "2.3.1", True),
            ("2.0-2.5", "2.6.0", False),
            ("all", "9.9.9", True),
            ("latest", "9.9.9", True),
            ("2.x || 3.x", "3.1.0", True),
            ("2.x || 3.x", "4.0.0", False),
        ],
    )
    def test_matches(self, pattern: str, version: str, expected: bool) -> None:
        assert matches_version(pattern, version) is expected

    @pytest.mark.parametrize(
        ("pattern", "version"),
        [("", "1.0"), ("2.x", ""), ("", "")],
    )
    def test_empty_inputs_never_match(self, pattern: str, version: str) -> None:
        assert not matches_version(pattern, version)


class TestPolicyFile:
    def test_loads_a_valid_policy(self, policy_file: Path) -> None:
        policy = load_policy_file(policy_file)
        assert policy.supported_versions == ("2.x",)
        assert policy.in_scope == ("parser", "network-client")
        assert policy.evidence.poc_required is True
        assert policy.confirmed is True
        assert policy.origin is PolicyOrigin.EXPLICIT

    def test_missing_file_raises(self, tmp_path: Path) -> None:
        with pytest.raises(PolicyLoadError):
            load_policy_file(tmp_path / "nope.yml")

    def test_invalid_yaml_raises(self, tmp_path: Path) -> None:
        path = tmp_path / "policy.yml"
        path.write_text("supported_versions: [\n", encoding="utf-8")
        with pytest.raises(PolicyLoadError):
            load_policy_file(path)

    def test_non_mapping_raises(self, tmp_path: Path) -> None:
        path = tmp_path / "policy.yml"
        path.write_text("- a\n- b\n", encoding="utf-8")
        with pytest.raises(PolicyLoadError):
            load_policy_file(path)

    def test_empty_file_is_an_empty_policy(self, tmp_path: Path) -> None:
        path = tmp_path / "policy.yml"
        path.write_text("", encoding="utf-8")
        policy = load_policy_file(path)
        assert policy.supported_versions == ()

    def test_out_of_scope_becomes_an_exclusion(self) -> None:
        policy = policy_from_dict({"out_of_scope": ["docs only"]})
        assert policy.excluded_classes[0].kind == "excluded"

    def test_bad_excluded_class_raises(self) -> None:
        with pytest.raises(PolicyLoadError):
            policy_from_dict({"excluded_classes": [123]})


class TestDerivation:
    def test_derives_from_security_md(self, tmp_path: Path) -> None:
        (tmp_path / "SECURITY.md").write_text(
            "# Security policy\n"
            "\n"
            "## Supported versions\n"
            "\n"
            "- 2.x\n"
            "\n"
            "## Out of scope\n"
            "\n"
            "- Denial of service from local CLI input\n",
            encoding="utf-8",
        )
        policy = derive_policy_from_docs(tmp_path)
        assert policy is not None
        assert "2.x" in policy.supported_versions
        assert policy.out_of_scope
        assert policy.derived is True
        assert policy.confirmed is False
        assert policy.origin is PolicyOrigin.UNVERIFIED

    def test_derivation_cites_the_source(self, tmp_path: Path) -> None:
        (tmp_path / "SECURITY.md").write_text(
            "# Security\n\n## Out of scope\n\n- Local DoS from the CLI\n", encoding="utf-8"
        )
        policy = derive_policy_from_docs(tmp_path)
        assert policy is not None
        clause = policy.excluded_classes[0]
        assert clause.file.endswith("SECURITY.md")
        assert clause.heading == "Out of scope"
        assert clause.line_start > 0
        assert "Local DoS" in clause.quote

    def test_no_docs_means_no_derivation(self, tmp_path: Path) -> None:
        assert derive_policy_from_docs(tmp_path) is None

    def test_load_policy_prefers_the_explicit_file(self, tmp_path: Path) -> None:
        (tmp_path / ".verdis").mkdir()
        (tmp_path / ".verdis" / "policy.yml").write_text(
            "supported_versions: ['1.x']\n", encoding="utf-8"
        )
        (tmp_path / "SECURITY.md").write_text(
            "# Security\n\n## Supported versions\n\n- 9.x\n", encoding="utf-8"
        )
        policy, origin = load_policy(tmp_path)
        assert origin == "policy.yml"
        assert policy.supported_versions == ("1.x",)

    def test_load_policy_falls_back_to_derivation(self, tmp_path: Path) -> None:
        (tmp_path / "SECURITY.md").write_text(
            "# Security\n\n## Supported versions\n\n- 3.x\n", encoding="utf-8"
        )
        policy, origin = load_policy(tmp_path)
        assert origin == "derived"
        assert policy.derived

    def test_load_policy_without_anything_is_permissive(self, tmp_path: Path) -> None:
        policy, origin = load_policy(tmp_path)
        assert origin == "default"
        assert policy.supported_versions == ()


class TestComponentMatching:
    @pytest.mark.parametrize(
        ("pattern", "component", "expected"),
        [
            ("parser", "parse_header", True),
            ("parser", "src/parser.c", True),
            ("network-client", "network_client", True),
            ("parser", "unrelated_module", False),
            ("*client*", "my_client", True),
        ],
    )
    def test_matching(self, pattern: str, component: str, expected: bool) -> None:
        assert component_matches_pattern(pattern, component) is expected

    def test_empty_pattern_never_matches(self) -> None:
        assert not component_matches_pattern("", "anything")


class TestPolicyEngine:
    def _policy(self, **kwargs) -> Policy:
        base = {
            "supported_versions": ["2.x"],
            "in_scope": ["parser"],
            "evidence_requirements": {"poc_required": True, "default_config_only": True},
        }
        base.update(kwargs)
        return policy_from_dict(base)

    def _claim(self, **kwargs) -> Claim:
        base = {
            "component": ClaimComponent(name="parse_header", file="src/hdr.c"),
            "vuln_class": "CWE-122",
            "affected_version": "2.3.1",
            "poc_commands": (PoCCommand(command="./demo poc.bin"),),
        }
        base.update(kwargs)
        return Claim(**base)

    def test_in_scope_claim(self) -> None:
        assessment = PolicyEngine(self._policy()).check(self._claim())
        assert assessment.component_in_scope is True
        assert assessment.version_supported is True
        assert not assessment.out_of_scope
        assert not assessment.missing_evidence

    def test_out_of_scope_component(self) -> None:
        claim = self._claim(component=ClaimComponent(name="docs_builder"))
        assessment = PolicyEngine(self._policy()).check(claim)
        assert assessment.component_in_scope is False
        assert assessment.out_of_scope
        assert assessment.exclusions

    def test_unsupported_version(self) -> None:
        claim = self._claim(affected_version="1.0.0")
        assessment = PolicyEngine(self._policy()).check(claim)
        assert assessment.version_supported is False
        assert any(m.verdict is PolicyVerdict.UNSUPPORTED_VERSION for m in assessment.matches)

    def test_missing_poc_is_a_evidence_gap(self) -> None:
        claim = self._claim(poc_commands=())
        assessment = PolicyEngine(self._policy()).check(claim)
        assert "poc" in assessment.missing_evidence

    def test_non_default_config_is_a_gap(self) -> None:
        claim = self._claim(non_default_config=True)
        assessment = PolicyEngine(self._policy()).check(claim)
        assert "default_configuration" in assessment.missing_evidence

    def test_exclusion_by_description(self) -> None:
        policy = self._policy(
            excluded_classes=[
                {
                    "id": "local-dos",
                    "description": "Denial of service from unbounded local CLI input",
                }
            ]
        )
        claim = self._claim(impact={"summary": "denial of service from unbounded local input"})
        assessment = PolicyEngine(policy).check(claim)
        assert assessment.exclusions

    def test_exclusion_cites_the_clause(self) -> None:
        policy = self._policy(
            excluded_classes=[{"id": "x", "description": "Requires attacker-controlled config"}]
        )
        claim = self._claim(impact={"summary": "requires attacker-controlled configuration"})
        assessment = PolicyEngine(policy).check(claim)
        assert assessment.exclusions
        clause = assessment.exclusions[0].clause
        assert clause is not None
        assert clause.id == "x"
        assert "attacker-controlled" in clause.description

    def test_unknown_version_cannot_be_judged(self) -> None:
        claim = self._claim(affected_version="")
        assessment = PolicyEngine(self._policy()).check(claim)
        assert assessment.version_supported is None

    def test_empty_policy_is_permissive(self) -> None:
        assessment = PolicyEngine(Policy()).check(self._claim())
        assert assessment.component_in_scope is None
        assert assessment.version_supported is None
        assert not assessment.out_of_scope
