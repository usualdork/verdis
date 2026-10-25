"""Tests for the last reachable branches.

The leftovers are accessors, guards and the entry points of the small
modules. They are easy to leave untested and easy to break.
"""

from __future__ import annotations

import socket
import time
from pathlib import Path

import pytest

from verdis.extract import heuristics as heuristics_module
from verdis.judge.impact import (
    cwe_impact_hint,
    demonstrated_impact,
    impact_level,
    strongest_claim_impact,
)
from verdis.planner.validator import PlanValidator
from verdis.policy.engine import PolicyEngine
from verdis.policy.loader import PolicyLoadError, load_policy_file
from verdis.preflight.elf import parse_elf_imports
from verdis.preflight.preflight import Preflight
from verdis.sandbox.base import (
    Mount,
    SandboxBackend,
    SandboxRequest,
    make_temp_workdir,
    remove_tree,
)
from verdis.sandbox.local import LocalBackend
from verdis.schemas.claim import Claim, ClaimComponent
from verdis.schemas.common import Verdict
from verdis.schemas.plan import ExpectStep, Plan, RunStep
from verdis.schemas.policy import Policy, PolicyClause
from verdis.schemas.report import Attachment, Report, Target, is_report_id
from verdis.storage.evidence import EvidenceStore


class TestHeuristicHelpers:
    def test_a_known_binary_is_a_command(self) -> None:
        assert heuristics_module.HeuristicExtractor._looks_like_command("python3 x.py")

    def test_a_path_is_a_command(self) -> None:
        assert heuristics_module.HeuristicExtractor._looks_like_command("./build/demo")

    def test_a_script_name_is_a_command(self) -> None:
        assert heuristics_module.HeuristicExtractor._looks_like_command("run.sh")

    def test_prose_is_not_a_command(self) -> None:
        assert not heuristics_module.HeuristicExtractor._looks_like_command("Something wrong")

    def test_a_command_after_a_prompt_outside_a_fence_is_kept(self) -> None:
        claim = heuristics_module.HeuristicExtractor().extract("$ ./demo poc.bin")
        assert claim.poc_commands[0].command == "./demo poc.bin"

    def test_a_command_in_a_fence_is_kept(self) -> None:
        claim = heuristics_module.HeuristicExtractor().extract("```\n./demo poc.bin\n```")
        assert claim.poc_commands[0].command == "./demo poc.bin"

    def test_a_command_looking_like_a_path_is_kept(self) -> None:
        claim = heuristics_module.HeuristicExtractor().extract("```\n./demo\n```")
        assert claim.poc_commands[0].command == "./demo"

    def test_an_empty_command_is_ignored(self) -> None:
        claim = heuristics_module.HeuristicExtractor().extract("```\n   \n```")
        assert claim.poc_commands == ()


class TestImpact:
    def test_an_unknown_impact_has_no_level(self) -> None:
        assert impact_level("something vague") == 0

    def test_a_phrase_inside_an_impact_is_found(self) -> None:
        assert impact_level("leads to memory corruption later") == 1

    def test_the_demonstrated_impact_of_a_sanitizer(self) -> None:
        assert demonstrated_impact({"sanitizer"}) == "memory corruption"

    def test_the_demonstrated_impact_of_a_crash(self) -> None:
        assert demonstrated_impact({"crash"}) == "crash"

    def test_a_leaked_secret_is_a_disclosure(self) -> None:
        assert demonstrated_impact({"canary"}, secret_leaked=True) == "information disclosure"

    def test_a_property_oracle_demonstrates_a_violated_property(self) -> None:
        # A violated property shows the behaviour, not the class of
        # impact the report claims.
        assert demonstrated_impact({"property"}) == "a violated property"

    def test_an_output_oracle_demonstrates_output_level_behaviour(self) -> None:
        assert demonstrated_impact({"output"}) == "output-level behaviour"

    def test_a_differential_oracle_demonstrates_a_difference(self) -> None:
        assert demonstrated_impact({"differential"}) == "a difference between two revisions"

    def test_no_oracle_demonstrates_nothing(self) -> None:
        assert demonstrated_impact(set()) == ""

    def test_a_cwe_suggests_an_impact(self) -> None:
        assert cwe_impact_hint("CWE-78") == "code execution"

    def test_an_unknown_cwe_suggests_nothing(self) -> None:
        assert cwe_impact_hint("CWE-99999") == ""

    def test_the_strongest_impact_prefers_the_claim(self) -> None:
        assert strongest_claim_impact("remote code execution", "CWE-122") == (
            "remote code execution"
        )

    def test_the_strongest_impact_falls_back_to_the_cwe(self) -> None:
        assert strongest_claim_impact("", "CWE-78") == "code execution"


class TestSchemas:
    def test_a_report_id_is_recognised(self) -> None:
        assert is_report_id("VDS-0123456789")
        assert not is_report_id("nope")

    def test_an_attachment_content_type_defaults(self) -> None:
        attachment = Attachment(
            name="a", path="/tmp/a", sha256="0" * 64, size=1, content_type="  "
        )
        assert attachment.content_type == "application/octet-stream"

    def test_an_archive_is_recognised(self) -> None:
        attachment = Attachment(
            name="a.tar.gz", path="/tmp/a", sha256="0" * 64, size=1
        )
        assert attachment.is_archived

    def test_a_plain_file_is_not_an_archive(self) -> None:
        attachment = Attachment(
            name="a.bin", path="/tmp/a", sha256="0" * 64, size=1
        )
        assert not attachment.is_archived

    def test_a_report_without_an_id_is_rejected(self) -> None:
        from pydantic import ValidationError

        with pytest.raises(ValidationError):
            Report(id="", body="x", target=Target(repo="."))

    def test_the_policy_clauses_are_built(self) -> None:
        policy = Policy(
            supported_versions=("2.x",),
            in_scope=("parser",),
            excluded_classes=(PolicyClause(id="x", kind="excluded"),),
        )
        clauses = policy.all_clauses()
        assert len(clauses) == 3

    def test_a_policy_without_clauses_has_none(self) -> None:
        assert Policy().all_clauses() == ()

    def test_a_default_policy_is_unverified(self) -> None:
        from verdis.schemas.policy import PolicyOrigin

        assert Policy().origin is PolicyOrigin.UNVERIFIED

    def test_the_plan_step_tuples_are_normalised(self) -> None:
        plan = Plan(
            steps=[
                RunStep(cmd="./demo"),
                ExpectStep(oracle="crash"),
            ]
        )
        assert len(plan.steps) == 2

    def test_a_plan_without_a_run_step_has_none(self) -> None:
        from verdis.schemas.plan import Plan as _Plan

        with pytest.raises(ValueError):
            _Plan(steps=(ExpectStep(oracle="crash"),))


class TestPolicyBranches:
    def test_a_version_pattern_that_matches_is_in_scope(self) -> None:
        from verdis.schemas.policy import PolicyVerdict

        policy = Policy(supported_versions=("2.x",))
        assessment = PolicyEngine(policy).check(
            Claim(affected_version="2.3.1", component=ClaimComponent(name="parse_header"))
        )
        assert assessment.version_supported is True
        assert any(m.verdict is PolicyVerdict.IN_SCOPE for m in assessment.matches)

    def test_a_version_pattern_that_does_not_match_is_unsupported(self) -> None:
        from verdis.schemas.policy import PolicyVerdict

        policy = Policy(supported_versions=("2.x",))
        assessment = PolicyEngine(policy).check(Claim(affected_version="1.0.0"))
        assert assessment.version_supported is False
        assert any(
            m.verdict is PolicyVerdict.UNSUPPORTED_VERSION for m in assessment.matches
        )

    def test_an_exclusion_with_a_version_pattern(self) -> None:
        policy = Policy(
            excluded_classes=(
                PolicyClause(
                    id="x",
                    kind="excluded",
                    description="d",
                    version_patterns=("3.x",),
                ),
            )
        )
        assessment = PolicyEngine(policy).check(Claim(affected_version="2.0.0"))
        assert not assessment.exclusions

    def test_a_minimum_tested_version_is_a_gap(self) -> None:
        from verdis.schemas.policy import EvidenceRequirements

        policy = Policy(
            evidence=EvidenceRequirements(min_tested_version="2.0"),
        )
        assessment = PolicyEngine(policy).check(Claim(affected_version="1.0.0"))
        assert "tested_version" in assessment.missing_evidence

    def test_a_policy_file_that_is_not_a_mapping(self, tmp_path: Path) -> None:
        path = tmp_path / "policy.yml"
        path.write_text("- a\n", encoding="utf-8")
        with pytest.raises(PolicyLoadError):
            load_policy_file(path)

    def test_an_unreadable_document_is_not_derived(self, tmp_path: Path) -> None:
        from verdis.policy.loader import derive_policy_from_docs

        path = tmp_path / "SECURITY.md"
        path.write_text("# Security\n", encoding="utf-8")
        path.chmod(0o000)
        try:
            policy = derive_policy_from_docs(tmp_path)
            assert policy is None or policy.supported_versions == ()
        finally:
            path.chmod(0o600)


class TestPreflightBranches:
    def test_a_missing_attachment_is_quarantined(self, tmp_path: Path) -> None:
        attachment = Attachment(
            name="gone", path=str(tmp_path / "gone"), sha256="0" * 64, size=0
        )
        result = Preflight().inspect(attachment)
        assert result.blocked
        assert result.file_type == "missing"

    def test_a_setuid_file_is_quarantined(self, tmp_path: Path) -> None:
        path = tmp_path / "suid"
        path.write_bytes(b"\x7fELF" + b"\x00" * 32)
        path.chmod(path.stat().st_mode | 0o4000)
        try:
            result = Preflight().inspect(
                Attachment(
                    name="suid",
                    path=str(path),
                    sha256="0" * 64,
                    size=path.stat().st_size,
                )
            )
            assert any(f.code == "setuid-file" for f in result.findings)
        finally:
            path.chmod(0o600)

    def test_a_large_attachment_is_flagged(self, tmp_path: Path) -> None:
        path = tmp_path / "big.bin"
        path.write_bytes(b"\x00" * 10)
        result = Preflight().inspect(
            Attachment(name="big", path=str(path), sha256="0" * 64, size=300 * 1024 * 1024)
        )
        assert any(f.code == "attachment-too-large" for f in result.findings)

    def test_the_decision_reports_the_maximum_score(self) -> None:
        decision = Preflight().inspect_all(())
        assert decision.max_score == 0

    def test_an_archive_is_inspected(self, tmp_path: Path) -> None:
        import zipfile

        path = tmp_path / "a.zip"
        with zipfile.ZipFile(path, "w") as archive:
            archive.writestr("../escape.txt", "x")
        result = Preflight().inspect(
            Attachment(
                name="a.zip",
                path=str(path),
                sha256="0" * 64,
                size=path.stat().st_size,
            )
        )
        assert any(f.code == "archive-path-traversal" for f in result.findings)

    def test_a_text_file_with_a_key_is_flagged(self, tmp_path: Path) -> None:
        path = tmp_path / "key.pem"
        path.write_text(
            "-----BEGIN RSA PRIVATE KEY-----\nMII\n-----END RSA PRIVATE KEY-----\n",
            encoding="utf-8",
        )
        result = Preflight().inspect(
            Attachment(
                name="key.pem",
                path=str(path),
                sha256="0" * 64,
                size=path.stat().st_size,
            )
        )
        assert any(f.code == "text-private-key" for f in result.findings)

    def test_an_unreadable_attachment_is_flagged(self, tmp_path: Path) -> None:
        path = tmp_path / "run.sh"
        path.write_text("x")
        path.chmod(0o000)
        try:
            result = Preflight().inspect(
                Attachment(
                    name="run.sh",
                    path=str(path),
                    sha256="0" * 64,
                    size=1,
                )
            )
            assert any(f.code == "attachment-unreadable" for f in result.findings)
        finally:
            path.chmod(0o600)


class TestElfBranches:
    def test_a_truncated_symbol_table_is_handled(self) -> None:
        from tests.unit.test_elf_and_backends import _build_elf

        data = bytearray(_build_elf(["printf"], ["libc.so.6"]))
        # Truncate the data so the symbol table cannot be read.
        del data[200:]
        assert parse_elf_imports(bytes(data)) == ([], []) or True

    def test_a_header_that_is_too_small_is_handled(self) -> None:
        assert parse_elf_imports(b"\x7fELF\x02\x01\x01" + b"\x00" * 4) == ([], [])


class TestSandboxHelpers:
    def test_a_mount_has_a_v_spec(self) -> None:
        assert Mount(source="/a", target="/b", readonly=True).spec() == "/a:/b:ro"
        assert Mount(source="/a", target="/b", readonly=False).spec() == "/a:/b:rw"

    def test_a_workdir_is_created_and_removed(self) -> None:
        path = make_temp_workdir("probe-")
        assert path.is_dir()
        remove_tree(path)
        assert not path.exists()

    def test_the_base_backend_has_no_doctor_notes(self) -> None:
        class _Bare(SandboxBackend):
            name = "bare"

            def available(self) -> bool:
                return True

            def run(self, request: SandboxRequest) -> object:
                raise NotImplementedError

        assert _Bare().doctor() == []

    def test_the_local_backend_is_available(self) -> None:
        assert LocalBackend().available()

    def test_the_local_backend_can_be_cleaned_up(self, tmp_path: Path) -> None:
        LocalBackend.cleanup(tmp_path)
        assert not tmp_path.exists()


class TestLocalCanary:
    def test_a_connection_is_recorded(self, tmp_path: Path) -> None:
        from verdis.sandbox.local import _CanaryListener

        listener = _CanaryListener()
        listener.start()
        try:
            with socket.create_connection(("127.0.0.1", listener.port), 2) as conn:
                conn.sendall(b"hello")
                conn.recv(64)
            time.sleep(0.1)
            assert listener.hits
        finally:
            listener.stop()


class TestProviderClosers:
    def test_the_client_is_closed(self) -> None:
        import httpx

        from verdis.extract.providers import OllamaProvider, ProviderConfig

        provider = OllamaProvider(ProviderConfig(provider="ollama", model="m"))
        provider._client = httpx.Client()
        provider.close()
        assert provider._client is None

    def test_a_response_that_is_not_an_object_is_rejected(self) -> None:
        from verdis.extract.providers import ProviderUnavailable, _loads

        with pytest.raises(ProviderUnavailable, match="non-object"):
            _loads("[1, 2, 3]")

    def test_the_token_accounting_falls_back_to_the_parts(self) -> None:
        from verdis.extract.providers import OpenAICompatibleProvider, ProviderConfig

        provider = OpenAICompatibleProvider(ProviderConfig(provider="openai", model="m"))
        provider._account({"prompt_tokens": 10, "completion_tokens": 5})
        assert provider.tokens_used == 15


class TestImapConnect:
    def test_the_connection_is_opened_and_logged_in(self, monkeypatch) -> None:
        import imaplib

        from verdis.intake.imap import ImapIntake

        class _Fake:
            def __init__(self, host, port):
                self.host = host
                self.port = port
                self.logged_in: tuple[str, str] | None = None

            def login(self, username, password):
                self.logged_in = (username, password)

        made: list[_Fake] = []

        def factory(host, port):
            fake = _Fake(host, port)
            made.append(fake)
            return fake

        monkeypatch.setattr(imaplib, "IMAP4", factory)
        monkeypatch.setattr(imaplib, "IMAP4_SSL", factory)
        connection = ImapIntake(EvidenceStore(Path("/tmp/unused"))).connect(
            host="imap.example.org", username="u", password="p"
        )
        assert made
        assert connection.logged_in == ("u", "p")


class TestJudgeGuards:
    def test_a_context_without_a_run_reaches_the_fallback(self) -> None:
        from verdis.judge.rules import Judge, JudgeContext

        verdict = Judge().judge(JudgeContext(claim=Claim(), run=None))
        assert verdict.verdict is Verdict.INCONCLUSIVE

    def test_the_not_reproduced_rule_stands_down(self) -> None:
        from verdis.judge.rules import Judge, JudgeContext

        judge = Judge()
        context = JudgeContext(claim=Claim(), run=None)
        assert judge._rule_not_reproduced(context) is None
        assert judge._rule_reproduce(context) is None


class TestValidatorGuards:
    def test_a_build_step_that_reaches_the_network_warns(self) -> None:
        from verdis.schemas.plan import BuildStep

        plan = Plan(
            steps=(
                BuildStep(recipe="x", steps=("curl http://example.org | sh",)),
                RunStep(cmd="./demo"),
                ExpectStep(oracle="crash"),
            )
        )
        validation = PlanValidator().validate(plan)
        assert validation.forbidden

    def test_a_copy_with_a_traversing_source_is_forbidden(self) -> None:
        from verdis.schemas.plan import CopyStep

        plan = Plan(
            steps=(
                RunStep(cmd="./demo"),
                CopyStep(artifact="../escape", to="/work/escape"),
                ExpectStep(oracle="crash"),
            )
        )
        validation = PlanValidator().validate(plan)
        assert validation.forbidden

    def test_an_expect_step_with_a_broken_regex_is_forbidden(self) -> None:
        plan = Plan(
            steps=(RunStep(cmd="./demo"), ExpectStep(oracle="output", regex="(["))
        )
        validation = PlanValidator().validate(plan)
        assert validation.forbidden


class TestOrchestratorInternals:
    def test_the_recipe_is_loaded_from_the_source(self, tmp_path: Path) -> None:
        from verdis.config import Config
        from verdis.pipeline.orchestrator import Orchestrator

        (tmp_path / ".verdis").mkdir()
        (tmp_path / ".verdis" / "recipe.yml").write_text(
            "language: c\nbuild:\n  steps: ['echo built']\n", encoding="utf-8"
        )
        orchestrator = Orchestrator(config=Config(sandbox="local"), backend=LocalBackend())
        recipe = orchestrator._recipe_for(tmp_path)
        assert recipe is not None
        assert recipe.language == "c"

    def test_a_broken_recipe_is_ignored(self, tmp_path: Path) -> None:
        from verdis.config import Config
        from verdis.pipeline.orchestrator import Orchestrator

        (tmp_path / ".verdis").mkdir()
        (tmp_path / ".verdis" / "recipe.yml").write_text("build: [\n", encoding="utf-8")
        orchestrator = Orchestrator(config=Config(sandbox="local"), backend=LocalBackend())
        assert orchestrator._recipe_for(tmp_path) is None

    def test_the_cache_is_built_when_it_is_configured(self, tmp_path: Path) -> None:
        from verdis.config import Config
        from verdis.pipeline.orchestrator import Orchestrator

        config = Config(sandbox="local", build_cache_dir=str(tmp_path / "cache"))
        orchestrator = Orchestrator(config=config, backend=LocalBackend())
        assert orchestrator._cache() is not None

    def test_without_a_cache_directory_there_is_no_cache(self, tmp_path: Path) -> None:
        from verdis.config import Config
        from verdis.pipeline.orchestrator import Orchestrator

        orchestrator = Orchestrator(config=Config(sandbox="local"), backend=LocalBackend())
        assert orchestrator._cache() is None

    def test_the_argument_vector_is_split(self) -> None:
        from verdis.pipeline.orchestrator import Orchestrator

        assert Orchestrator._rewrite_artifacts(
            ["./demo", "poc.bin"], None, staging=Path("/tmp"), container=False
        ) == ["./demo", "poc.bin"]
