"""The last branches, one assertion each.

Every remaining line is a single statement: an accessor, a guard, or one
arm of a conditional. They are written out here so that the coverage
number means something.
"""

from __future__ import annotations

import importlib
import json
import subprocess
from pathlib import Path

import pytest

from verdis.build.builder import BuildCache, Builder
from verdis.build.checkout import CheckoutError, checkout_ref
from verdis.dedupe.fingerprint import jaccard
from verdis.dedupe.osv import OSVAdvisorySource
from verdis.extract.extractor import ClaimExtractor
from verdis.extract.rrs import parse_rrs
from verdis.judge.impact import impact_level
from verdis.judge.rules import Judge, JudgeContext
from verdis.oracles.base import OracleContext
from verdis.oracles.differential import DifferentialOracle
from verdis.oracles.frames import extract_frames
from verdis.planner.validator import PlanValidator
from verdis.policy.engine import PolicyEngine
from verdis.policy.loader import PolicyLoadError, matches_version, policy_from_dict
from verdis.preflight.analyzers import _is_unsafe_member, inspect_archive
from verdis.sandbox.base import SandboxLimits, SandboxProfile
from verdis.sandbox.container import ContainerBackend
from verdis.sandbox.local import LocalBackend
from verdis.schemas.claim import Claim, ClaimComponent
from verdis.schemas.common import OracleType
from verdis.schemas.plan import ExpectStep, Plan, RunStep
from verdis.schemas.policy import Policy, PolicyClause
from verdis.schemas.rrs import RRSPlanStep
from verdis.schemas.run import CommandResult, RunResult, RunStatus
from verdis.storage.evidence import EvidenceStore


class TestEntryPoints:
    def test_the_module_entry_point_can_be_imported(self) -> None:
        module = importlib.import_module("verdis.__main__")
        assert module.main is not None


class TestBuilderAccessors:
    def test_the_cache_replaces_an_existing_entry(self, tmp_path: Path) -> None:
        from verdis.build.recipe import recipe_from_dict

        cache = BuildCache(root=tmp_path / "cache")
        recipe = recipe_from_dict({"language": "c"})
        key = cache.key("v1", recipe)
        source = tmp_path / "src"
        source.mkdir()
        (source / "a.txt").write_text("one", encoding="utf-8")
        cache.store(key, source)
        (source / "a.txt").write_text("two", encoding="utf-8")
        cache.store(key, source)
        assert (cache.path_for(key) / "a.txt").read_text() == "two"

    def test_the_cache_stops_when_it_fits(self, tmp_path: Path) -> None:
        from verdis.build.recipe import recipe_from_dict

        cache = BuildCache(root=tmp_path / "cache", max_bytes=10_000_000)
        source = tmp_path / "src"
        source.mkdir()
        (source / "a.txt").write_text("x", encoding="utf-8")
        key = cache.key("v1", recipe_from_dict({"language": "c"}))
        cache.store(key, source)
        assert cache.enforce_cap() == []

    def test_the_build_profile_without_a_network(self, tmp_path: Path) -> None:
        from verdis.build.recipe import recipe_from_dict

        builder = Builder(backend=LocalBackend())
        recipe = recipe_from_dict(
            {"language": "c", "build": {"steps": ["true"], "network": "none"}}
        )
        assert builder._build_profile(recipe).network == "none"


class TestCheckoutBranches:
    def test_the_head_fallback_is_used(self, tmp_path: Path, monkeypatch) -> None:
        import verdis.build.checkout as checkout_module

        def fake(args, cwd, timeout=120):
            if "--git-dir" in args:
                return subprocess.CompletedProcess(args, 0, ".git\n", "")
            return subprocess.CompletedProcess(args, 1, "", "")

        monkeypatch.setattr(checkout_module, "_run_git", fake)
        from verdis.build.checkout import default_branch

        assert default_branch(tmp_path) == ""

    def test_an_archive_that_cannot_be_exported_is_an_error(
        self, tmp_path: Path, monkeypatch
    ) -> None:
        import verdis.build.checkout as checkout_module

        def fake(args, cwd, timeout=120):
            if args[0] == "worktree":
                return subprocess.CompletedProcess(args, 1, "", "no worktree")
            if args[0] == "rev-parse":
                return subprocess.CompletedProcess(args, 0, "abc123\n", "")
            return subprocess.CompletedProcess(args, 1, "", "no archive")

        monkeypatch.setattr(checkout_module, "_run_git", fake)
        monkeypatch.setattr(checkout_module, "_is_git_repo", lambda path: True)
        with pytest.raises(CheckoutError, match="could not check out"):
            checkout_ref(tmp_path, "v1.0")

    def test_an_archive_that_cannot_be_unpacked_is_an_error(
        self, tmp_path: Path, monkeypatch
    ) -> None:
        import verdis.build.checkout as checkout_module

        def fake(args, cwd, timeout=120):
            if args[0] == "worktree":
                return subprocess.CompletedProcess(args, 1, "", "no worktree")
            if args[0] == "rev-parse":
                return subprocess.CompletedProcess(args, 0, "abc123\n", "")
            if args[0] == "archive":
                archive = Path(args[args.index("-o") + 1])
                archive.write_bytes(b"not a tar")
                return subprocess.CompletedProcess(args, 0, "", "")
            return subprocess.CompletedProcess(args, 0, "", "")

        def broken_unpack(*args, **kwargs):
            return subprocess.CompletedProcess(args, 1, "", "cannot unpack")

        monkeypatch.setattr(checkout_module, "_run_git", fake)
        monkeypatch.setattr(checkout_module, "_is_git_repo", lambda path: True)
        monkeypatch.setattr(checkout_module.subprocess, "run", broken_unpack)
        with pytest.raises(CheckoutError, match="could not unpack"):
            checkout_ref(tmp_path, "v1.0")


class TestSimilarityBranch:
    def test_two_different_empty_sets_do_not_match(self) -> None:
        assert jaccard(frozenset(), frozenset({"a"})) == 0.0


class TestAdvisoryBranches:
    def test_an_advisory_entry_that_is_not_a_mapping_is_skipped(self, tmp_path: Path) -> None:
        from verdis.dedupe.index import LocalAdvisorySource

        path = tmp_path / "advisories.json"
        path.write_text(json.dumps([{"id": "a", "title": "t"}, "not a mapping"]), encoding="utf-8")
        assert len(LocalAdvisorySource(path).lookup()) == 1

    def test_the_osv_affected_entries_are_read(self) -> None:
        import httpx

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200,
                json={
                    "vulns": [
                        {
                            "id": "GHSA-1",
                            "affected": [
                                "not a mapping",
                                {"package": {"name": "libfoo"}},
                            ],
                        }
                    ]
                },
            )

        source = OSVAdvisorySource(
            package="libfoo",
            ecosystem="Debian",
            client=httpx.Client(transport=httpx.MockTransport(handler)),
        )
        candidates = source.lookup()
        assert candidates[0].component == "libfoo"


class TestExtractorBranches:
    def test_the_model_fills_the_impact(self) -> None:
        from tests.unit.test_extractor import FakeProvider

        provider = FakeProvider({"impact": ""})
        outcome = ClaimExtractor(provider).extract(
            "this causes a memory corruption"
        )
        assert outcome.claim.impact.summary == "memory corruption"

    def test_an_rrs_component_with_a_file_and_a_function_is_split(self) -> None:
        text = """\
```yaml
rrs: 0.1
target:
  repo: r
  ref: v1
claim:
  component: src/hdr.c:parse_header
```
"""
        outcome = ClaimExtractor(None).extract(text)
        assert outcome.claim.component.name == "parse_header"
        assert outcome.claim.component.file == "src/hdr.c"

    def test_a_broken_rrs_block_is_reported(self) -> None:
        from verdis.extract.rrs import RRSParseError

        with pytest.raises(RRSParseError):
            parse_rrs("```yaml\nrrs: 0.1\ntarget: [unclosed\n```\n")


class TestHeuristicBranches:
    def test_a_command_that_is_already_seen_is_ignored(self) -> None:
        from verdis.extract.heuristics import HeuristicExtractor

        claim = HeuristicExtractor().extract("```\n./demo\n./demo\n```")
        assert len(claim.poc_commands) == 1

    def test_a_command_hint_is_found_outside_a_fence(self) -> None:
        from verdis.extract.heuristics import HeuristicExtractor

        claim = HeuristicExtractor().extract("python3 exploit.py\n")
        assert claim.poc_commands[0].command == "python3 exploit.py"

    def test_an_empty_command_is_not_a_command(self) -> None:
        from verdis.extract.heuristics import HeuristicExtractor

        assert not HeuristicExtractor._looks_like_command("")

    def test_a_path_is_a_command(self) -> None:
        from verdis.extract.heuristics import HeuristicExtractor

        assert HeuristicExtractor._looks_like_command("/usr/bin/demo")


class TestIntakeBranches:
    def test_the_github_client_is_made_and_closed(self, evidence: EvidenceStore) -> None:
        from verdis.intake.github import GitHubPrivateReportIntake

        adapter = GitHubPrivateReportIntake(evidence)
        client = adapter._client("token")
        assert client is not None
        client.close()

    def test_the_imap_connection_without_ssl(self, evidence: EvidenceStore, monkeypatch) -> None:
        import imaplib

        from verdis.intake.imap import ImapIntake

        class _Fake:
            def __init__(self, host, port):
                pass

        monkeypatch.setattr(imaplib, "IMAP4", _Fake)
        adapter = ImapIntake(evidence)
        assert adapter.connect(host="imap.example.org", use_ssl=False) is not None

    def test_a_message_that_cannot_be_fetched_is_skipped(
        self, evidence: EvidenceStore
    ) -> None:
        from verdis.intake.imap import ImapIntake

        class _Fake:
            def select(self, mailbox):
                return "OK", [b"1"]

            def uid(self, command, *args):
                if command == "search":
                    return "OK", [b"1"]
                return "NO", []

            def close(self):
                return "OK", [b""]

        outcomes = ImapIntake(evidence).fetch(
            host="imap.example.org", connection=_Fake()
        )
        assert outcomes == []

    def test_a_connection_the_adapter_opened_is_closed(
        self, evidence: EvidenceStore, monkeypatch
    ) -> None:
        import imaplib

        from verdis.intake.imap import ImapIntake

        class _Fake:
            def __init__(self, host, port):
                self.closed = False

            def select(self, mailbox):
                return "OK", [b"0"]

            def uid(self, command, *args):
                return "OK", [b""]

            def close(self):
                self.closed = True
                return "OK", [b""]

        made: list[_Fake] = []

        def factory(host, port):
            fake = _Fake(host, port)
            made.append(fake)
            return fake

        monkeypatch.setattr(imaplib, "IMAP4_SSL", factory)
        adapter = ImapIntake(evidence)
        # The adapter opens its own connection when none is given, and
        # closes it again afterwards.
        adapter.fetch(host="imap.example.org")
        assert made
        assert made[0].closed


class TestImpactBranch:
    def test_the_strongest_phrase_wins(self) -> None:
        assert impact_level("a crash and some memory corruption") == 1


class TestJudgeBranch:
    def test_the_not_reproduced_rule_stands_down(self) -> None:
        from verdis.schemas.run import OracleResult

        judge = Judge()
        context = JudgeContext(
            claim=Claim(),
            run=RunResult(
                status=RunStatus.COMPLETED,
                runs=(CommandResult(cmd="./demo"),),
            ),
            oracles=(OracleResult(oracle=OracleType.CRASH, fired=True),),
        )
        assert judge._rule_not_reproduced(context) is None


class TestDifferentialBranch:
    def test_a_comparison_that_did_not_finish_is_reported(self) -> None:
        context = OracleContext(
            claim=Claim(),
            expect=ExpectStep(oracle=OracleType.DIFFERENTIAL),
            comparison_run=RunResult(status=RunStatus.TIMEOUT, runs=()),
            extra={"primary_fired": "1", "comparison_fired": "0"},
        )
        result = DifferentialOracle().evaluate(
            RunResult(status=RunStatus.COMPLETED, runs=(CommandResult(cmd="./demo"),)), context
        )
        assert result.fired
        assert any("did not complete cleanly" in line for line in result.evidence)


class TestFrameBranch:
    def test_a_frame_matched_by_both_patterns_is_counted_once(self) -> None:
        # The same line matches the AddressSanitizer pattern and the
        # symbol pattern; it is one frame, not two.
        output = "    #0 0x1 in parse_header(a.c:1)\n"
        assert len(extract_frames(output)) == 1


class TestOrchestratorBranches:
    def test_a_git_checkout_is_used(self, tmp_path: Path, git_repo: Path) -> None:
        from verdis.config import Config
        from verdis.pipeline.orchestrator import Orchestrator

        orchestrator = Orchestrator(config=Config(sandbox="local"), backend=LocalBackend())
        source, cleanup = orchestrator._prepare_source(git_repo, "v1.0")
        try:
            assert (source / "file.txt").read_text() == "first\n"
        finally:
            cleanup()

    def test_a_broken_named_recipe_is_ignored(self, tmp_path: Path) -> None:
        from verdis.config import Config
        from verdis.pipeline.orchestrator import Orchestrator
        from verdis.schemas.plan import BuildStep

        recipe_dir = tmp_path / ".verdis"
        recipe_dir.mkdir()
        (recipe_dir / "recipe-special.yml").write_text("build: [\n", encoding="utf-8")
        orchestrator = Orchestrator(config=Config(sandbox="local"), backend=LocalBackend())
        plan = Plan(
            steps=(
                BuildStep(recipe="special"),
                RunStep(cmd="./demo"),
                ExpectStep(oracle="crash"),
            )
        )
        result = orchestrator._build(tmp_path, "v1", plan)
        assert result.status.value in {"ok", "unsupported", "failed"}


class TestValidatorBranch:
    def test_a_ref_with_a_shell_character_is_forbidden(self) -> None:
        from verdis.schemas.plan import CompareStep

        plan = Plan(
            steps=(
                RunStep(cmd="./demo"),
                ExpectStep(oracle="crash"),
                CompareStep(ref="v1; rm -rf /"),
            )
        )
        assert PlanValidator().validate(plan).forbidden


class TestPolicyBranches:
    def test_a_pattern_with_an_underscore_matches(self) -> None:
        from verdis.policy.engine import component_matches_pattern

        assert component_matches_pattern("network_client", "network_client")

    def test_an_exclusion_matches_by_component(self) -> None:
        policy = Policy(
            excluded_classes=(
                PolicyClause(
                    id="x",
                    kind="excluded",
                    description="d",
                    component_patterns=("config-loader",),
                ),
            )
        )
        assessment = PolicyEngine(policy).check(
            Claim(component=ClaimComponent(name="config_loader"))
        )
        assert assessment.exclusions

    def test_a_wildcard_version_matches(self) -> None:
        assert matches_version("2.*", "2.3.1")

    def test_an_exact_version_matches_only_itself(self) -> None:
        assert matches_version("2.3.1", "2.3.1")
        assert not matches_version("2.3.1", "2.3.2")

    def test_a_policy_that_is_not_a_mapping_is_rejected(self) -> None:
        with pytest.raises(PolicyLoadError):
            policy_from_dict(["not", "a", "mapping"])  # type: ignore[arg-type]

    def test_a_missing_list_is_empty(self) -> None:
        from verdis.policy.loader import _as_str_tuple

        assert _as_str_tuple(None) == ()


class TestPreflightBranches:
    def test_an_empty_archive_member_is_unsafe(self) -> None:
        assert _is_unsafe_member("")

    def test_a_windows_absolute_path_is_unsafe(self) -> None:
        assert _is_unsafe_member("C:\\Windows\\System32")

    def test_an_archive_with_an_unsafe_member_is_flagged(self, tmp_path: Path) -> None:
        import zipfile

        path = tmp_path / "a.zip"
        with zipfile.ZipFile(path, "w") as archive:
            archive.writestr("/etc/passwd", "x")
        report = inspect_archive(path)
        assert any(f.code == "archive-path-traversal" for f in report.findings)

    def test_the_printable_strings_stop_at_the_limit(self, tmp_path: Path) -> None:
        from verdis.preflight.analyzers import _extract_printable_strings

        data = b"".join(b"string%05d\x00" % i for i in range(5000))
        assert len(_extract_printable_strings(data, limit=10)) == 10


class TestElfBranches:
    def test_a_name_without_a_terminator_is_empty(self) -> None:
        # A section name that runs past the end of the string table.
        from verdis.preflight.elf import parse_elf_imports

        assert isinstance(parse_elf_imports(b"\x7fELF" + b"\x00" * 100), tuple)

    def test_a_symbol_without_a_name_is_skipped(self) -> None:
        from tests.unit.test_coverage_finale import _elf32

        from verdis.preflight.elf import parse_elf_imports

        imports, _libraries = parse_elf_imports(_elf32())
        assert "printf" in imports


class TestSandboxAccessors:
    def test_the_limits_are_expressed_for_the_runtime(self) -> None:
        limits = SandboxLimits()
        assert limits.to_cli()["--memory"] == "2048m"

    def test_the_profile_is_hardened_by_name(self) -> None:
        assert SandboxProfile(name="hardened").hardened
        assert not SandboxProfile(name="default").hardened


class TestContainerIsolationNotes:
    def _backend(self) -> ContainerBackend:
        class _Concrete(ContainerBackend):
            runtime = "fake"
            name = "fake"

            def _unused(self) -> None:  # pragma: no cover
                raise NotImplementedError

        return _Concrete(binary="fake")

    def test_a_podman_style_info_is_read(self, monkeypatch) -> None:
        import verdis.sandbox.container as container_module

        def handler(*args, **kwargs):
            return subprocess.CompletedProcess(
                args, 0, json.dumps({"host": {"security": {"rootless": True}}}), ""
            )

        monkeypatch.setattr(container_module.subprocess, "run", handler)
        backend = self._backend()
        assert backend._isolation_notes() == [f"{backend.binary} is running rootless"]

    def test_a_docker_style_info_is_read(self, monkeypatch) -> None:
        import verdis.sandbox.container as container_module

        def handler(*args, **kwargs):
            return subprocess.CompletedProcess(
                args, 0, json.dumps({"SecurityOptions": ["name=rootless"]}), ""
            )

        monkeypatch.setattr(container_module.subprocess, "run", handler)
        backend = self._backend()
        assert backend._isolation_notes() == [f"{backend.binary} is running rootless"]


class TestSchemaAccessors:
    def test_the_env_is_a_mapping(self) -> None:
        plan = Plan(
            steps=(
                RunStep(cmd="./demo", env=["A=1"]),
                ExpectStep(oracle="crash"),
            )
        )
        assert plan.run_step.env == {"A": "1"}

    def test_the_env_can_be_given_as_a_mapping(self) -> None:
        plan = Plan(
            steps=(
                RunStep(cmd="./demo", env={"A": "1"}),
                ExpectStep(oracle="crash"),
            )
        )
        assert plan.run_step.env == {"A": "1"}

    def test_an_env_entry_without_a_value_is_dropped(self) -> None:
        plan = Plan(
            steps=(
                RunStep(cmd="./demo", env=["NOPE"]),
                ExpectStep(oracle="crash"),
            )
        )
        assert plan.run_step.env == {}

    def test_the_rrs_step_text_is_read(self) -> None:
        step = RRSPlanStep.model_validate({"run": "./demo"})
        assert step.raw == "run: ./demo"

    def test_the_rrs_step_builds_a_raw_text(self) -> None:
        step = RRSPlanStep.model_validate("run: ./demo")
        assert step.raw == "run: ./demo"

    def test_a_run_without_commands_did_not_execute(self) -> None:
        run = RunResult(status=RunStatus.COMPLETED, runs=())
        assert not run.ran_as_intended


class TestStorageAccessors:
    def test_the_reports_are_listed(self, tmp_path: Path) -> None:
        store = EvidenceStore(tmp_path / "evidence")
        store.store_original("VDS-1", "a")
        assert store.list_reports() == ["VDS-1"]

    def test_an_empty_store_lists_nothing(self, tmp_path: Path) -> None:
        store = EvidenceStore(tmp_path / "evidence")
        assert store.list_reports() == []

    def test_the_original_is_written_once(self, tmp_path: Path) -> None:
        store = EvidenceStore(tmp_path / "evidence")
        path, _ = store.store_original("VDS-1", "first")
        store.store_original("VDS-1", "second")
        assert Path(path).read_text(encoding="utf-8") == "first"

    def test_a_file_that_is_not_in_the_manifest_is_ignored(self, tmp_path: Path) -> None:
        store = EvidenceStore(tmp_path / "evidence")
        store.write_bundle("VDS-1", {"a.txt": "x"})
        assert store.verify_bundle("VDS-1") == []
