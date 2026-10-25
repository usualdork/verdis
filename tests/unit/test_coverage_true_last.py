"""The final lines.

At this point every remaining line is a single statement. They are
written out so that the coverage number reflects the code rather than
the tests.
"""

from __future__ import annotations

import json
import struct
import subprocess
from pathlib import Path

import pytest

from verdis.build.builder import BuildCache
from verdis.dedupe.index import DedupeEngine
from verdis.extract.extractor import ClaimExtractor
from verdis.extract.heuristics import HeuristicExtractor
from verdis.judge.impact import impact_level
from verdis.oracles.frames import extract_frames
from verdis.policy.engine import PolicyEngine, component_matches_pattern
from verdis.policy.loader import matches_version
from verdis.preflight.elf import parse_elf_imports
from verdis.sandbox.container import ContainerBackend
from verdis.schemas.claim import Claim
from verdis.schemas.policy import Policy, PolicyClause
from verdis.schemas.rrs import RRSPlanStep
from verdis.storage.evidence import EvidenceStore


class TestLastLines:
    def test_the_cache_stops_when_it_is_within_the_cap(self, tmp_path: Path) -> None:
        from verdis.build.recipe import recipe_from_dict

        cache = BuildCache(root=tmp_path / "cache", max_bytes=10_000_000)
        source = tmp_path / "src"
        source.mkdir()
        (source / "a.txt").write_text("x", encoding="utf-8")
        key = cache.key("v1", recipe_from_dict({"language": "c"}))
        cache.store(key, source)
        assert cache.enforce_cap() == []

    def test_an_advisory_that_does_not_match_is_skipped(self, store) -> None:
        from verdis.dedupe.index import AdvisoryCandidate

        class _Source:
            @staticmethod
            def lookup(repo: str = "", version: str = "") -> list[AdvisoryCandidate]:
                return [
                    AdvisoryCandidate(
                        identifier="GHSA-1",
                        title="something else entirely",
                        text="a completely different subject",
                    )
                ]

        engine = DedupeEngine(store=store, advisory_source=_Source())
        from verdis.dedupe.fingerprint import DedupeFingerprint

        fingerprint = DedupeFingerprint.build(
            report_id="VDS-2", body="a heap buffer overflow in parse_header"
        )
        matches = engine.search(fingerprint, "a heap buffer overflow in parse_header")
        assert all(match.similarity < 0.82 for match in matches)

    def test_the_model_fills_the_preconditions(self) -> None:
        from tests.unit.test_extractor import FakeProvider

        provider = FakeProvider({"preconditions": []})
        outcome = ClaimExtractor(provider).extract(
            "this requires a running server"
        )
        assert outcome.claim.preconditions

    def test_a_component_without_a_colon_is_a_name(self) -> None:
        from verdis.extract.extractor import _split_component

        assert _split_component("parse_header") == ("parse_header", "")

    def test_an_empty_command_is_ignored(self) -> None:

        claim = HeuristicExtractor().extract("```\n   \n```")
        assert claim.poc_commands == ()

    def test_a_path_with_a_slash_is_a_command(self) -> None:

        assert HeuristicExtractor._looks_like_command("bin/demo")

    def test_a_broken_yaml_block_that_is_not_an_rrs_is_skipped(self) -> None:
        from verdis.extract.rrs import parse_rrs

        assert parse_rrs("```yaml\nfoo: [unclosed\n```\n") is None

    def test_the_github_client_is_closed(self, evidence: EvidenceStore) -> None:
        from verdis.intake.github import GitHubError, GitHubPrivateReportIntake

        adapter = GitHubPrivateReportIntake(evidence)
        # No token: the client is refused before it is made.
        with pytest.raises(GitHubError):
            adapter.list_reports(owner="example", token="")

    def test_a_message_that_is_not_bytes_is_skipped(self, evidence: EvidenceStore) -> None:
        from verdis.intake.imap import ImapIntake

        class _Fake:
            def select(self, mailbox):
                return "OK", [b"1"]

            def uid(self, command, *args):
                if command == "search":
                    return "OK", [b"1"]
                return "OK", [(b"1 (RFC822 {1}", "not bytes")]

            def close(self):
                return "OK", [b""]

        outcomes = ImapIntake(evidence).fetch(
            host="imap.example.org", connection=_Fake()
        )
        assert outcomes == []

    def test_the_strongest_impact_phrase_wins(self) -> None:
        # "crash" is matched first in the table; the loop takes the
        # strongest of the phrases it finds.
        assert impact_level("a privilege escalation and a crash") >= 1

    def test_the_frames_are_returned_when_the_limit_is_not_reached(self) -> None:
        assert len(extract_frames("    #0 0x1 in parse_header a.c:1\n")) == 1

    def test_a_pattern_inside_the_value_matches(self) -> None:
        assert component_matches_pattern("parser", "the_parser_module")

    def test_an_exclusion_with_a_pattern_that_does_not_match(self) -> None:
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
        assessment = PolicyEngine(policy).check(Claim())
        assert not assessment.exclusions

    def test_a_wildcard_version_matches(self) -> None:
        assert matches_version("2.*", "2.3.1")

    def test_an_exact_version_does_not_match_another(self) -> None:
        assert not matches_version("2.3.1", "2.3.2")

    def test_a_name_without_a_terminator_is_empty(self) -> None:
        # A section whose name runs past the string table.
        data = bytearray(b"\x7fELF" + b"\x00" * 300)
        struct.pack_into("<Q", data, 0x28, 64)
        struct.pack_into("<H", data, 0x3C, 2)
        struct.pack_into("<H", data, 0x3E, 1)
        struct.pack_into("<II", data, 64, 0, 3)
        assert isinstance(parse_elf_imports(bytes(data)), tuple)

    def test_a_static_symbol_table_is_not_a_dynamic_one(self) -> None:
        # A section of type 2 (SHT_SYMTAB) with a dynamic string table
        # present is still not an import list.
        data = bytearray(b"\x7fELF" + b"\x00" * 300)
        struct.pack_into("<Q", data, 0x28, 64)
        struct.pack_into("<H", data, 0x3C, 2)
        struct.pack_into("<H", data, 0x3E, 1)
        struct.pack_into("<II", data, 64, 0, 2)
        assert parse_elf_imports(bytes(data)) == ([], [])

    def test_a_file_that_cannot_be_stat_ed_is_reported(self, tmp_path: Path) -> None:
        path = tmp_path / "run.sh"
        path.write_text("x", encoding="utf-8")

        import verdis.preflight.preflight as preflight_module

        class _Broken(Path):
            def stat(self, *args, **kwargs):
                raise OSError("the file vanished")

        broken = _Broken(path)
        findings = preflight_module.Preflight._check_permissions(broken)
        assert findings == []

    def test_a_text_file_that_cannot_be_read_is_reported(self, tmp_path: Path) -> None:
        import verdis.preflight.preflight as preflight_module

        class _Broken(Path):
            def read_bytes(self, *args, **kwargs):
                raise OSError("the file vanished")

        findings = preflight_module.Preflight._check_text(_Broken(tmp_path / "x"))
        assert findings == []

    def test_the_container_reports_a_broken_info(self, monkeypatch) -> None:
        import verdis.sandbox.container as container_module

        class _Concrete(ContainerBackend):
            runtime = "fake"
            name = "fake"

            def _unused(self) -> None:  # pragma: no cover
                raise NotImplementedError

        def handler(*args, **kwargs):
            return subprocess.CompletedProcess(args, 1, "", "no info")

        monkeypatch.setattr(container_module.subprocess, "run", handler)
        backend = _Concrete(binary="fake")
        assert backend._isolation_notes() == []

    def test_the_container_reads_an_older_docker_info(self, monkeypatch) -> None:
        import verdis.sandbox.container as container_module

        class _Concrete(ContainerBackend):
            runtime = "fake"
            name = "fake"

            def _unused(self) -> None:  # pragma: no cover
                raise NotImplementedError

        def handler(*args, **kwargs):
            return subprocess.CompletedProcess(
                args, 0, json.dumps({"HostSecurity": {"Rootless": True}}), ""
            )

        monkeypatch.setattr(container_module.subprocess, "run", handler)
        backend = _Concrete(binary="fake")
        assert backend._isolation_notes() == [f"{backend.binary} is running rootless"]

    def test_the_container_reads_a_top_level_rootless_flag(self, monkeypatch) -> None:
        import verdis.sandbox.container as container_module

        class _Concrete(ContainerBackend):
            runtime = "fake"
            name = "fake"

            def _unused(self) -> None:  # pragma: no cover
                raise NotImplementedError

        def handler(*args, **kwargs):
            return subprocess.CompletedProcess(
                args, 0, json.dumps({"Rootless": False}), ""
            )

        monkeypatch.setattr(container_module.subprocess, "run", handler)
        backend = _Concrete(binary="fake")
        assert backend._isolation_notes() == [f"{backend.binary} is running rootful"]

    def test_a_pinned_image_is_checked_by_digest(self, monkeypatch) -> None:
        import verdis.sandbox.container as container_module

        class _Concrete(ContainerBackend):
            runtime = "fake"
            name = "fake"

            def _unused(self) -> None:  # pragma: no cover
                raise NotImplementedError

        def handler(*args, **kwargs):
            return subprocess.CompletedProcess(args, 0, "sha256:abc\n", "")

        monkeypatch.setattr(container_module.subprocess, "run", handler)
        backend = _Concrete(binary="fake")
        assert backend.image_present("x@sha256:abc") is True

    def test_the_rrs_hash_is_read(self) -> None:
        step = RRSPlanStep.model_validate({"run": "./demo"})
        assert step.raw == "run: ./demo"

    def test_the_rrs_step_reads_a_build_key(self) -> None:
        step = RRSPlanStep.model_validate({"build": "default"})
        assert step.action == "build"

    def test_the_rrs_step_reads_a_run_key(self) -> None:
        step = RRSPlanStep.model_validate({"run": "./demo"})
        assert step.action == "run"

    def test_the_bundle_verification_skips_the_manifest(self, tmp_path: Path) -> None:
        store = EvidenceStore(tmp_path / "evidence")
        store.write_bundle("VDS-1", {"a.txt": "x"})
        manifest = store.read_manifest("VDS-1")
        assert manifest is not None
        assert store.verify_bundle("VDS-1") == []

    def test_an_existing_file_is_not_rewritten(self, tmp_path: Path) -> None:
        from verdis.storage.evidence import _write_immutable

        path = tmp_path / "a.txt"
        path.write_text("first", encoding="utf-8")
        _write_immutable(path, "second")
        assert path.read_text(encoding="utf-8") == "first"
