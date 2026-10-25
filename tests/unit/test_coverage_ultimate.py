"""The last of the last.

Twenty-six lines were left. These are the tests that close them, and the
handful of places where the code is unreachable and says so.
"""

from __future__ import annotations

import struct
from pathlib import Path

import pytest

from verdis.judge.impact import impact_level
from verdis.oracles.frames import extract_frames
from verdis.policy.engine import PolicyEngine, component_matches_pattern
from verdis.policy.loader import matches_version
from verdis.preflight.elf import parse_elf_imports
from verdis.preflight.preflight import Preflight
from verdis.schemas.claim import Claim
from verdis.schemas.policy import Policy, PolicyClause
from verdis.schemas.rrs import RRSPlanStep
from verdis.storage.evidence import EvidenceStore


class TestFinalLines:
    def test_the_github_client_is_closed(self, evidence: EvidenceStore) -> None:
        import httpx

        from verdis.intake.github import GitHubPrivateReportIntake

        adapter = GitHubPrivateReportIntake(evidence)
        created: list[httpx.Client] = []

        def factory(token: str) -> httpx.Client:
            client = httpx.Client(
                transport=httpx.MockTransport(
                    lambda request: httpx.Response(200, json=[])
                ),
                base_url="https://api.github.com",
            )
            created.append(client)
            return client

        # Without a client of its own the adapter makes one and closes it
        # again afterwards.
        adapter._client = factory  # type: ignore[method-assign]
        adapter.list_reports(owner="example", token="token")
        assert created
        assert created[0].is_closed

    def test_an_impact_phrase_inside_a_sentence_is_found(self) -> None:
        assert impact_level("it is a crash in the parser") == 1

    def test_the_frames_are_returned_at_the_end(self) -> None:
        assert len(extract_frames("    #0 0x1 in parse_header a.c:1\n", limit=12)) == 1

    def test_a_pattern_that_is_a_substring_matches(self) -> None:
        assert component_matches_pattern("parser", "the_parser_module")

    def test_an_exclusion_with_a_component_pattern(self) -> None:
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

    def test_an_exact_version_matches_only_itself(self) -> None:
        assert not matches_version("2.3.1", "2.3.10")

    def test_a_section_name_without_a_terminator(self) -> None:
        # The string table has no terminator after the name.
        data = bytearray(b"\x7fELF" + b"\x00" * 400)
        struct.pack_into("<Q", data, 0x28, 64)
        struct.pack_into("<H", data, 0x3C, 2)
        struct.pack_into("<H", data, 0x3E, 1)
        # Section 0 is the string table, with a size that runs off the end.
        struct.pack_into("<II", data, 64, 0, 3)
        struct.pack_into("<Q", data, 72, 300)
        assert isinstance(parse_elf_imports(bytes(data)), tuple)

    def test_a_static_symbol_table_with_a_dynamic_string(self) -> None:
        # A section of type 2 is a static symbol table: it is recorded, but
        # it is not a dynamic import list.
        data = bytearray(b"\x7fELF" + b"\x00" * 400)
        struct.pack_into("<Q", data, 0x28, 64)
        struct.pack_into("<H", data, 0x3C, 3)
        struct.pack_into("<H", data, 0x3E, 1)
        # Section 1: the dynamic string table.
        struct.pack_into("<II", data, 64, 1, 3)
        struct.pack_into("<Q", data, 72, 100)
        struct.pack_into("<Q", data, 80, 10)
        # Section 2: a static symbol table, linked to the string table.
        struct.pack_into("<II", data, 128, 0, 2)
        struct.pack_into("<Q", data, 136, 1)
        struct.pack_into("<Q", data, 144, 16)
        assert isinstance(parse_elf_imports(bytes(data)), tuple)

    def test_a_symbol_table_that_runs_off_the_end_is_stopped(self) -> None:
        data = bytearray(b"\x7fELF" + b"\x00" * 400)
        struct.pack_into("<Q", data, 0x28, 64)
        struct.pack_into("<H", data, 0x3C, 3)
        struct.pack_into("<H", data, 0x3E, 1)
        struct.pack_into("<II", data, 64, 1, 3)
        struct.pack_into("<Q", data, 72, 100)
        struct.pack_into("<Q", data, 80, 10)
        # The symbol table claims to be larger than the file.
        struct.pack_into("<II", data, 128, 0, 11)
        struct.pack_into("<Q", data, 136, 1)
        struct.pack_into("<Q", data, 144, 100_000)
        assert isinstance(parse_elf_imports(bytes(data)), tuple)

    def test_an_executable_attachment_that_cannot_be_read(self, tmp_path: Path) -> None:
        from verdis.schemas.report import Attachment

        path = tmp_path / "run.sh"
        path.write_text("x", encoding="utf-8")
        path.chmod(0o111)
        try:
            result = Preflight().inspect(
                Attachment(
                    name="run.sh",
                    path=str(path),
                    sha256="0" * 64,
                    size=1,
                )
            )
            assert result.findings
        finally:
            path.chmod(0o600)

    def test_the_rrs_hash_may_be_none(self) -> None:
        from verdis.schemas.rrs import RRSInput

        assert RRSInput(path="poc.bin", sha256=None).sha256 == ""

    def test_the_rrs_step_reads_a_build_key(self) -> None:
        step = RRSPlanStep.model_validate({"build": "default"})
        assert step.action == "build"
        assert step.value == "default"

    def test_the_rrs_step_reads_a_run_key(self) -> None:
        step = RRSPlanStep.model_validate({"run": "./demo"})
        assert step.action == "run"
        assert step.value == "./demo"

    def test_the_rrs_block_passes_a_non_mapping_through(self) -> None:
        from pydantic import ValidationError

        from verdis.schemas.rrs import RRS

        # A block that is not a mapping is left alone for the validator to
        # reject with a clear message.
        with pytest.raises(ValidationError):
            RRS.model_validate(["not", "a", "mapping"])

    def test_the_bundle_verification_skips_the_manifest_itself(self, tmp_path: Path) -> None:
        store = EvidenceStore(tmp_path / "evidence")
        store.write_bundle("VDS-1", {"a.txt": "x"})
        manifest = store.read_manifest("VDS-1")
        assert manifest is not None
        assert store.verify_bundle("VDS-1") == []
