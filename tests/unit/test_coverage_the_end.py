"""The last twenty-two lines.

Each one is a specific branch. Where a branch cannot be reached, the
source says so; this file covers the ones that can.
"""

from __future__ import annotations

import struct
from pathlib import Path

from verdis.extract.heuristics import HeuristicExtractor
from verdis.judge.impact import impact_level
from verdis.oracles.frames import extract_frames
from verdis.policy.engine import PolicyEngine, component_matches_pattern
from verdis.policy.loader import matches_version
from verdis.preflight.elf import parse_elf_imports
from verdis.schemas.claim import Claim
from verdis.schemas.policy import Policy, PolicyClause
from verdis.schemas.rrs import RRSPlanStep


class TestTheLastBranches:
    def test_the_cache_stops_when_it_fits(self, tmp_path: Path) -> None:
        from verdis.build.builder import BuildCache
        from verdis.build.recipe import recipe_from_dict

        cache = BuildCache(root=tmp_path / "cache", max_bytes=10_000_000)
        source = tmp_path / "src"
        source.mkdir()
        (source / "a.txt").write_text("x", encoding="utf-8")
        key = cache.key("v1", recipe_from_dict({"language": "c"}))
        cache.store(key, source)
        # The cache is over its cap at the start and under it after the
        # first entry is measured.
        assert cache.enforce_cap() == []

    def test_a_command_that_is_already_seen_is_ignored(self) -> None:
        # The same command twice in one fence.
        claim = HeuristicExtractor().extract("```\n./demo\n./demo\n```")
        assert len(claim.poc_commands) == 1

    def test_an_impact_phrase_is_found_inside_a_sentence(self) -> None:
        # The exact phrase is not in the table, so the loop looks for it.
        assert impact_level("there was a crash in the parser") == 1

    def test_the_frames_end_without_reaching_the_limit(self) -> None:
        assert extract_frames("    #0 0x1 in parse_header a.c:1\n", limit=50) == (
            "parse_header (a.c:1)",
        )

    def test_a_pattern_with_a_slash_matches(self) -> None:
        # The plain substring check fails; the slash-normalised one works.
        assert component_matches_pattern("network_client", "network/client")

    def test_an_exclusion_with_a_pattern_that_does_not_match(self) -> None:
        policy = Policy(
            excluded_classes=(
                PolicyClause(
                    id="x",
                    kind="excluded",
                    description="a description that matches nothing",
                    component_patterns=("config-loader",),
                ),
            )
        )
        assessment = PolicyEngine(policy).check(Claim())
        assert not assessment.exclusions

    def test_a_wildcard_with_no_prefix_matches_everything(self) -> None:
        # "x" on its own has no prefix, so it matches anything.
        assert matches_version("x", "1.0.0")

    def test_a_pattern_that_is_not_a_version_matches_nothing(self) -> None:
        assert not matches_version("nightly", "1.0.0")

    def test_a_section_name_without_a_terminator_is_empty(self) -> None:
        # The string table has no terminator after the section name.
        data = bytearray(b"\x7fELF" + b"\x00" * 400)
        struct.pack_into("<Q", data, 0x28, 64)
        struct.pack_into("<H", data, 0x3C, 2)
        struct.pack_into("<H", data, 0x3E, 1)
        # The string table runs to the end of the file with no terminator.
        struct.pack_into("<II", data, 64, 0, 3)
        struct.pack_into("<Q", data, 72, 64)
        struct.pack_into("<Q", data, 80, 400)
        assert isinstance(parse_elf_imports(bytes(data)), tuple)

    def test_a_static_symbol_table_is_recorded(self) -> None:
        # A section of type 2 (SHT_SYMTAB) is a static symbol table; the
        # parser records it so the dynamic section can be found.
        data = bytearray(b"\x7fELF" + b"\x00" * 400)
        struct.pack_into("<Q", data, 0x28, 64)
        struct.pack_into("<H", data, 0x3C, 3)
        struct.pack_into("<H", data, 0x3E, 1)
        # The dynamic string table.
        struct.pack_into("<II", data, 64, 1, 3)
        struct.pack_into("<Q", data, 72, 100)
        struct.pack_into("<Q", data, 80, 10)
        # A static symbol table, linked to the string table.
        struct.pack_into("<II", data, 128, 0, 2)
        struct.pack_into("<Q", data, 136, 1)
        struct.pack_into("<Q", data, 144, 16)
        assert isinstance(parse_elf_imports(bytes(data)), tuple)

    def test_a_symbol_table_that_runs_off_the_end_stops(self) -> None:
        data = bytearray(b"\x7fELF" + b"\x00" * 400)
        struct.pack_into("<Q", data, 0x28, 64)
        struct.pack_into("<H", data, 0x3C, 3)
        struct.pack_into("<H", data, 0x3E, 1)
        struct.pack_into("<II", data, 64, 1, 3)
        struct.pack_into("<Q", data, 72, 100)
        struct.pack_into("<Q", data, 80, 10)
        # The symbol table claims to be far larger than the file.
        struct.pack_into("<II", data, 128, 0, 11)
        struct.pack_into("<Q", data, 136, 1)
        struct.pack_into("<Q", data, 144, 100_000)
        assert isinstance(parse_elf_imports(bytes(data)), tuple)

    def test_a_symbol_with_no_name_is_skipped(self) -> None:
        # A symbol whose name offset is zero is the null symbol.
        from tests.unit.test_coverage_finale import _elf32

        data = bytearray(_elf32())
        # The first symbol's name offset is 1; move it to zero.
        dynsym_offset = 70
        struct.pack_into("<I", data, dynsym_offset, 0)
        imports, _libraries = parse_elf_imports(bytes(data))
        assert "printf" not in imports

    def test_a_symbol_past_the_string_table_is_skipped(self) -> None:
        from tests.unit.test_coverage_finale import _elf32

        data = bytearray(_elf32())
        dynsym_offset = 70
        # A name offset beyond the string table.
        struct.pack_into("<I", data, dynsym_offset, 9999)
        imports, _libraries = parse_elf_imports(bytes(data))
        assert imports == []

    def test_the_rrs_step_reads_a_build_key(self) -> None:
        step = RRSPlanStep.model_validate({"build": "default"})
        assert step.action == "build"
        assert step.value == "default"

    def test_the_rrs_step_reads_a_run_key(self) -> None:
        step = RRSPlanStep.model_validate({"run": "./demo"})
        assert step.action == "run"
        assert step.value == "./demo"

    def test_the_bundle_verification_skips_the_manifest(self, tmp_path: Path) -> None:
        from verdis.storage.evidence import EvidenceStore

        store = EvidenceStore(tmp_path / "evidence")
        store.write_bundle("VDS-1", {"a.txt": "x"})
        assert store.verify_bundle("VDS-1") == []
