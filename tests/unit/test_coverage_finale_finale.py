"""The last nineteen lines, and the ones that cannot be reached.

A branch that cannot be reached is marked in the source, not left to
look like an untested path.
"""

from __future__ import annotations

import struct

from verdis.judge.impact import impact_level
from verdis.oracles.frames import extract_frames
from verdis.policy.engine import PolicyEngine
from verdis.policy.loader import matches_version
from verdis.preflight.elf import parse_elf_imports
from verdis.schemas.claim import Claim
from verdis.schemas.policy import Policy, PolicyClause
from verdis.schemas.rrs import RRSPlanStep


class TestTheLastNineteen:
    def test_an_impact_that_is_not_a_canonical_phrase(self) -> None:
        # "arbitrary file write" is in the level table but not in the
        # canonical-phrase map, so the loop is what finds it.
        assert impact_level("it leads to an arbitrary file write") == 3

    def test_the_frames_end_at_the_limit(self) -> None:
        output = "".join(
            f"    #{i} 0x{i} in symbol_{i} a.c:{i}\n" for i in range(5)
        )
        assert len(extract_frames(output, limit=3)) == 3

    def test_an_exclusion_with_no_description_does_not_match(self) -> None:
        policy = Policy(
            excluded_classes=(
                PolicyClause(id="x", kind="excluded", description=""),
            )
        )
        assessment = PolicyEngine(policy).check(Claim())
        assert not assessment.exclusions

    def test_a_wildcard_with_no_prefix_matches_everything(self) -> None:
        assert matches_version("*", "1.0.0")

    def test_a_section_name_without_a_terminator(self) -> None:
        # The string table has no terminator after the section name.
        data = bytearray(b"\x7fELF" + b"\x00" * 400)
        struct.pack_into("<Q", data, 0x28, 64)
        struct.pack_into("<H", data, 0x3C, 2)
        struct.pack_into("<H", data, 0x3E, 1)
        # The string table is the last thing in the file, with no "\x00".
        struct.pack_into("<II", data, 64, 0, 3)
        struct.pack_into("<Q", data, 72, 64)
        struct.pack_into("<Q", data, 80, 400)
        assert isinstance(parse_elf_imports(bytes(data)), tuple)

    def test_a_static_symbol_table_with_a_string_table(self) -> None:
        # A section of type 2 (SHT_SYMTAB) alongside a dynamic string
        # table: the parser records it so it can find the dynamic section.
        data = bytearray(b"\x7fELF" + b"\x00" * 400)
        struct.pack_into("<Q", data, 0x28, 64)
        struct.pack_into("<H", data, 0x3C, 3)
        struct.pack_into("<H", data, 0x3E, 1)
        struct.pack_into("<II", data, 64, 1, 3)
        struct.pack_into("<Q", data, 72, 100)
        struct.pack_into("<Q", data, 80, 10)
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
        struct.pack_into("<II", data, 128, 0, 11)
        struct.pack_into("<Q", data, 136, 1)
        struct.pack_into("<Q", data, 144, 100_000)
        assert isinstance(parse_elf_imports(bytes(data)), tuple)

    def test_a_symbol_name_without_a_terminator_is_skipped(self) -> None:
        from tests.unit.test_coverage_finale import _elf32

        data = bytearray(_elf32())
        dynstr_offset = 52
        # The name of the first symbol points at the very end of the
        # string table, where there is no terminator.
        struct.pack_into("<I", data, dynstr_offset + 1, 17)
        imports, _libraries = parse_elf_imports(bytes(data))
        assert "printf" not in imports

    def test_the_rrs_step_reads_a_build_key_among_others(self) -> None:
        step = RRSPlanStep.model_validate({"build": "default", "note": "x"})
        assert step.action == "build"
        assert step.value == "default"

    def test_the_rrs_step_reads_a_run_key_among_others(self) -> None:
        step = RRSPlanStep.model_validate({"run": "./demo", "note": "x"})
        assert step.action == "run"
        assert step.value == "./demo"
