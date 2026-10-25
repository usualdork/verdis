"""The final branches: the 32-bit ELF path, the analyzers and the accessors."""

from __future__ import annotations

import struct
from pathlib import Path

from verdis.dedupe.fingerprint import cosine_similarity
from verdis.extract.rrs import parse_rrs
from verdis.judge.impact import impact_level
from verdis.preflight.analyzers import (
    detect_file_type,
    inspect_archive,
    inspect_binary,
    inspect_script,
)
from verdis.preflight.elf import parse_elf_imports
from verdis.schemas.plan import Plan, RunStep
from verdis.schemas.rrs import RRSPlanStep
from verdis.schemas.run import CommandResult, RunResult, RunStatus


def _elf32() -> bytes:
    """A 32-bit little-endian ELF with a dynamic symbol table."""
    header = bytearray(52)
    header[0:4] = b"\x7fELF"
    header[4] = 1  # 32-bit
    header[5] = 1  # little endian
    struct.pack_into("<I", header, 16, 3)  # e_type
    struct.pack_into("<I", header, 20, 3)  # e_machine
    struct.pack_into("<H", header, 46, 40)  # e_shentsize
    struct.pack_into("<H", header, 48, 5)  # e_shnum
    struct.pack_into("<H", header, 50, 3)  # e_shstrndx

    dynstr = b"\x00printf\x00libc.so.6\x00"
    dynsym = struct.pack("<IIIBBH", 1, 0, 0, 0, 0, 1)
    dynsym += struct.pack("<IIIBBH", 0, 0, 0, 0, 0, 0)
    shstrtab = b"\x00.dynstr\x00.dynsym\x00.shstrtab\x00.dynamic\x00"
    # A dynamic section with one DT_NEEDED entry: the library name.
    dynamic = struct.pack("<II", 1, 8)  # DT_NEEDED -> "libc.so.6"
    dynamic += struct.pack("<II", 0, 0)  # DT_NULL

    dynstr_offset = len(header)
    dynsym_offset = dynstr_offset + len(dynstr)
    shstr_offset = dynsym_offset + len(dynsym)
    dynamic_offset = shstr_offset + len(shstrtab)
    sections_offset = dynamic_offset + len(dynamic)
    struct.pack_into("<I", header, 32, sections_offset)  # e_shoff

    sections = b""
    sections += struct.pack("<IIIIIIIIII", 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
    sections += struct.pack(
        "<IIIIIIIIII", 1, 3, 0, 0, dynstr_offset, len(dynstr), 0, 0, 0, 0
    )
    sections += struct.pack(
        "<IIIIIIIIII", 9, 11, 0, 0, dynsym_offset, len(dynsym), 1, 0, 0, 16
    )
    sections += struct.pack(
        "<IIIIIIIIII", 17, 3, 0, 0, shstr_offset, len(shstrtab), 0, 0, 0, 0
    )
    sections += struct.pack(
        "<IIIIIIIIII", 27, 6, 0, 0, dynamic_offset, len(dynamic), 1, 0, 0, 8
    )
    assert len(sections) == 5 * 40
    return bytes(header) + dynstr + dynsym + shstrtab + dynamic + sections


class TestElf32:
    def test_the_32_bit_path_is_read(self) -> None:
        imports, libraries = parse_elf_imports(_elf32())
        assert "printf" in imports
        assert libraries == ["libc.so.6"]

    def test_a_truncated_32_bit_file_is_handled(self) -> None:
        data = _elf32()
        assert isinstance(parse_elf_imports(data[:60]), tuple)


class TestAnalyzers:
    def test_a_tar_is_detected(self, tmp_path: Path) -> None:
        import tarfile

        path = tmp_path / "a.tar"
        with tarfile.open(path, "w") as archive:
            info = tarfile.TarInfo("a.txt")
            info.size = 0
            archive.addfile(info)
        assert detect_file_type(path) == "tar"

    def test_too_many_entries_are_flagged(self, tmp_path: Path) -> None:
        import zipfile

        from verdis.preflight.analyzers import MAX_ARCHIVE_ENTRIES

        path = tmp_path / "many.zip"
        with zipfile.ZipFile(path, "w") as archive:
            for index in range(MAX_ARCHIVE_ENTRIES + 5):
                archive.writestr(f"file{index}.txt", "x")
        report = inspect_archive(path)
        assert any(f.code == "archive-too-many-entries" for f in report.findings)

    def test_the_printable_strings_are_capped(self, tmp_path: Path) -> None:
        path = tmp_path / "many.bin"
        path.write_bytes(b"".join(b"string%05d\x00" % i for i in range(2000)))
        report = inspect_binary(path)
        assert len(report.strings) <= 4000

    def test_an_unreadable_script_is_reported(self, tmp_path: Path) -> None:
        path = tmp_path / "run.sh"
        path.write_text("x")
        path.chmod(0o000)
        try:
            findings = inspect_script(path)
            assert any(f.code == "script-unreadable" for f in findings)
        finally:
            path.chmod(0o600)

    def test_an_unreadable_binary_is_reported(self, tmp_path: Path) -> None:
        path = tmp_path / "a.bin"
        path.write_bytes(b"\x7fELF" + b"\x00" * 32)
        path.chmod(0o000)
        try:
            report = inspect_binary(path)
            assert any(f.code == "binary-unreadable" for f in report.findings)
        finally:
            path.chmod(0o600)


class TestAccessors:
    def test_the_validation_serialises_to_a_dictionary(self) -> None:
        from verdis.planner.validator import PlanValidator
        from verdis.schemas.plan import ExpectStep

        plan = Plan(steps=(RunStep(cmd="./demo"), ExpectStep(oracle="crash")))
        payload = PlanValidator().validate(plan).to_dict()
        assert payload["ok"] is True

    def test_the_issue_serialises_to_a_dictionary(self) -> None:
        from verdis.planner.validator import PlanIssue, Severity

        issue = PlanIssue(severity=Severity.WARNING, code="x", message="m")
        assert issue.to_dict()["code"] == "x"

    def test_a_run_without_a_fire_is_reported(self) -> None:
        run = RunResult(
            status=RunStatus.COMPLETED,
            runs=(CommandResult(cmd="./demo", exit_code=0),),
        )
        assert not run.any_fired

    def test_the_cosine_of_an_empty_vector_is_zero(self) -> None:
        assert cosine_similarity((), (1.0,)) == 0.0

    def test_an_impact_with_a_phrase_is_found(self) -> None:
        assert impact_level("it is a memory corruption") == 1


class TestRrsStepShapes:
    def test_a_step_with_a_build_key(self) -> None:
        step = RRSPlanStep.model_validate({"build": "default"})
        assert step.action == "build"
        assert step.value == "default"

    def test_a_step_with_a_run_key(self) -> None:
        step = RRSPlanStep.model_validate({"run": "./demo"})
        assert step.action == "run"

    def test_a_step_that_is_kept_as_it_is(self) -> None:
        step = RRSPlanStep.model_validate({"action": "run", "value": "./demo"})
        assert step.action == "run"

    def test_a_block_that_is_not_a_mapping_is_skipped(self) -> None:
        assert parse_rrs("```yaml\n- one\n- two\n```\n") is None
