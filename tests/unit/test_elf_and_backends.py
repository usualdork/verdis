"""Tests for the ELF import parser and the container backend plumbing.

The ELF parser is exercised against a synthetic but valid ELF file that
the test builds itself, so the test is portable and does not depend on
what the host platform's compiler happens to produce.
"""

from __future__ import annotations

import struct
import sys
from pathlib import Path

import pytest

from verdis.preflight.analyzers import inspect_binary
from verdis.preflight.elf import parse_elf_imports
from verdis.sandbox.base import SandboxRequest, SandboxResult
from verdis.sandbox.container import ContainerBackend, build_container_args


def _build_elf(symbols: list[str], libraries: list[str]) -> bytes:
    """Build a small but valid 64-bit little-endian ELF.

    The file has a section header string table, a ``.dynstr``, a
    ``.dynsym`` and a ``.dynamic`` section, which is everything the import
    parser needs.
    """
    dynstr = b"\x00"
    symbol_offsets: list[int] = []
    for name in symbols:
        symbol_offsets.append(len(dynstr))
        dynstr += name.encode("utf-8") + b"\x00"

    needed_offsets: list[int] = []
    for name in libraries:
        needed_offsets.append(len(dynstr))
        dynstr += name.encode("utf-8") + b"\x00"

    shstrtab = b"\x00"
    name_offsets: dict[str, int] = {}
    for name in (".dynstr", ".dynsym", ".dynamic", ".shstrtab"):
        name_offsets[name] = len(shstrtab)
        shstrtab += name.encode("utf-8") + b"\x00"

    dynsym = b""
    for offset in symbol_offsets:
        # st_name, st_info, st_other, st_shndx, st_value, st_size
        dynsym += struct.pack("<IBBHQQ", offset, 0x12, 0, 1, 0, 0)
    dynsym += struct.pack("<IBBHQQ", 0, 0, 0, 0, 0, 0)  # the null symbol

    dynamic = b""
    for offset in needed_offsets:
        dynamic += struct.pack("<qQ", 1, offset)  # DT_NEEDED
    dynamic += struct.pack("<qQ", 0, 0)  # DT_NULL

    header_size = 64
    section_size = 64
    body_start = header_size

    dynstr_offset = body_start
    dynsym_offset = dynstr_offset + len(dynstr)
    dynamic_offset = dynsym_offset + len(dynsym)
    shstr_offset = dynamic_offset + len(dynamic)
    sections_offset = shstr_offset + len(shstrtab)

    sections = [
        # name, type, offset, size, link
        (0, 0, 0, 0, 0),
        (name_offsets[".dynstr"], 3, dynstr_offset, len(dynstr), 0),
        (name_offsets[".dynsym"], 11, dynsym_offset, len(dynsym), 1),
        (name_offsets[".shstrtab"], 3, shstr_offset, len(shstrtab), 0),
        (name_offsets[".dynamic"], 6, dynamic_offset, len(dynamic), 1),
    ]

    header = bytearray()
    header += b"\x7fELF" + bytes([2, 1, 1, 0]) + b"\x00" * 8
    header += struct.pack(
        "<HHIQQQIHHHHHH",
        3,  # e_type: ET_DYN
        62,  # e_machine: x86-64
        1,  # e_version
        0,  # e_entry
        0,  # e_phoff
        sections_offset,  # e_shoff
        0,  # e_flags
        header_size,  # e_ehsize
        56,  # e_phentsize
        0,  # e_phnum
        section_size,  # e_shentsize
        len(sections),  # e_shnum
        3,  # e_shstrndx
    )
    assert len(header) == header_size, len(header)

    body = dynstr + dynsym + dynamic + shstrtab
    body += b"\x00" * (sections_offset - header_size - len(body))

    section_headers = b""
    for name, sh_type, offset, size, link in sections:
        section_headers += struct.pack(
            "<IIQQQQIIQQ", name, sh_type, 0, 0, offset, size, link, 0, 8, 0
        )

    return bytes(header) + body + section_headers


class TestElfParser:
    def test_it_extracts_dynamic_imports(self) -> None:
        data = _build_elf(["printf", "malloc", "free"], ["libc.so.6"])
        imports, libraries = parse_elf_imports(data)
        assert "printf" in imports
        assert "malloc" in imports
        assert libraries == ["libc.so.6"]

    def test_it_ignores_the_null_symbol(self) -> None:
        data = _build_elf(["printf"], [])
        imports, _libraries = parse_elf_imports(data)
        assert "" not in imports

    def test_it_returns_nothing_for_a_non_elf(self) -> None:
        assert parse_elf_imports(b"not an elf file at all") == ([], [])

    def test_it_returns_nothing_for_empty_data(self) -> None:
        assert parse_elf_imports(b"") == ([], [])

    def test_it_survives_a_truncated_elf(self) -> None:
        data = _build_elf(["printf"], ["libc.so.6"])
        assert parse_elf_imports(data[:100]) == ([], [])

    def test_it_survives_garbage_section_headers(self) -> None:
        data = bytearray(_build_elf(["printf"], ["libc.so.6"]))
        data[0x28:0x30] = b"\xff" * 8  # a nonsense e_shoff
        assert parse_elf_imports(bytes(data)) == ([], [])

    def test_the_binary_report_finds_the_imports(self, tmp_path: Path) -> None:
        binary = tmp_path / "fake.elf"
        binary.write_bytes(_build_elf(["printf", "socket"], ["libc.so.6"]))
        report = inspect_binary(binary)
        assert report.file_type == "elf"
        assert "printf" in report.imports
        assert any(f.code == "binary-network-imports" for f in report.findings)

    def test_a_packed_binary_is_reported(self, tmp_path: Path) -> None:
        binary = tmp_path / "packed.elf"
        binary.write_bytes(b"\x7fELF" + b"UPX!" + b"\x00" * 64)
        report = inspect_binary(binary)
        assert any(f.code == "binary-packed" for f in report.findings)


class TestContainerBackend:
    def _backend(self) -> ContainerBackend:
        class _Fake(ContainerBackend):
            runtime = "fake"
            name = "fake"

            def _unused(self) -> None:  # pragma: no cover
                raise NotImplementedError

        return _Fake(binary="fake-podman")

    def test_a_missing_binary_is_not_available(self) -> None:
        assert not self._backend().available()

    def test_doctor_reports_a_missing_binary(self) -> None:
        notes = self._backend().doctor()
        assert notes
        assert "PATH" in notes[0]

    def test_run_raises_without_a_runtime(self) -> None:
        from verdis.sandbox.base import SandboxError

        with pytest.raises(SandboxError):
            self._backend().run(SandboxRequest(image="alpine", command=["true"]))

    def test_the_arguments_are_ordered(self) -> None:
        request = SandboxRequest(
            image="alpine:3.20",
            command=["/bin/sh", "-c", "true"],
            env={"A": "1"},
        )
        args = build_container_args(request, "podman")
        assert args[0] == "podman"
        assert args[1] == "run"
        assert args[-1] == "true"
        assert "alpine:3.20" in args

    def test_the_image_comes_after_the_flags(self) -> None:
        request = SandboxRequest(
            image="alpine:3.20",
            command=["true"],
            extra_args=["--env", "X=1"],
        )
        args = build_container_args(request, "docker")
        image_index = args.index("alpine:3.20")
        assert image_index < len(args) - 1
        assert args[-1] == "true"

    def test_the_workdir_is_a_tmpfs(self) -> None:
        request = SandboxRequest(image="alpine", command=["true"], workdir="/work")
        args = build_container_args(request, "podman")
        tmpfs = [args[i + 1] for i, arg in enumerate(args) if arg == "--tmpfs"]
        assert any(entry.startswith("/work:") for entry in tmpfs)


class TestLocalBackendPlumbing:
    def test_the_result_reports_a_signal(self) -> None:
        result = SandboxResult(exit_code=-11)
        assert result.signal == 11
        assert result.crashed

    def test_a_clean_exit_has_no_signal(self) -> None:
        assert SandboxResult(exit_code=0).signal is None

    def test_a_missing_program_is_reported(self, tmp_path: Path) -> None:
        from verdis.sandbox.local import LocalBackend

        backend = LocalBackend()
        result = backend.run(
            SandboxRequest(
                image="",
                command=["/nonexistent/binary"],
                workdir_source=str(tmp_path),
            )
        )
        assert result.exit_code != 0
        assert result.error


_ = sys
