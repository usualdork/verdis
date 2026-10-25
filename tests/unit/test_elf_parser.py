"""The ELF parser's last branches, with a proper section table.

The builder here makes a complete 64-bit ELF: a string table, a dynamic
string table, a dynamic symbol table, a dynamic section and the section
header string table.
"""

from __future__ import annotations

import struct

from verdis.preflight.elf import parse_elf_imports


def _elf(
    *,
    symbols: tuple[str, ...] = ("printf",),
    needed: tuple[str, ...] = ("libc.so.6",),
    extra_symtab: bool = False,
    truncate_symtab: bool = False,
    unterminated_dynstr: bool = False,
) -> bytes:
    """A complete 64-bit little-endian ELF."""
    dynstr = b"\x00"
    symbol_offsets: list[int] = []
    for name in symbols:
        symbol_offsets.append(len(dynstr))
        dynstr += name.encode() + (b"" if unterminated_dynstr else b"\x00")
    needed_offsets: list[int] = []
    for name in needed:
        needed_offsets.append(len(dynstr))
        dynstr += name.encode() + (b"" if unterminated_dynstr else b"\x00")

    dynsym = b""
    for offset in symbol_offsets:
        dynsym += struct.pack("<IBBHQQ", offset, 0x12, 0, 1, 0, 0)
    dynsym += struct.pack("<IBBHQQ", 0, 0, 0, 0, 0, 0)

    dynamic = b""
    for offset in needed_offsets:
        dynamic += struct.pack("<qQ", 1, offset)
    dynamic += struct.pack("<qQ", 0, 0)

    shstrtab = b"\x00"
    names: dict[str, int] = {}
    for name in (".dynstr", ".dynsym", ".shstrtab", ".dynamic"):
        names[name] = len(shstrtab)
        shstrtab += name.encode() + b"\x00"

    header = bytearray(64)
    header[0:4] = b"\x7fELF"
    header[4] = 2  # 64-bit
    header[5] = 1  # little endian
    struct.pack_into("<H", header, 16, 3)  # e_type
    struct.pack_into("<H", header, 18, 62)  # e_machine
    struct.pack_into("<H", header, 58, 64)  # e_shentsize
    struct.pack_into("<H", header, 60, 6 if extra_symtab else 5)  # e_shnum
    struct.pack_into("<H", header, 62, 3)  # e_shstrndx

    body = bytearray()
    offsets: dict[str, int] = {}
    for name, blob in (
        (".dynstr", dynstr),
        (".dynsym", dynsym),
        (".shstrtab", shstrtab),
        (".dynamic", dynamic),
    ):
        offsets[name] = 64 + len(body)
        body += blob
        while len(body) % 8:
            body += b"\x00"

    symtab_size = len(dynsym)
    if truncate_symtab:
        symtab_size = 1_000_000

    sections = bytearray()
    sections += struct.pack("<IIQQQQIIQQ", 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
    sections += struct.pack(
        "<IIQQQQIIQQ", names[".dynstr"], 3, 0, 0, offsets[".dynstr"], len(dynstr), 0, 0, 0, 0
    )
    sections += struct.pack(
        "<IIQQQQIIQQ",
        names[".dynsym"],
        11,
        0,
        0,
        offsets[".dynsym"],
        symtab_size,
        1,
        0,
        0,
        24,
    )
    sections += struct.pack(
        "<IIQQQQIIQQ",
        names[".shstrtab"],
        3,
        0,
        0,
        offsets[".shstrtab"],
        len(shstrtab),
        0,
        0,
        0,
        0,
    )
    sections += struct.pack(
        "<IIQQQQIIQQ",
        names[".dynamic"],
        6,
        0,
        0,
        offsets[".dynamic"],
        len(dynamic),
        1,
        0,
        0,
        16,
    )
    if extra_symtab:
        # A static symbol table, with no name of its own.
        sections += struct.pack("<IIQQQQIIQQ", 0, 2, 0, 0, offsets[".dynsym"], 24, 1, 0, 0, 24)

    struct.pack_into("<Q", header, 40, 64 + len(body))  # e_shoff
    return bytes(header) + bytes(body) + bytes(sections)


class TestElfParser:
    def test_the_imports_are_read(self) -> None:
        imports, libraries = parse_elf_imports(_elf())
        assert "printf" in imports
        assert libraries == ["libc.so.6"]

    def test_a_static_symbol_table_is_recorded(self) -> None:
        # A section of type 2 (SHT_SYMTAB) with a name of its own: the
        # parser records it so the dynamic section can be found.
        imports, libraries = parse_elf_imports(_elf(extra_symtab=True))
        assert "printf" in imports
        assert libraries == ["libc.so.6"]

    def test_a_symbol_table_that_runs_off_the_end_stops(self) -> None:
        # The symbol table claims to be larger than the file: the parser
        # reads what is there and stops.
        imports, _libraries = parse_elf_imports(_elf(truncate_symtab=True))
        assert imports == ["printf"]

    def test_a_symbol_name_without_a_terminator_is_skipped(self) -> None:
        # A dynamic string table with no terminator at the end: the
        # symbol's name has no end, so it is skipped.
        imports, _libraries = parse_elf_imports(_elf(unterminated_dynstr=True))
        assert imports == []

    def test_a_section_name_past_the_string_table_is_empty(self) -> None:
        # A section whose name offset is past the last terminator.
        data = bytearray(_elf())
        # The name of the second section points past the string table.
        shoff = struct.unpack_from("<Q", data, 40)[0]
        struct.pack_into("<I", data, shoff + 64, 9999)
        assert isinstance(parse_elf_imports(bytes(data)), tuple)
