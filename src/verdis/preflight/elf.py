"""Reading the dynamic imports of an ELF binary (FR-5.1).

The parser is deliberately small and read-only: it reads the section
headers and the dynamic symbol table, and it never loads or runs the
binary. A file that is not an ELF, or an ELF it cannot make sense of, is
reported as having no imports rather than as an error.
"""

from __future__ import annotations

import struct

__all__ = ["parse_elf_imports"]


def parse_elf_imports(data: bytes) -> tuple[list[str], list[str]]:
    """Extract imported symbol names and needed libraries from an ELF file.

    Returns ``(imports, libraries)``. Only dynamic (runtime) imports are
    considered; static symbols are not a meaningful signal.
    """
    if len(data) < 64 or data[:4] != b"\x7fELF":
        return [], []
    is_64 = data[4] == 2
    little = data[5] == 1
    endian = "<" if little else ">"

    try:
        if is_64:
            e_shoff, = struct.unpack_from(endian + "Q", data, 0x28)
            e_shentsize, e_shnum, e_shstrndx = struct.unpack_from(endian + "HHH", data, 0x3A)
            struct.unpack_from(endian + "Q", data, 0x20)  # e_phoff
            struct.unpack_from(endian + "HH", data, 0x36)  # e_phentsize, e_phnum
        else:
            e_shoff, = struct.unpack_from(endian + "I", data, 0x20)
            e_shentsize, e_shnum, e_shstrndx = struct.unpack_from(endian + "HHH", data, 0x2E)
            struct.unpack_from(endian + "I", data, 0x1C)  # e_phoff
            struct.unpack_from(endian + "HH", data, 0x2A)  # e_phentsize, e_phnum
    except struct.error:  # pragma: no cover - a truncated header
        return [], []

    if e_shoff == 0 or e_shnum == 0:
        return [], []

    sections: list[tuple[int, int, int, int, int]] = []
    for index in range(e_shnum):
        offset = e_shoff + index * e_shentsize
        if offset + e_shentsize > len(data):
            break
        if is_64:
            sh_name, sh_type, _flags, _sh_addr, sh_offset, sh_size, sh_link, _info, _align, _sh_entsize = struct.unpack_from(
                endian + "IIQQQQIIQQ", data, offset
            )
        else:
            sh_name, sh_type, _flags, _sh_addr, sh_offset, sh_size, sh_link, _info, _align, _sh_entsize = struct.unpack_from(
                endian + "IIIIIIIIII", data, offset
            )
        sections.append((sh_name, sh_type, sh_offset, sh_size, sh_link))

    if e_shstrndx >= len(sections):
        return [], []
    _, _, shstr_off, shstr_size, _ = sections[e_shstrndx]
    shstrtab = data[shstr_off : shstr_off + shstr_size]

    def name_at(offset: int) -> str:
        end = shstrtab.find(b"\x00", offset)
        if end < 0:
            return ""
        return shstrtab[offset:end].decode("utf-8", errors="replace")

    dynstr: bytes = b""
    dynsym_offset = 0
    dynsym_size = 0
    dynsym_entsize = 24 if is_64 else 16
    dynamic: list[tuple[int, int]] = []
    for sh_name, sh_type, sh_offset, sh_size, sh_link in sections:
        name = name_at(sh_name)
        if name == ".dynstr":
            dynstr = data[sh_offset : sh_offset + sh_size]
        elif name == ".dynsym":
            dynsym_offset, dynsym_size = sh_offset, sh_size
        elif name == ".dynamic":
            # A dynamic entry is a tag and a value. They are 8 bytes wide
            # on both classes, but a 32-bit tag is 4 bytes, not 8.
            entry_format = endian + ("qQ" if is_64 else "iI")
            for pos in range(sh_offset, sh_offset + sh_size, 8):
                try:
                    tag, val = struct.unpack_from(entry_format, data, pos)
                except struct.error:  # pragma: no cover - a truncated entry
                    break
                if tag == 0:
                    break
                dynamic.append((tag, val))
        elif sh_type == 2 and dynstr:  # SHT_SYMTAB
            dynamic.append((6, sh_link))

    libraries: list[str] = []
    for tag, val in dynamic:
        if tag in (1, 14) and 0 <= val < len(dynstr):  # DT_NEEDED, DT_STRTAB-ish
            end = dynstr.find(b"\x00", val)
            if end > 0:
                libraries.append(dynstr[val:end].decode("utf-8", errors="replace"))

    imports: list[str] = []
    if dynsym_size:
        count = dynsym_size // max(dynsym_entsize, 1)
        for index in range(count):
            offset = dynsym_offset + index * dynsym_entsize
            if offset + dynsym_entsize > len(data):
                break
            if is_64:
                st_name, _info, _other, st_shndx, _value, _size = struct.unpack_from(
                    endian + "IBBHQQ", data, offset
                )
            else:
                st_name, _value, _size, _info, _other, st_shndx = struct.unpack_from(
                    endian + "IIIBBH", data, offset
                )
            if st_name == 0 or st_shndx == 0:
                continue
            if st_name >= len(dynstr):
                continue
            end = dynstr.find(b"\x00", st_name)
            if end < 0:
                continue
            imports.append(dynstr[st_name:end].decode("utf-8", errors="replace"))
    return imports, libraries


