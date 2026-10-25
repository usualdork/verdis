"""Reading stack frames out of a crash or sanitizer report.

Both the oracles and the dedupe fingerprints need the same thing: the
names of the functions on the stack, without the addresses and line
numbers, which change between builds of the same code.
"""

from __future__ import annotations

import re

__all__ = ["extract_frame_symbols", "extract_frames"]

#: ``#0 0x4f2a in parse_header src/hdr.c:212`` — the AddressSanitizer form.
_ASAN_FRAME_RE = re.compile(
    r"^\s*#\d+\s+0x[0-9a-f]+\s+in\s+(?P<symbol>[\w:<>~.+-]+)"
    r"(?P<location>[^\n(]*)",
    re.MULTILINE,
)

#: ``#1  0x00007fff in parse_header() at src/hdr.c:212`` — the gdb and
#: libbacktrace form.
_SYMBOL_FRAME_RE = re.compile(
    r"^\s*(?:#\d+\s+)?(?:0x[0-9a-f]+\s+)?(?P<symbol>[\w:<>~.+-]+)\s*\((?P<location>[^)]*)\)",
    re.MULTILINE,
)

#: Frames that are not functions.
_NOT_A_SYMBOL = frozenset({"ERROR", "SUMMARY", "WARNING", "in", "at", "0x0"})


def extract_frames(output: str, limit: int = 12) -> tuple[str, ...]:
    """The stack frames of a crash or sanitizer report, in order.

    Both the ``symbol(args)`` form and the ``#0 0xADDR in symbol`` form
    are understood.
    """
    frames: list[str] = []
    seen: set[tuple[int, str]] = set()
    for regex in (_ASAN_FRAME_RE, _SYMBOL_FRAME_RE):
        for match in regex.finditer(output):
            symbol = match.group("symbol")
            if not symbol or symbol in _NOT_A_SYMBOL:
                continue
            location = (match.groupdict().get("location") or "").strip()
            # The same line can match both patterns. The line number tells
            # them apart from a genuine repetition, such as a recursion.
            line = output.count("\n", 0, match.start()) + 1
            key = (line, symbol)
            if key in seen:  # pragma: no cover - the patterns are disjoint
                continue
            seen.add(key)
            frames.append(f"{symbol} ({location})" if location else symbol)
            if len(frames) >= limit:
                return tuple(frames)
    return tuple(frames)


def extract_frame_symbols(output: str, limit: int = 6) -> tuple[str, ...]:
    """Just the symbol names of the frames, for a stable signature."""
    symbols: list[str] = []
    for frame in extract_frames(output, limit=limit * 3):
        symbol = frame.split(" (")[0].split("+")[0]
        if symbol and symbol not in symbols:
            symbols.append(symbol)
        if len(symbols) >= limit:
            break
    return tuple(symbols)
