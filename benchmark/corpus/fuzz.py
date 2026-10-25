#!/usr/bin/env python3
"""Find a proof of concept by fuzzing a tool.

This runs *inside* the container: a container start per iteration would
be far too slow. It mutates the project's own test files and runs the
tool against each mutation until one of them crashes.

The proof of concept that comes out is only usable if it *discriminates*:
it has to crash the vulnerable release and not the fixed one. The caller
checks that, and discards the input otherwise.

Usage (inside the container)::

    python3 fuzz.py --tool tools/tiffcrop --args "{poc} /tmp/out.tif" \\
        --seeds /seeds --out /tmp/poc --budget 20000
"""

from __future__ import annotations

import argparse
import random
import subprocess
import sys
import time
from pathlib import Path

#: The bytes that are worth trying first: TIFF tags carry their sizes
#: and offsets, so changing one of them is more likely to reach a
#: length check than flipping an arbitrary byte.
INTERESTING = (
    0x00,
    0x01,
    0x02,
    0x03,
    0x04,
    0x07,
    0x08,
    0x0F,
    0x10,
    0x1F,
    0x20,
    0x40,
    0x7F,
    0x80,
    0xFF,
)


def _mutate(data: bytes, rng: random.Random) -> bytes:
    buffer = bytearray(data)
    if not buffer:
        return bytes(buffer)
    for _ in range(rng.randint(1, 8)):
        if not buffer:
            break
        kind = rng.random()
        position = rng.randrange(len(buffer))
        if kind < 0.35:
            buffer[position] = rng.choice(INTERESTING)
        elif kind < 0.6:
            buffer[position] = rng.randrange(256)
        elif kind < 0.8 and len(buffer) > 16:
            # A four byte field, which is where a size or an offset
            # usually lives.
            start = rng.randrange(len(buffer) - 4)
            value = rng.choice(
                [
                    rng.randrange(1, 1 << 16),
                    rng.randrange(1, 1 << 24),
                    0xFFFFFFFF,
                    0x7FFFFFFF,
                ]
            )
            buffer[start : start + 4] = value.to_bytes(4, "little")
        else:
            # Grow or shrink the file.
            if kind < 0.9:
                buffer.extend(
                    bytes(rng.randrange(256) for _ in range(rng.randint(1, 64)))
                )
            else:
                del buffer[position : position + rng.randint(1, 32)]
    return bytes(buffer)


def _crashed(returncode: int, output: bytes) -> bool:
    """Did the run die, rather than exit?

    A negative return code is a death by signal. A return code of 128
    or more is *not*: a program is free to exit with any value it
    likes, and many of them use the low hundreds to mean "I could not
    read that file". Only a signal or a sanitizer diagnostic is a
    crash.
    """
    if returncode < 0:
        return True
    return b"AddressSanitizer" in output or b"runtime error:" in output


#: The diagnostics that are not memory errors.
#:
#: A huge allocation is a resource problem, not a corruption, and most
#: releases have one. An integer overflow reported by the undefined
#: behaviour sanitizer is real but is not the class of defect the
#: corpus is looking for, and stopping at the first one would hide the
#: memory error behind it.
_NOT_A_MEMORY_ERROR = (
    b"allocator is out of memory",
    b"allocation-size-too-big",
    b"out-of-memory",
    b"requested allocation size",
    b"runtime error:",
    b"negative-size-param",
)


def _memory_error(output: bytes) -> bool:
    """Is this a memory error?

    The fuzzer keeps looking until it finds one, and collects several:
    a crash is only interesting if the *fixed* build does not have it.
    """
    if any(marker in output for marker in _NOT_A_MEMORY_ERROR):
        return False
    return (
        b"AddressSanitizer" in output
        or b"SEGV" in output
        or b"Segmentation fault" in output
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tool", required=True)
    parser.add_argument("--args", default="{poc}")
    parser.add_argument("--seeds", default="/seeds")
    parser.add_argument("--out", default="/tmp/poc")
    parser.add_argument("--budget", type=int, default=20000)
    parser.add_argument("--seed", type=int, default=1)
    parser.add_argument("--timeout", type=float, default=10.0)
    args = parser.parse_args(argv)

    rng = random.Random(args.seed)
    seed_dir = Path(args.seeds)
    seeds: list[bytes] = []
    for path in sorted(seed_dir.rglob("*")):
        if not path.is_file() or path.stat().st_size > 200_000:
            continue
        if path.suffix == ".zip":
            # A project that ships its own fuzzing corpus: the seeds
            # are inside it.
            import zipfile

            try:
                with zipfile.ZipFile(path) as archive:
                    for name in archive.namelist():
                        try:
                            seeds.append(archive.read(name))
                        except (KeyError, OSError):
                            continue
            except zipfile.BadZipFile:
                continue
            continue
        seeds.append(path.read_bytes())
    if not seeds:
        print("no seeds", file=sys.stderr)
        return 2
    print(f"{len(seeds)} seed(s), budget {args.budget}", file=sys.stderr)

    working = Path("/tmp/fuzz-input")
    working.write_bytes(seeds[0])
    argv_template = args.args.split()

    started = time.monotonic()
    for index in range(args.budget):
        data = _mutate(rng.choice(seeds), rng)
        working.write_bytes(data)
        argv = [part.replace("{poc}", str(working)) for part in argv_template]
        try:
            result = subprocess.run(
                [args.tool, *argv],
                capture_output=True,
                timeout=args.timeout,
                check=False,
            )
        except subprocess.TimeoutExpired:
            continue
        output = result.stdout + result.stderr
        if _memory_error(output) or result.returncode < 0:
            # Keep going: a crash is only interesting if the *fixed*
            # build does not have it, so several candidates are worth
            # collecting.
            target = Path(args.out)
            target.parent.mkdir(parents=True, exist_ok=True)
            found = len(list(target.parent.glob("crash-*"))) if target.parent.is_dir() else 0
            if found < 20:
                candidate = target.parent / f"crash-{found:03d}"
                candidate.write_bytes(data)
                print(
                    f"crash after {index} iteration(s): {candidate} "
                    f"({len(data)} bytes, exit {result.returncode})",
                    file=sys.stderr,
                )
                continue
            print("enough crashes", file=sys.stderr)
            return 0
        if _crashed(result.returncode, output) and not Path(args.out).exists():
            # An integer overflow, or another diagnostic that is not a
            # memory error. Remember it, but keep looking.
            Path(args.out).write_bytes(data)
            Path(str(args.out) + ".weak").write_text(
                "not a memory error\n", encoding="utf-8"
            )
        if time.monotonic() - started > 900:
            print("out of time", file=sys.stderr)
            return 1
    print("no crash found", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
