#!/usr/bin/env python3
# A tiny file server that serves one directory.
#
# The name comes from the request, and the name is joined to the root
# without checking that it stays inside it. A name that climbs out of
# the served directory reaches the files beside it.

import os
import sys

ROOT = "share"


def read(name: str) -> str:
    path = os.path.join(ROOT, name)
    with open(path, encoding="utf-8", errors="replace") as handle:
        return handle.read()


def main() -> int:
    if len(sys.argv) < 2:
        sys.stderr.write("usage: server <request>\n")
        return 2
    with open(sys.argv[1], encoding="utf-8", errors="replace") as handle:
        name = handle.readline().strip()
    try:
        sys.stdout.write(read(name))
    except OSError as exc:
        sys.stderr.write(f"cannot read the file: {exc}\n")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
