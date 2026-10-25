#!/usr/bin/env python3
"""Find the upstream fix commits and the proof of concept that came with them.

The release-pair approach (build release A and release B) is too coarse:
the vulnerable release can be years older than the fix, so the input
that the fix added may not discriminate. The *fix commit* is precise:
its parent is the vulnerable code, and the files it added are usually
the proof of concept.

So this script clones the history, finds the commit that fixed a CVE,
lists the files it added, and reports what looks like a proof of
concept.

Usage::

    python benchmark/corpus/findfixes.py --json /tmp/fixes.json
"""

from __future__ import annotations

import argparse
import json
import subprocess
from pathlib import Path
from typing import Any

#: project -> the CVE, the patterns to find the fix commit in the log,
#: and the tool the fix touched.
TARGETS: list[dict[str, Any]] = [
    {
        "key": "libxml2-cve-2016-1834",
        "name": "libxml2",
        "cve": "CVE-2016-1834",
        "repo": "https://github.com/GNOME/libxml2.git",
        "patterns": ["758588", "xmlDictComputeFastKey", "CVE-2016-1834"],
        "tool": "xmllint",
        "note": "an infinite loop in the dictionary key computation",
    },
    {
        "key": "libxml2-cve-2016-4658",
        "name": "libxml2",
        "cve": "CVE-2016-4658",
        "repo": "https://github.com/GNOME/libxml2.git",
        "patterns": ["758518", "CVE-2016-4658", "xpointer"],
        "tool": "xmllint",
        "note": "an out-of-bounds read in the XPointer implementation",
    },
    {
        "key": "libarchive-cve-2020-36148",
        "name": "libarchive",
        "cve": "CVE-2020-36148",
        "repo": "https://github.com/libarchive/libarchive.git",
        "patterns": ["CVE-2020-36148", "rar5", "Rar5"],
        "tool": "bsdtar",
        "note": "an out-of-bounds read in the RAR5 reader",
    },
    {
        "key": "libtiff-cve-2017-11613",
        "name": "libtiff",
        "cve": "CVE-2017-11613",
        "repo": "https://gitlab.com/libtiff/libtiff.git",
        "patterns": ["CVE-2017-11613"],
        "tool": "tiffcp",
        "note": "a memory exhaustion in the strip reader",
    },
    {
        "key": "libtiff-cve-2016-3991",
        "name": "libtiff",
        "cve": "CVE-2016-3991",
        "repo": "https://gitlab.com/libtiff/libtiff.git",
        "patterns": ["CVE-2016-3991"],
        "tool": "tiffcrop",
        "note": "an out-of-bounds write in loadImage",
    },
    {
        "key": "libtiff-cve-2016-3945",
        "name": "libtiff",
        "cve": "CVE-2016-3945",
        "repo": "https://gitlab.com/libtiff/libtiff.git",
        "patterns": ["CVE-2016-3945"],
        "tool": "tiff2rgba",
        "note": "an integer overflow in the buffer size",
    },
    {
        "key": "bzip2-cve-2019-12900",
        "name": "bzip2",
        "cve": "CVE-2019-12900",
        "repo": "https://gitlab.com/bzip2/bzip2.git",
        "patterns": ["CVE-2019-12900", "12900", "out of bounds"],
        "tool": "bunzip2",
        "note": "an out-of-bounds write in the decompressor",
    },
    {
        "key": "xz-cve-2016-9840",
        "name": "xz",
        "cve": "CVE-2016-9840",
        "repo": "https://github.com/tukaani-project/xz.git",
        "patterns": ["CVE-2016-9840", "2016-9840"],
        "tool": "xz",
        "note": "a crash in the decoder",
    },
    {
        "key": "libpng-cve-2015-8126",
        "name": "libpng",
        "cve": "CVE-2015-8126",
        "repo": "https://github.com/glennrp/libpng.git",
        "patterns": ["CVE-2015-8126", "read past the end"],
        "tool": "pngfix",
        "note": "a buffer overread in the row reader",
    },
    {
        "key": "libpng-cve-2016-3751",
        "name": "libpng",
        "cve": "CVE-2016-3751",
        "repo": "https://github.com/glennrp/libpng.git",
        "patterns": ["CVE-2016-3751", "null deref"],
        "tool": "pngfix",
        "note": "a null pointer dereference in the row reader",
    },
    {
        "key": "libwebp-cve-2018-25009",
        "name": "libwebp",
        "cve": "CVE-2018-25009",
        "repo": "https://github.com/webmproject/libwebp.git",
        "patterns": ["CVE-2018-25009", "25009"],
        "tool": "dwebp",
        "note": "a heap buffer overflow in the incremental decoder",
    },
    {
        "key": "libgd-cve-2016-10166",
        "name": "libgd",
        "cve": "CVE-2016-10166",
        "repo": "https://github.com/libgd/libgd.git",
        "patterns": ["CVE-2016-10166", "10166"],
        "tool": "gd2topng",
        "note": "a heap buffer overflow in the fill-to-border code",
    },
    {
        "key": "pcre-cve-2015-2326",
        "name": "pcre",
        "cve": "CVE-2015-2326",
        "repo": "https://github.com/PCRE2Project/pcre.git",
        "patterns": ["CVE-2015-2326", "2326", "pcre_compile2"],
        "tool": "pcretest",
        "note": "a heap buffer overflow in the pattern compiler",
    },
    {
        "key": "libtiff-cve-2016-5314",
        "name": "libtiff",
        "cve": "CVE-2016-5314",
        "repo": "https://gitlab.com/libtiff/libtiff.git",
        "patterns": ["CVE-2016-5314", "PixarLogDecode"],
        "tool": "tiffcp",
        "note": "a heap buffer overflow in the PixarLog codec",
    },
    {
        "key": "giflib-cve-2018-5711",
        "name": "giflib",
        "cve": "CVE-2018-5711",
        "repo": "https://git.code.sf.net/p/giflib/code",
        "patterns": ["CVE-2018-5711", "5711", "infinite loop"],
        "tool": "gif2png",
        "note": "an infinite loop in the GIF reader",
    },
]


def _run(args: list[str], *, cwd: Path | None = None, timeout: int = 900) -> str:
    result = subprocess.run(
        args,
        cwd=str(cwd) if cwd else None,
        capture_output=True,
        text=True,
        errors="replace",
        timeout=timeout,
        check=False,
    )
    return result.stdout + result.stderr


def _clone(repo: str, destination: Path) -> bool:
    if (destination / ".git").exists():
        return True
    destination.parent.mkdir(parents=True, exist_ok=True)
    output = _run(["git", "clone", "--quiet", repo, str(destination)], timeout=1800)
    if (destination / ".git").exists():
        return True
    print(f"    clone failed: {output.strip()[:200]}")
    return False


def _find_commits(repo: Path, patterns: list[str]) -> list[str]:
    """The commits whose subject matches any of the patterns."""
    found: list[str] = []
    for pattern in patterns:
        output = _run(
            ["git", "log", "--all", "--format=%H%x09%s%x09%ad", "--date=short", f"--grep={pattern}", "-i"],
            cwd=repo,
        )
        for line in output.splitlines():
            if "\t" not in line:
                continue
            commit, subject, date = line.split("\t", 2)
            if commit not in [entry[0] for entry in found]:
                found.append((commit, subject, date))  # type: ignore[arg-type]
    return found  # type: ignore[return-value]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--workdir", default=str(Path.home() / ".cache" / "verdis-upstream")
    )
    parser.add_argument("--json", default="")
    args = parser.parse_args(argv)

    workdir = Path(args.workdir)
    workdir.mkdir(parents=True, exist_ok=True)

    report: list[dict[str, Any]] = []
    for target in TARGETS:
        name = str(target["name"])
        print(f"== {target['key']} ({target['cve']})")
        repo = workdir / name
        if not _clone(str(target["repo"]), repo):
            report.append({"key": target["key"], "cloned": False})
            continue
        commits = _find_commits(repo, list(target["patterns"]))
        print(f"    {len(commits)} candidate commit(s)")
        for commit, subject, date in commits[:4]:
            added = _run(
                ["git", "show", "--name-only", "--diff-filter=A", "--format=", commit],
                cwd=repo,
            ).splitlines()
            added = [name for name in added if name.strip()]
            print(f"      {commit[:10]} {date} {subject[:70]}")
            for name in added[:6]:
                size = ""
                try:
                    size = str((repo / name).stat().st_size)
                except OSError:
                    size = "?"
                print(f"        + {name} ({size} bytes)")
            report.append(
                {
                    "key": target["key"],
                    "cve": target["cve"],
                    "repo": target["repo"],
                    "commit": commit,
                    "subject": subject,
                    "date": date,
                    "added": added,
                    "tool": target["tool"],
                    "note": target["note"],
                }
            )
    if args.json:
        Path(args.json).write_text(json.dumps(report, indent=2), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
