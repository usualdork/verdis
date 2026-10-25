#!/usr/bin/env python3
"""Find the proof of concept for an upstream CVE.

The approach is: take the vulnerable release and the fixed release of an
upstream project, look at what the fix added, and use the file the fix
brought with it as the proof of concept. A fix that adds a test file
usually adds the crashing input with it.

When the fix adds nothing usable, the script says so, and the input has
# to be found by fuzzing the affected tool instead.

Usage::

    python benchmark/corpus/findpoc.py --json /tmp/pocs.json
"""

from __future__ import annotations

import argparse
import json
import subprocess
from pathlib import Path

#: project -> the release pairs to try, and the tool that is affected.
CANDIDATES: list[dict[str, object]] = [
    {
        "key": "giflib",
        "repo": "https://git.code.sf.net/p/giflib/code",
        "pairs": [("2.1.4", "2.1.5", "CVE-2018-5711")],
        "tools": ["gif2png"],
    },
    {
        "key": "pcre",
        "repo": "https://git.code.sf.net/p/pcre/code",
        "pairs": [("8.38", "8.39", "CVE-2015-2326")],
        "tools": ["pcretest"],
    },
    {
        "key": "wavpack",
        "repo": "https://github.com/dbry/WavPack.git",
        "pairs": [("5.1.0", "5.2.0", "CVE-2018-10536")],
        "tools": ["wvunpack"],
    },
    {
        "key": "libwebp",
        "repo": "https://github.com/webmproject/libwebp.git",
        "pairs": [("1.0.0", "1.0.1", "CVE-2018-25009")],
        "tools": ["dwebp", "cwebp"],
    },
    {
        "key": "xz",
        "repo": "https://github.com/tukaani-project/xz.git",
        "pairs": [("v5.2.2", "v5.2.3", "CVE-2016-9840")],
        "tools": ["xz"],
    },
    {
        "key": "bzip2",
        "repo": "https://gitlab.com/bzip2/bzip2.git",
        "pairs": [("bzip2-1.0.6", "bzip2-1.0.8", "CVE-2019-12900")],
        "tools": ["bzip2", "bunzip2"],
    },
    {
        "key": "libexif",
        "repo": "https://github.com/libexif/libexif.git",
        "pairs": [("v0.6.20", "v0.6.21", "CVE-2016-6328")],
        "tools": ["exif"],
    },
    {
        "key": "libtiff",
        "repo": "https://gitlab.com/libtiff/libtiff.git",
        "pairs": [
            ("v4.0.6", "v4.0.7", "CVE-2016-3945"),
            ("v4.0.6", "v4.0.7", "CVE-2016-3991"),
        ],
        "tools": ["tiff2rgba", "tiffcrop", "tiff2pdf", "tiffcp"],
    },
    {
        "key": "libarchive",
        "repo": "https://github.com/libarchive/libarchive.git",
        "pairs": [("v3.4.0", "v3.4.1", "CVE-2020-36148")],
        "tools": ["bsdtar", "bsdcpio"],
    },
    {
        "key": "libxml2",
        "repo": "https://github.com/GNOME/libxml2.git",
        "pairs": [("v2.9.3", "v2.9.4", "CVE-2016-1834")],
        "tools": ["xmllint"],
    },
]

#: The kinds of file that could plausibly be a proof of concept.
POC_SUFFIXES = (
    ".tif",
    ".tiff",
    ".gif",
    ".png",
    ".webp",
    ".wv",
    ".xz",
    ".bz2",
    ".tar",
    ".gz",
    ".xml",
    ".jpg",
    ".jpeg",
    ".exv",
    ".txt",
    ".dat",
    ".bin",
    ".out",
    ".ppm",
    ".pnm",
    ".raw",
)


def _run(args: list[str], *, cwd: Path | None = None, timeout: int = 600) -> str:
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


def _clone(spec: dict[str, object], workdir: Path) -> Path | None:
    key = str(spec["key"])
    destination = workdir / key
    if (destination / ".git").exists():
        return destination
    output = _run(
        ["git", "clone", "--quiet", str(spec["repo"]), str(destination)], timeout=1800
    )
    if (destination / ".git").exists():
        return destination
    print(f"    clone failed: {output.strip()[:200]}")
    return None


def _tags(repo: Path) -> list[str]:
    return _run(["git", "tag", "-l"], cwd=repo).splitlines()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workdir", default=str(Path.home() / ".cache" / "verdis-upstream"))
    parser.add_argument("--json", default="")
    args = parser.parse_args(argv)

    workdir = Path(args.workdir)
    workdir.mkdir(parents=True, exist_ok=True)

    report: list[dict[str, object]] = []
    for spec in CANDIDATES:
        key = str(spec["key"])
        print(f"== {key}")
        repo = _clone(spec, workdir)
        if repo is None:
            report.append({"project": key, "cloned": False})
            continue
        available = set(_tags(repo))
        for vulnerable, fixed, cve in spec["pairs"]:  # type: ignore[misc]
            if vulnerable not in available:
                print(f"    {vulnerable} is not a tag")
                continue
            if fixed not in available:
                print(f"    {fixed} is not a tag")
                continue
            added = _run(
                ["git", "diff", "--name-only", "--diff-filter=A", vulnerable, fixed],
                cwd=repo,
            ).splitlines()
            interesting = [
                name
                for name in added
                if name.lower().endswith(POC_SUFFIXES)
                or "/test" in name.lower()
                or "fuzz" in name.lower()
            ]
            print(f"    {cve}: {vulnerable} -> {fixed}, {len(added)} added file(s)")
            for name in interesting[:12]:
                size = ""
                try:
                    size = str((repo / name).stat().st_size)
                except OSError:
                    size = "?"
                print(f"      + {name} ({size} bytes)")
            report.append(
                {
                    "project": key,
                    "cve": cve,
                    "vulnerable": vulnerable,
                    "fixed": fixed,
                    "added": added,
                    "candidates": interesting,
                    "tools": spec["tools"],
                }
            )
    if args.json:
        Path(args.json).write_text(json.dumps(report, indent=2), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
