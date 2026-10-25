#!/usr/bin/env python3
"""Try every candidate proof of concept a release brought with it.

Some projects add the crashing input to their test suite with the fix.
This script builds the vulnerable and the fixed release, runs every
candidate against both, and reports which ones discriminate: the input
has to crash the vulnerable one and not the fixed one.

Usage::

    python benchmark/corpus/try_pocs.py --project libxml2 --cve CVE-2016-4658
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from upstream import (
    UPSTREAM,
    _build_in_container,
    _download,
    _extract,
    _run,
    _write_wrapper,
)


def _candidates(fixed_tree: Path, patterns: tuple[str, ...]) -> list[Path]:
    found: list[Path] = []
    for pattern in patterns:
        found.extend(sorted(fixed_tree.rglob(pattern)))
    return [path for path in found if path.is_file() and path.stat().st_size < 500_000]


def _run_tool(
    tree: Path,
    runtime: str,
    image: str,
    tool: str,
    args: list[str],
    poc: Path,
) -> tuple[bool, bool, str]:
    """Run the tool: did it crash, did it hang, and what did it say?"""
    parts = [str(part) for part in args]
    script = (
        "cd /src\n"
        f"./{tool} "
        + " ".join(part.replace("{poc}", "/poc") for part in parts)
        + "\n"
    )
    container_args = [
        runtime,
        "run",
        "--rm",
        "--pull=never",
        "--network",
        "none",
        "--memory",
        "2g",
        "-v",
        f"{tree}:/src:ro",
        "-v",
        f"{poc}:/poc:ro",
        image,
        "sh",
        "-c",
        script,
    ]
    try:
        output = _run(container_args, timeout=30)
    except subprocess.TimeoutExpired:
        return False, True, "the run did not finish"
    crashed = "AddressSanitizer" in output or "Segmentation fault" in output
    return crashed, False, output


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--project", default="")
    parser.add_argument("--cve", default="")
    parser.add_argument("--runtime", default="podman")
    parser.add_argument("--image", default="ghcr.io/usualdork/verdis/base:latest")
    parser.add_argument(
        "--workdir", default=str(Path.home() / ".cache" / "verdis-upstream")
    )
    parser.add_argument("--json", default="")
    args = parser.parse_args(argv)

    workdir = Path(args.workdir)
    workdir.mkdir(parents=True, exist_ok=True)

    results: list[dict[str, object]] = []
    for spec in UPSTREAM:
        if args.project and spec["name"] != args.project:
            continue
        if args.cve and spec["cve"] != args.cve:
            continue
        print(f"== {spec['key']} ({spec['cve']})")
        project = workdir / str(spec["name"])
        project.mkdir(parents=True, exist_ok=True)
        trees: dict[str, Path] = {}
        for role in ("vulnerable", "fixed"):
            release = spec[role]
            archive = project / Path(str(release["url"])).name
            if not _download(str(release["url"]), archive):
                print("    download failed")
                continue
            tree = _extract(archive, project / role, fresh=True)
            if tree is None:
                print("    extract failed")
                continue
            trees[role] = tree
        if len(trees) != 2:
            continue
        for role, tree in trees.items():
            ok, output = _build_in_container(
                tree,
                args.runtime,
                args.image,
                list(spec["build"]),
                _write_wrapper(workdir / "softcc"),
            )
            print(f"    the {role} release built: {ok}")
            if not ok:
                print(output[-1500:])
                break
        else:
            candidates = _candidates(
                trees["fixed"], tuple(spec.get("candidate_patterns", ("*",)))
            )
            print(f"    {len(candidates)} candidate(s)")
            # A defect can show up as a crash or as a hang, and the tool
            # that reaches it may need an option.
            for candidate in candidates[:40]:
                for options in (
                    [],
                    ["--xpath"],
                    ["--recover"],
                    ["--noent"],
                    ["--html"],
                    ["--xpath", "//node()"],
                ):
                    args_v = [*options, *spec["poc_args"]]
                    crashed_v, hung_v, _ = _run_tool(
                        trees["vulnerable"],
                        args.runtime,
                        args.image,
                        str(spec["tool"]),
                        args_v,
                        candidate,
                    )
                    if not (crashed_v or hung_v):
                        continue
                    crashed_f, hung_f, _ = _run_tool(
                        trees["fixed"],
                        args.runtime,
                        args.image,
                        str(spec["tool"]),
                        args_v,
                        candidate,
                    )
                    mark = (
                        "DISCRIMINATES"
                        if (crashed_v or hung_v) and not (crashed_f or hung_f)
                        else ""
                    )
                    print(
                        f"      {candidate.relative_to(trees['fixed'])} "
                        f"{' '.join(options) or '(no options)'}: "
                        f"vulnerable={crashed_v or hung_v} fixed={crashed_f or hung_f} "
                        f"{mark}"
                    )
                    results.append(
                        {
                            "cve": spec["cve"],
                            "candidate": str(candidate.relative_to(trees["fixed"])),
                            "options": options,
                            "vulnerable_crashed": crashed_v,
                            "vulnerable_hung": hung_v,
                            "fixed_crashed": crashed_f,
                            "fixed_hung": hung_f,
                        }
                    )
    if args.json:
        Path(args.json).write_text(json.dumps(results, indent=2), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
