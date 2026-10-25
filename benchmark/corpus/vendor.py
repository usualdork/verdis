"""Bring the vendored upstream cases into the corpus.

An upstream case is a real project, at a real commit, with the proof of
concept the fix brought with it. The target is vendored as a compressed
tree so the corpus can be built without a network, and the benchmark
builds it in the sandbox like any other target.

The recipe is the project's own build, with the sanitizer turned on: the
defect has to be *visible* for the case to mean anything.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any

#: The build recipe for a vendored upstream case. The steps come from
#: the meta file; the sanitizer flags and the run environment are added
#: here, because every upstream case needs them.
RECIPE_TEMPLATE = """\
# The project's own build, with the sanitizer turned on: the defect has
# to be visible for the case to mean anything.
language: c
build:
  system: make
  steps:
{steps}
  env:
    CFLAGS: -fsanitize=address -g -O0 -Wno-error
    CXXFLAGS: -fsanitize=address -g -O0 -Wno-error
run:
  workdir: /work
  default_timeout: 60s
  repeat: 3
  env:
    ASAN_OPTIONS: detect_leaks=0
"""


def _steps(meta: dict[str, Any]) -> str:
    lines = []
    for step in meta.get("build", []):
        lines.append(f"    - {step}")
    if meta.get("driver_source"):
        lines.append(
            "    - ./libtool --mode=link cc -fsanitize=address -g -O0 "
            "-I. -Ilibarchive verdis_driver.c -o verdis_driver "
            "./libarchive.la"
        )
    return "\n".join(lines)


def _report(meta: dict[str, Any]) -> str:
    """The report for an upstream case."""
    if meta.get("report"):
        return str(meta["report"])
    poc_name = str(meta.get("poc_name", "poc.bin"))
    if meta.get("driver_args"):
        command = "./{} {}".format(
            meta.get("driver_binary", "verdis_driver"), poc_name
        )
    else:
        args = meta.get("tool_args") or []
        invocations = [list(args)] if args and isinstance(args[0], str) else [
            list(item) for item in args
        ]
        parts = invocations[0] if invocations else []
        command = "./{} {}".format(
            meta["tool"],
            " ".join(str(part).replace("{poc}", poc_name) for part in parts),
        )
    return f"""\
# {meta['title']}

**Version**: {meta.get('version', 'unknown')}
**Component**: {meta['component']}
**Class**: {meta.get('cwe', 'CWE-125')}

This is {meta['cve']} ({meta['advisory']}), in {meta['name']}. A crafted
file makes the program read or write outside the buffer it was given.

## Steps to reproduce

```
{command}
```

The program aborts with a sanitizer diagnostic.

## Impact

{meta['impact']}

## Provenance

The proof of concept is the one that came with the fix, from the
upstream repository. The target is the upstream source at the commit
before the fix.
"""


def _command(meta: dict[str, Any]) -> str:
    """The command the report gives."""
    if meta.get("driver_args"):
        args = " ".join(
            str(part).replace("{poc}", "poc") for part in meta["driver_args"]
        )
        return f"./{meta.get('driver_binary', 'verdis_driver')} {args}"
    args = " ".join(str(part).replace("{poc}", "poc") for part in meta["tool_args"][0])
    return f"./{meta['tool']} {args}"


def _unpack(archive: Path, destination: Path) -> bool:
    destination.mkdir(parents=True, exist_ok=True)
    result = subprocess.run(
        [
            "tar",
            "xJf",
            str(archive),
            "-C",
            str(destination),
            "--strip-components=1",
        ],
        capture_output=True,
        text=True,
        timeout=1800,
        check=False,
    )
    if result.returncode != 0:
        print(f"    could not unpack {archive.name}: {result.stderr.strip()[:200]}")
        return False
    return True


def build_upstream_cases(
    vendor: Path, out: Path
) -> list[tuple[str, dict[str, Any]]]:
    """Write the vendored upstream cases into the corpus tree.

    Returns the manifests, so the caller can build the case directories.
    """
    manifests: list[tuple[str, dict[str, Any]]] = []
    if not vendor.is_dir():
        return manifests

    for directory in sorted(vendor.iterdir()):
        meta_path = directory / "meta.json"
        archive = directory / "target.tar.xz"
        if not meta_path.is_file() or not archive.is_file():
            continue
        meta = json.loads(meta_path.read_text(encoding="utf-8"))
        key = str(meta["key"])

        case = out / key
        target = case / "target"
        if target.exists():
            import shutil

            shutil.rmtree(target, ignore_errors=True)
        if not _unpack(archive, target):
            continue
        # The recipe.
        (target / ".verdis").mkdir(parents=True, exist_ok=True)
        (target / ".verdis" / "recipe.yml").write_text(
            RECIPE_TEMPLATE.format(steps=_steps(meta)), encoding="utf-8"
        )
        # The harness.
        if meta.get("driver_source"):
            (target / "verdis_driver.c").write_text(
                str(meta["driver_source"]), encoding="utf-8"
            )
        # The proof of concept, where the command expects it.
        poc_dir = directory / "poc"
        poc_files = list(poc_dir.glob("*")) if poc_dir.is_dir() else []
        for poc in poc_files:
            (target / poc.name).write_bytes(poc.read_bytes())

        manifests.append((key, meta))
    return manifests
