#!/usr/bin/env python3
"""Admit upstream cases: real projects, real CVEs, real proofs of concept.

An upstream case is only admitted when it *discriminates*: the proof of
concept has to make the vulnerable build fail and the fixed build
succeed. Everything else -- the clone, the build, the check -- is
mechanism.

The vulnerable version is the **parent of the fix commit**, not the
release before it. The release before it can be years older, and the
input the fix brought with it may not discriminate against it. The
parent is the code the fix was written for.

Usage::

    python benchmark/corpus/upstream.py --list
    python benchmark/corpus/upstream.py --key libxml2-cve-2016-1834
    python benchmark/corpus/upstream.py --all --emit
"""

from __future__ import annotations

import argparse
import binascii
import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "benchmark"))


CFLAGS = "-fsanitize=address -g -O0 -Wno-error"

#: A harness that reads an archive and its data.
#:
#: The command line tools skip an entry they cannot name, and the defects
#: are in the data path. The upstream test harness reads the data, so
#: this does too: the proof of concept is still upstream's, and the
#: harness is the controlled one PRD 13.1 asks for.
ARCHIVE_DRIVER = """\
#include <archive.h>
#include <archive_entry.h>
#include <stdio.h>

int main(int argc, char **argv) {
    if (argc < 2) {
        fputs("usage: harness <archive>", stderr);
        fputc(10, stderr);
        return 2;
    }
    struct archive *reader = archive_read_new();
    if (reader == NULL) {
        return 2;
    }
    archive_read_support_filter_all(reader);
    archive_read_support_format_all(reader);
    if (archive_read_open_filename(reader, argv[1], 10240) != ARCHIVE_OK) {
        fputs("cannot open the archive", stderr);
        fputc(10, stderr);
        archive_read_free(reader);
        return 2;
    }
    struct archive_entry *entry = NULL;
    int status = archive_read_next_header(reader, &entry);
    while (status == ARCHIVE_OK) {
        char buffer[65536];
        la_int64_t read = 0;
        while ((read = archive_read_data(reader, buffer, sizeof(buffer))) > 0) {
            /* The data is where the defect is. */
        }
        status = archive_read_next_header(reader, &entry);
    }
    archive_read_free(reader);
    puts("read the archive");
    return 0;
}
"""

#: The upstream cases this pipeline knows how to admit.
#:
#: ``fix`` is the commit that fixed the vulnerability. ``poc`` is where
#: the proof of concept came from: a file the fix added, or one the fix
#: named. ``tool`` is the program that reaches the defect.
CASES: list[dict[str, Any]] = [
    {
        "key": "libxml2-cve-2016-1834",
        "name": "libxml2",
        "cve": "CVE-2016-1834",
        "advisory": "GNOME bug 758588",
        "repo": "https://github.com/GNOME/libxml2.git",
        "fix": "db07dd613e461df93dde7902c6505629bf0734e9",
        "poc_from": "test/errors/758588.xml",
        "poc_name": "poc.xml",
        "tool": "xmllint",
        "tool_args": ["{poc}"],
        "build": [
            "./autogen.sh --without-python --without-lzma --without-zlib "
            "--without-iconv --without-icu --disable-shared",
            "make -j4 xmllint",
        ],
        "component": "parser.c:xmlParseEndTag2",
        "cwe": "CWE-125",
        "version": "2.9.3",
        "title": "Heap buffer overread in the tag parser",
        "impact": "A heap overread lets a crafted document read past the end of "
        "the input buffer.",
    },
    {
        "key": "libtiff-cve-2016-5314",
        "name": "libtiff",
        "cve": "CVE-2016-5314",
        "advisory": "a buffer write overrun in the PixarLog decoder",
        "repo": "https://gitlab.com/libtiff/libtiff.git",
        "fix": "bf5b698868b0b16f14cc03d83d74cdcd9e98983e",
        "poc_from": "",
        "poc_name": "poc.tif",
        "tool": "tools/tiffcp",
        "tool_args": [["{poc}", "/tmp/out.tif"]],
        "build": [
            "./configure --build=$(uname -m)-unknown-linux-gnu --disable-shared "
            "--without-jpeg --without-zlib --without-lzma --without-webp --without-zstd",
            "make -j4",
        ],
        "component": "tif_pixarlog.c:PixarLogDecode",
        "cwe": "CWE-787",
        "version": "4.0.6",
        "title": "Buffer write overrun in the PixarLog decoder",
        "impact": "A crafted TIFF writes past the end of the decode buffer.",
        "seeds_url": (
            "https://gitlab.com/libtiff/libtiff/-/archive/v4.1.0/libtiff-v4.1.0.tar.gz"
        ),
        "seeds_path": "libtiff-v4.1.0/test/images",
    },
    {
        "key": "libarchive-cve-2020-36148",
        "name": "libarchive",
        "cve": "CVE-2020-36148",
        "advisory": "an out-of-bounds read in the RAR5 reader",
        "repo": "https://github.com/libarchive/libarchive.git",
        "fix": "2331456dc1f83e6b20e656e69fa01b6e30302865",
        "poc_from": (
            "libarchive/test/test_read_format_rar5_arm_filter_on_window_boundary.rar.uu"
        ),
        "poc_name": "poc.rar",
        "tool": "bsdtar",
        "tool_args": [["-xOf", "{poc}"], ["-xf", "{poc}"], ["-tf", "{poc}"]],
        "build": [
            "sh build/autogen.sh",
            "./configure --disable-shared",
            "make -j4",
        ],
        "component": "archive_read_support_format_rar5.c:run_arm_filter",
        "cwe": "CWE-125",
        "version": "3.4.0",
        "title": "Out-of-bounds read in the RAR5 ARM filter",
        "impact": "A crafted archive reads past the end of the window buffer.",
        "driver": ARCHIVE_DRIVER,
        "driver_args": ["{poc}"],
        "driver_binary": "verdis_driver",
    },
    {
        "key": "libarchive-cve-2020-36149",
        "name": "libarchive",
        "cve": "CVE-2020-36149",
        "advisory": "an out-of-bounds write in the RAR5 reader",
        "repo": "https://github.com/libarchive/libarchive.git",
        "fix": "47bb8187d3ef2d49ee8c7841cb2872b3cfa1f6f7",
        "poc_from": (
            "libarchive/test/test_read_format_rar5_different_window_size.rar.uu"
        ),
        "poc_name": "poc.rar",
        "tool": "bsdtar",
        "tool_args": [["-xOf", "{poc}"], ["-xf", "{poc}"], ["-tf", "{poc}"]],
        "build": [
            "sh build/autogen.sh",
            "./configure --disable-shared",
            "make -j4",
        ],
        "component": "archive_read_support_format_rar5.c:update_crc",
        "cwe": "CWE-787",
        "version": "3.4.0",
        "title": "Out-of-bounds write in the RAR5 reader",
        "impact": "A crafted archive writes past the end of the window buffer.",
        "driver": ARCHIVE_DRIVER,
        "driver_args": ["{poc}"],
        "driver_binary": "verdis_driver",
    },
]


def _run(
    args: list[str], *, cwd: Path | None = None, timeout: int = 2400
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        args,
        cwd=str(cwd) if cwd else None,
        capture_output=True,
        text=True,
        errors="replace",
        timeout=timeout,
        check=False,
    )


def _clone(repo: str, destination: Path) -> bool:
    if (destination / ".git").exists():
        return True
    destination.parent.mkdir(parents=True, exist_ok=True)
    result = _run(["git", "clone", "--quiet", repo, str(destination)], timeout=3600)
    if (destination / ".git").exists():
        return True
    print(f"    clone failed: {(result.stdout + result.stderr).strip()[:200]}")
    return False


def _export(repo: Path, rev: str, destination: Path) -> bool:
    """Export a revision into a directory."""
    if destination.exists():
        shutil.rmtree(destination, ignore_errors=True)
    destination.mkdir(parents=True, exist_ok=True)
    result = _run(
        ["git", "archive", rev], cwd=repo, timeout=900
    )
    if result.returncode != 0:
        print(f"    export of {rev} failed: {result.stderr.strip()[:200]}")
        return False
    archive = destination.parent / f"{destination.name}.tar"
    archive.write_bytes(result.stdout.encode("utf-8", errors="replace"))
    # git archive writes binary; redo it properly through a pipe.
    archive.unlink(missing_ok=True)
    tar = subprocess.run(
        ["git", "archive", rev],
        cwd=str(repo),
        capture_output=True,
        check=False,
        timeout=900,
    )
    if tar.returncode != 0:
        return False
    unpack = subprocess.run(
        ["tar", "x", "-C", str(destination)],
        input=tar.stdout,
        capture_output=True,
        check=False,
        timeout=900,
    )
    return unpack.returncode == 0


def _decode_uu(text: str) -> bytes:
    out = bytearray()
    for line in text.splitlines():
        if line.startswith("begin "):
            continue
        if line.strip() in {"end", "`"} or not line.strip():
            continue
        try:
            out += binascii.a2b_uu(line)
        except binascii.Error:
            continue
    return bytes(out)


def _write_wrapper(workdir: Path) -> Path:
    """The compiler wrapper: the project's own -Werror is dropped."""
    wrapper = workdir / "fuzz"
    wrapper.mkdir(parents=True, exist_ok=True)
    for name in ("cc", "gcc", "clang", "c++", "g++"):
        path = wrapper / name
        path.write_text(
            "#!/usr/bin/env python3\n"
            "import os, sys\n"
            "real = os.environ.get('REAL_CC', '/usr/bin/cc')\n"
            "kept = [a for a in sys.argv[1:] if a != '-Werror' "
            "and not a.startswith('-Werror=')]\n"
            "os.execv(real, [real, *kept, '-Wno-error'])\n",
            encoding="utf-8",
        )
        path.chmod(0o755)
    return wrapper


def _build(tree: Path, steps: list[str], runtime: str, image: str) -> tuple[bool, str]:
    """Build a source tree inside the container."""
    script = (
        "set -e\n"
        "cd /src\n"
        "export PATH=/softcc:$PATH\n"
        "export REAL_CC=/usr/bin/cc\n"
        f"export CFLAGS='{CFLAGS}'\n"
        f"export CXXFLAGS='{CFLAGS}'\n"
        + "\n".join(steps)
        + "\n"
    )
    wrapper = Path(tempfile.mkdtemp(prefix="softcc-"))
    for name in ("cc", "gcc", "clang", "c++", "g++"):
        path = wrapper / name
        path.write_text(
            "#!/usr/bin/env python3\n"
            "import os, sys\n"
            "real = os.environ.get('REAL_CC', '/usr/bin/cc')\n"
            "kept = [a for a in sys.argv[1:] if a != '-Werror' "
            "and not a.startswith('-Werror=')]\n"
            "os.execv(real, [real, *kept, '-Wno-error'])\n",
            encoding="utf-8",
        )
        path.chmod(0o755)
    args = [
        runtime,
        "run",
        "--rm",
        "--pull=never",
        "--network",
        "none",
        "--memory",
        "4g",
        "-v",
        f"{tree}:/src:rw",
        "-v",
        f"{wrapper}:/softcc:ro",
        image,
        "sh",
        "-c",
        script,
    ]
    result = _run(args, timeout=3600)
    return result.returncode == 0, result.stdout + result.stderr


def _run_tool(
    tree: Path,
    tool: str,
    args: list[str],
    poc: Path,
    runtime: str,
    image: str,
) -> tuple[str, str, bool]:
    """Run the tool on the proof of concept.

    Returns ``(stdout+stderr, status, hung)``.
    """
    parts = [part.replace("{poc}", "/poc") for part in args]
    # The tool is bounded: a defect that hangs is a defect, and the
    # harness has to say so rather than wait for ever.
    script = (
        "cd /src\n"
        "export ASAN_OPTIONS=detect_leaks=0\n"
        f"timeout 60 ./{tool} " + " ".join(parts) + "\n"
        "echo \"__status=$?\"\n"
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
        result = _run(container_args, timeout=180)
    except subprocess.TimeoutExpired:
        return "", "timeout", True
    output = result.stdout + result.stderr
    status = ""
    for line in output.splitlines():
        if line.startswith("__status="):
            status = line.split("=", 1)[1].strip()
    return output, status, False


def _failed(output: str, status: str) -> bool:
    """Did the run fail in a way that shows the defect?"""
    if status == "timeout":
        return True
    if status == "124":
        # The tool ran out of time: a hang is a defect.
        return True
    if "AddressSanitizer" in output:
        return True
    if "runtime error:" in output:
        return True
    if "Segmentation fault" in output:
        return True
    try:
        code = int(status)
    except ValueError:
        return False
    return code >= 128


def _invocations(spec: dict[str, Any]) -> list[list[str]]:
    """The argument sets to try, in one shape.

    A spec may write its arguments as one invocation (``["{poc}"]``) or
    as several (``[["-xOf", "{poc}"]]``); they are normalised here so
    nothing downstream has to care.
    """
    args = spec.get("tool_args") or []
    if args and isinstance(args[0], str):
        return [list(args)]
    return [list(item) for item in args]


def _fuzz_for_poc(
    tree: Path,
    spec: dict[str, Any],
    destination: Path,
    runtime: str,
    image: str,
    seeds: Path,
    workdir: Path,
) -> Path | None:
    """Find the proof of concept by fuzzing the tool the fix touched.

    The seeds are the project's own test files: they are valid inputs, so
    a mutation of one is likely to reach the check the fix added.
    """
    destination.parent.mkdir(parents=True, exist_ok=True)
    args = " ".join(str(part) for part in _invocations(spec)[0])
    script = (
        "cd /src\n"
        "export ASAN_OPTIONS=detect_leaks=0\n"
        f"python3 /fuzz/fuzz.py --tool {spec['tool']} --args '{args}' "
        f"--seeds /seeds --out /poc-out/{destination.name} --budget 40000\n"
    )
    container_args = [
        runtime,
        "run",
        "--rm",
        "--pull=never",
        "--network",
        "none",
        "--memory",
        "4g",
        "-v",
        f"{tree}:/src:rw",
        "-v",
        f"{seeds}:/seeds:ro",
        "-v",
        f"{workdir / 'fuzz'}:/fuzz:ro",
        "-v",
        f"{destination.parent}:/poc-out:rw",
        image,
        "sh",
        "-c",
        script,
    ]
    result = _run(container_args, timeout=2400)
    if not destination.exists():
        print(f"    fuzzing found nothing: {(result.stdout + result.stderr)[-300:]}")
        return None
    return destination


def _seeds(spec: dict[str, Any], workdir: Path) -> Path | None:
    """The seed corpus for the fuzzer."""
    url = spec.get("seeds_url")
    if not url:
        return None
    archive = workdir / "seeds" / Path(str(url)).name
    archive.parent.mkdir(parents=True, exist_ok=True)
    if not archive.exists() or archive.stat().st_size < 1000:
        result = _run(
            ["curl", "-sSL", "--max-time", "900", "-o", str(archive), str(url)],
            timeout=1200,
        )
        if not archive.exists() or archive.stat().st_size < 1000:
            print(f"    could not fetch the seeds: {result.stdout[-200:]}")
            return None
    directory = archive.parent / "trees"
    directory.mkdir(parents=True, exist_ok=True)
    extracted = directory / archive.name.replace(".tar.gz", "").replace(".tar.xz", "")
    if not extracted.is_dir():
        extracted.mkdir(parents=True, exist_ok=True)
        _run(
            ["tar", "xf", str(archive), "-C", str(extracted)], timeout=1200
        )
    seeds = extracted / str(spec.get("seeds_path", ""))
    if not seeds.is_dir():
        print(f"    the seeds are not where they should be: {seeds}")
        return None
    return seeds


def _discriminates(
    trees: dict[str, Path],
    spec: dict[str, Any],
    poc: Path,
    runtime: str,
    image: str,
) -> bool:
    """Does this input crash the vulnerable build and not the fixed one?"""
    invocations = (
        [list(spec.get("driver_args", ["{poc}"]))]
        if spec.get("driver")
        else _invocations(spec)
    )
    for role, tree in trees.items():
        failed = False
        for candidate in invocations:
            output, status, _hung = _run_tool(
                tree,
                str(spec.get("driver_binary", spec["tool"])),
                list(candidate),
                poc,
                runtime,
                image,
            )
            if _failed(output, status):
                failed = True
                break
        if role == "vuln" and not failed:
            return False
        if role == "fixed" and failed:
            return False
    return True


def check(
    spec: dict[str, Any], workdir: Path, runtime: str, image: str
) -> dict[str, Any]:
    """Check one upstream case: does the proof of concept discriminate?"""
    outcome: dict[str, Any] = {"key": spec["key"], "cve": spec["cve"], "ok": False}
    repo = workdir / str(spec["name"])
    if not _clone(str(spec["repo"]), repo):
        outcome["error"] = "could not clone"
        return outcome

    trees: dict[str, Path] = {}
    for role, rev in (("vuln", f"{spec['fix']}^"), ("fixed", str(spec["fix"]))):
        tree = workdir / "trees" / f"{spec['key']}-{role}"
        if not _export(repo, rev, tree):
            outcome["error"] = f"could not export {role}"
            return outcome
        trees[role] = tree

    # The builds come first: the fuzzer needs the tool to exist.
    for role, tree in trees.items():
        steps = list(spec["build"])
        if spec.get("driver"):
            (tree / "verdis_driver.c").write_text(
                str(spec["driver"]), encoding="utf-8"
            )
            steps.append(
                "./libtool --mode=link cc -fsanitize=address -g -O0 "
                "-I. -Ilibarchive verdis_driver.c -o verdis_driver "
                "./libarchive.la"
            )
        ok, log = _build(tree, steps, runtime, image)
        if not ok:
            outcome["error"] = f"the {role} build failed"
            outcome["log"] = log[-3000:]
            return outcome

    # The proof of concept: the one the fix brought, or one found by
    # fuzzing the tool the fix touched.
    poc = workdir / "trees" / f"{spec['key']}-poc" / str(spec["poc_name"])
    poc.parent.mkdir(parents=True, exist_ok=True)
    poc_source = trees["fixed"] / str(spec.get("poc_from", ""))
    if spec.get("poc_from") and poc_source.is_file():
        if poc_source.suffix == ".uu":
            poc.write_bytes(
                _decode_uu(poc_source.read_text(encoding="utf-8", errors="replace"))
            )
        else:
            poc.write_bytes(poc_source.read_bytes())
    elif spec.get("seeds_url"):
        seeds = _seeds(spec, workdir)
        if seeds is None:
            outcome["error"] = "could not get the seeds"
            return outcome
        _write_wrapper(workdir)
        found = _fuzz_for_poc(
            trees["vuln"], spec, poc, runtime, image, seeds, workdir
        )
        if found is None:
            outcome["error"] = "fuzzing found no proof of concept"
            return outcome
        # Several crashes may have been collected; the one that
        # discriminates is the one the fix addresses.
        candidates = sorted(poc.parent.glob("crash-*"))
        if candidates:
            for candidate in candidates:
                if _discriminates(
                    trees, spec, candidate, runtime, image
                ):
                    shutil.copy2(candidate, poc)
                    break
            else:
                poc.unlink(missing_ok=True)
                outcome["error"] = (
                    "the crashes the fuzzer found are not the ones the fix addresses"
                )
                return outcome
    else:
        outcome["error"] = f"the fixed tree has no {spec.get('poc_from')}"
        return outcome
    outcome["poc_size"] = poc.stat().st_size

    if spec.get("driver"):
        invocations = [list(spec.get("driver_args", ["{poc}"]))]
    else:
        invocations = _invocations(spec)

    results: dict[str, Any] = {}
    for role, tree in trees.items():
        best: dict[str, Any] = {
            "failed": False,
            "status": "",
            "output": "",
            "args": [],
        }
        for candidate in invocations:
            output, status, _hung = _run_tool(
                tree,
                str(spec.get("driver_binary", spec["tool"])),
                list(candidate),
                poc,
                runtime,
                image,
            )
            failed = _failed(output, status)
            if failed:
                best = {
                    "failed": True,
                    "status": status,
                    "output": output[-1500:],
                    "args": list(candidate),
                }
                break
            best = {
                "failed": False,
                "status": status,
                "output": output[-800:],
                "args": list(candidate),
            }
        results[role] = best

    outcome["vulnerable_failed"] = results["vuln"]["failed"]
    outcome["fixed_failed"] = results["fixed"]["failed"]
    outcome["vulnerable_output"] = results["vuln"]["output"]
    outcome["fixed_output"] = results["fixed"]["output"]
    outcome["tool_args"] = results["vuln"]["args"] or invocations[0]
    outcome["ok"] = bool(
        results["vuln"]["failed"] and not results["fixed"]["failed"]
    )
    outcome["poc"] = str(poc)
    outcome["trees"] = {role: str(tree) for role, tree in trees.items()}
    return outcome


def _command(spec: dict[str, Any]) -> str:
    """The command the report gives."""
    poc_name = str(spec.get("poc_name", "poc.bin"))
    if spec.get("driver_args"):
        return "./{} {}".format(
            spec.get("driver_binary", "verdis_driver"), poc_name
        )
    invocations = _invocations(spec)
    parts = invocations[0] if invocations else []
    return "./{} {}".format(
        spec["tool"],
        " ".join(str(part).replace("{poc}", poc_name) for part in parts),
    )


def _report(spec: dict[str, Any]) -> str:
    """The report for an upstream case."""
    return f"""\
# {spec['title']}

**Version**: {spec.get('version', 'unknown')}
**Component**: {spec['component']}
**Class**: {spec.get('cwe', 'CWE-125')}

This is {spec['cve']} ({spec['advisory']}), in {spec['name']}. A crafted
file makes the program read or write outside the buffer it was given.

## Steps to reproduce

```
{_command(spec)}
```

The program aborts with a sanitizer diagnostic.

## Impact

{spec['impact']}

## Provenance

The proof of concept is the one that came with the fix, from the
upstream repository. The target is the upstream source at the commit
before the fix.
"""


def emit(
    spec: dict[str, Any],
    outcome: dict[str, Any],
    vendor: Path,
    workdir: Path | None = None,
) -> Path | None:
    """Vendor an admitted case: the target, the proof of concept, the recipe.

    The corpus has to be buildable without a network, so the upstream
    target is vendored: the source tree that carries the defect, the
    proof of concept, and the metadata that says where it came from.
    The benchmark then builds it in the sandbox like any other target.
    """
    trees = outcome.get("trees") or {}
    vulnerable = trees.get("vuln")
    poc = outcome.get("poc")
    if not vulnerable or not poc:
        return None
    directory = vendor / str(spec["key"])
    if directory.exists():
        shutil.rmtree(directory, ignore_errors=True)
    directory.mkdir(parents=True)

    # The vendored tree is a *clean* export: the tree that was built in
    # place carries the build artefacts, and the corpus builds the
    # target itself.
    repo = (workdir or Path.home() / ".cache" / "verdis-upstream") / str(
        spec["name"]
    )
    clean = directory / "clean"
    if clean.exists():
        shutil.rmtree(clean, ignore_errors=True)
    clean.mkdir(parents=True)
    export = subprocess.run(
        ["git", "archive", f"{spec['fix']}^"],
        cwd=str(repo),
        capture_output=True,
        check=False,
        timeout=900,
    )
    if export.returncode != 0:
        return None
    unpack = subprocess.run(
        ["tar", "x", "-C", str(clean)],
        input=export.stdout,
        capture_output=True,
        check=False,
        timeout=900,
    )
    if unpack.returncode != 0:
        return None
    archive = directory / "target.tar.xz"
    with archive.open("wb") as handle:
        subprocess.run(
            ["tar", "cJf", "-", "-C", str(clean), "."],
            stdout=handle,
            check=True,
            timeout=1800,
        )
    shutil.rmtree(clean, ignore_errors=True)

    poc_dir = directory / "poc"
    poc_dir.mkdir()
    shutil.copy2(poc, poc_dir / str(spec["poc_name"]))

    meta = {key: value for key, value in spec.items() if key != "driver"}
    meta["driver_source"] = spec.get("driver", "")
    meta["report"] = _report(spec)
    (directory / "meta.json").write_text(
        json.dumps(meta, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return directory


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--key", default="")
    parser.add_argument("--all", action="store_true")
    parser.add_argument("--list", action="store_true")
    parser.add_argument("--runtime", default="podman")
    parser.add_argument("--image", default="ghcr.io/usualdork/verdis/base:latest")
    parser.add_argument(
        "--workdir", default=str(Path.home() / ".cache" / "verdis-upstream")
    )
    parser.add_argument("--json", default="")
    parser.add_argument(
        "--emit",
        action="store_true",
        help="vendor the admitted cases so the corpus can build them offline",
    )
    parser.add_argument(
        "--vendor",
        default=str(REPO_ROOT / "benchmark" / "upstream"),
        help="where the vendored upstream cases go",
    )
    args = parser.parse_args(argv)

    if args.list:
        for spec in CASES:
            print(f"{spec['key']:<34} {spec['cve']:<20} {spec['title']}")
        return 0

    workdir = Path(args.workdir)
    workdir.mkdir(parents=True, exist_ok=True)

    results: list[dict[str, Any]] = []
    for spec in CASES:
        if args.key and spec["key"] != args.key:
            continue
        if not args.key and not args.all:
            continue
        print(f"== {spec['key']} ({spec['cve']})")
        outcome = check(spec, workdir, args.runtime, args.image)
        results.append(outcome)
        if outcome.get("ok"):
            print(
                f"    admitted: the proof of concept fails the vulnerable build "
                f"({outcome['poc_size']} bytes) and not the fixed one"
            )
            if args.emit:
                directory = emit(
                    spec, outcome, Path(args.vendor), Path(args.workdir)
                )
                if directory is not None:
                    print(f"    vendored at {directory}")
        else:
            print(f"    not admissible: {outcome.get('error', 'it does not discriminate')}")
            print(f"      vulnerable failed: {outcome.get('vulnerable_failed')}")
            print(f"      fixed failed: {outcome.get('fixed_failed')}")
    if args.json:
        Path(args.json).write_text(json.dumps(results, indent=2), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
