#!/usr/bin/env python3
"""Check that every program in the catalogue behaves as the corpus claims.

A benchmark is only worth anything if the cases are true. For each
program this script asserts, in a real container:

``crash``
    the vulnerable build fails on the PoC, the fixed build does not, and
    the vulnerable build does not fail on the benign input;

``output``
    the vulnerable and the fixed build both succeed, but print different
    answers, and the benign input prints the fixed answer;

``resource``
    the vulnerable build is killed by the memory limit on the PoC, and
    succeeds on the benign input.

A program that fails any of these is a broken case, not a hard case, and
the corpus builder refuses to emit it.

Usage::

    python benchmark/corpus/verify.py [--runtime podman]
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import tempfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "benchmark"))

from corpus.catalogue import PROGRAMMES, SIGNATURES  # noqa: E402

CFLAGS = "-fsanitize=address,undefined -fno-omit-frame-pointer -g -O0"

#: The C program is compiled; the Python one is only checked for syntax.
SCRIPT = """
mkdir -p /tmp/work
cp /probe/src.c /probe/fixed.c /probe/poc.bin /probe/benign.bin /tmp/work/
cd /tmp/work
cc {cflags} -o vulnerable src.c 2>/tmp/work/build.log
cc {cflags} -o fixed fixed.c 2>>/tmp/work/build.log
run() {{
  echo "### $1 begin"
  shift
  "$@" >/tmp/work/out.txt 2>/tmp/work/err.txt
  echo "status=$?"
  echo "--- stdout ---"
  cat /tmp/work/out.txt
  echo "--- stderr ---"
  cat /tmp/work/err.txt
  echo "### end"
}}
run poc ./vulnerable poc.bin
run fixed ./fixed poc.bin
run benign ./vulnerable benign.bin
"""

NODE_SCRIPT = """
mkdir -p /tmp/work
cp -r /probe/. /tmp/work/
cd /tmp/work
node --check vulnerable.js
node --check fixed.js
run() {
  echo "### $1 begin"
  shift
  "$@" >/tmp/work/out.txt 2>/tmp/work/err.txt
  echo "status=$?"
  echo "--- stdout ---"
  cat /tmp/work/out.txt
  echo "--- stderr ---"
  cat /tmp/work/err.txt
  echo "### end"
}
run poc node vulnerable.js poc.bin
run fixed node fixed.js poc.bin
run benign node vulnerable.js benign.bin
"""

GO_SCRIPT = """
mkdir -p /tmp/work/vuln /tmp/work/fixedsrc
cp -r /probe/. /tmp/work/
cd /tmp/work
mv vulnerable.go vuln/main.go
mv fixed.go fixedsrc/main.go
cp go.mod vuln/go.mod
cp go.mod fixedsrc/go.mod
cd /tmp/work/vuln
go build -o /tmp/work/vulnerable . 2>/tmp/work/build.log
cd /tmp/work/fixedsrc
go build -o /tmp/work/fixed . 2>>/tmp/work/build.log
echo "--- build log ---"
cat /tmp/work/build.log
cd /tmp/work
run() {
  echo "### $1 begin"
  shift
  "$@" >/tmp/work/out.txt 2>/tmp/work/err.txt
  echo "status=$?"
  echo "--- stdout ---"
  cat /tmp/work/out.txt
  echo "--- stderr ---"
  cat /tmp/work/err.txt
  echo "### end"
}
run poc ./vulnerable poc.bin
run fixed ./fixed poc.bin
run benign ./vulnerable benign.bin
"""

PYTHON_SCRIPT = """
mkdir -p /tmp/work
cp -r /probe/. /tmp/work/
cd /tmp/work
python3 -m py_compile vulnerable.py
python3 -m py_compile fixed.py
run() {
  echo "### $1 begin"
  shift
  "$@" >/tmp/work/out.txt 2>/tmp/work/err.txt
  echo "status=$?"
  echo "--- stdout ---"
  cat /tmp/work/out.txt
  echo "--- stderr ---"
  cat /tmp/work/err.txt
  echo "### end"
}
run poc python3 vulnerable.py poc.bin
run fixed python3 fixed.py poc.bin
run benign python3 vulnerable.py benign.bin
"""

def _run(argv: list[str], *, cwd: Path, timeout: int = 240) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        argv,
        cwd=str(cwd),
        capture_output=True,
        text=True,
        errors="replace",
        timeout=timeout,
        check=False,
    )


def _section(output: str, name: str) -> str:
    """The output of one run, delimited by the markers."""
    start = f"### {name} begin"
    end = "### end"
    if start not in output:
        return ""
    body = output.split(start, 1)[1]
    if end not in body:
        return ""
    return body.split(end, 1)[0]


def _status(section: str) -> str:
    for line in section.splitlines():
        if line.startswith("status="):
            return line.split("=", 1)[1].strip()
    return ""


def _stream(section: str, name: str) -> str:
    marker = f"--- {name} ---"
    if marker not in section:
        return ""
    body = section.split(marker, 1)[1]
    for other in ("stdout", "stderr"):
        other_marker = f"--- {other} ---"
        if other_marker in body:
            body = body.split(other_marker, 1)[0]
    return body.strip()


def _crashed(status: str, output: str) -> bool:
    """Did the run die, rather than exit?

    A program that rejects its input with a clean exit is not a crash:
    the fixed build is allowed to do exactly that. A fatal signal, or a
    sanitizer diagnostic, is a crash.
    """
    if "AddressSanitizer" in output or "runtime error:" in output:
        return True
    try:
        code = int(status)
    except ValueError:
        return True
    return code >= 128


def check(program, workdir: Path, image: str, runtime: str) -> dict[str, object]:
    """Compile and run one program inside the container."""
    (workdir / "poc.bin").write_bytes(program.poc)
    (workdir / "benign.bin").write_bytes(program.benign)
    for name, content in program.extra_files.items():
        path = workdir / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
    if program.language == "python":
        (workdir / "vulnerable.py").write_text(program.source, encoding="utf-8")
        (workdir / "fixed.py").write_text(program.fixed_source, encoding="utf-8")
    elif program.language == "node":
        (workdir / "vulnerable.js").write_text(program.source, encoding="utf-8")
        (workdir / "fixed.js").write_text(program.fixed_source, encoding="utf-8")
    elif program.language == "go":
        (workdir / "vulnerable.go").write_text(program.source, encoding="utf-8")
        (workdir / "fixed.go").write_text(program.fixed_source, encoding="utf-8")
    else:
        (workdir / "src.c").write_text(program.source, encoding="utf-8")
        (workdir / "fixed.c").write_text(program.fixed_source, encoding="utf-8")

    script = {
        "python": PYTHON_SCRIPT,
        "node": NODE_SCRIPT,
        "go": GO_SCRIPT,
    }.get(program.language, SCRIPT.format(cflags=CFLAGS))
    # On Linux a bind mount keeps the host owner and mode, and the image runs
    # as an unprivileged user, so the probe directory has to be open to it.
    workdir.chmod(0o777)
    args = [
        runtime,
        "run",
        "--rm",
        "--pull=never",
        "--network",
        "none",
        "--memory",
        "512m",
        "--pids-limit",
        "256",
        "-v",
        f"{workdir}:/probe:rw",
        image,
        "sh",
        "-c",
        script,
    ]
    result = _run(args, cwd=workdir, timeout=240)
    output = result.stdout + result.stderr

    poc = _section(output, "poc")
    fixed = _section(output, "fixed")
    benign = _section(output, "benign")
    poc_status = _status(poc)
    fixed_status = _status(fixed)
    benign_status = _status(benign)
    fixed_out = _stream(fixed, "stdout")
    benign_out = _stream(benign, "stdout")
    poc_out = _stream(poc, "stdout")
    poc_err = _stream(poc, "stderr")
    fixed_err = _stream(fixed, "stderr")
    benign_err = _stream(benign, "stderr")

    problems: list[str] = []
    if not poc_status:
        problems.append("the program did not run")
        return {"problems": problems, "output": output}

    poc_crashed = _crashed(poc_status, poc_err)
    fixed_crashed = _crashed(fixed_status, fixed_err)
    benign_crashed = _crashed(benign_status, benign_err)

    # The signature the report will name has to be in the output the
    # program really produces, or the case can never be reproduced and
    # the corpus is lying about itself.
    signature = SIGNATURES.get(program.key, ("", ""))[1]
    if (
        signature
        and program.detection == "crash"
        and signature.lower() not in (poc_err + poc_out).lower()
    ):
        problems.append(f"the expected signature {signature!r} is not in the output")
    elif (
        signature
        and program.detection == "output"
        and signature not in poc_out
    ):
        problems.append(
            f"the expected output {signature!r} is not in the vulnerable output"
        )

    if program.detection == "crash":
        if not poc_crashed:
            problems.append("the PoC did not crash the vulnerable build")
        if fixed_crashed:
            problems.append("the fixed build still crashed on the PoC")
        if benign_crashed:
            problems.append("the benign input crashed the vulnerable build")
    elif program.detection == "output":
        # The defect is a wrong answer, not a crash: the vulnerable
        # build prints the wrong thing, and the fixed build does not.
        if poc_crashed:
            problems.append("the PoC crashed the vulnerable build")
        if fixed_crashed:
            problems.append("the fixed build crashed on the PoC")
        if benign_crashed:
            problems.append("the benign input crashed the vulnerable build")
        if signature and signature in fixed_out:
            problems.append("the fixed build prints the wrong answer too")
        if signature and signature in benign_out:
            problems.append("the benign input produces the wrong answer too")
    elif program.detection == "resource":
        if not poc_crashed:
            problems.append("the PoC did not exhaust the memory limit")
        if fixed_crashed:
            problems.append("the fixed build still crashed on the PoC")
        if benign_crashed:
            problems.append("the benign input failed")
    else:  # pragma: no cover - a typo in the catalogue
        problems.append(f"unknown detection {program.detection!r}")

    return {
        "problems": problems,
        "output": output,
        "poc_status": poc_status,
        "fixed_status": fixed_status,
        "benign_status": benign_status,
        "fixed_out": fixed_out,
        "benign_out": benign_out,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", default="ghcr.io/usualdork/verdis/base:latest")
    parser.add_argument("--runtime", default="podman")
    parser.add_argument(
        "--workdir",
        default=str(Path.home() / ".cache" / "verdis-corpus"),
        help="a directory the container runtime can bind-mount",
    )
    parser.add_argument("--json", default="")
    args = parser.parse_args(argv)

    root = Path(args.workdir)
    root.mkdir(parents=True, exist_ok=True)

    failures: list[dict[str, object]] = []
    report: list[dict[str, object]] = []

    for program in PROGRAMMES:
        with tempfile.TemporaryDirectory(prefix="verdis-verify-", dir=str(root)) as tmp:
            outcome = check(program, Path(tmp), args.image, args.runtime)
        problems = list(outcome["problems"])
        entry = {
            "key": program.key,
            "detection": program.detection,
            "oracle": program.oracle,
            "ok": not problems,
            "problems": problems,
        }
        report.append(entry)
        if problems:
            failures.append(entry)
            print(f"FAIL {program.key}: {'; '.join(problems)}")
            tail = str(outcome["output"]).splitlines()[-14:]
            print("  " + "\n  ".join(tail))
        else:
            print(
                f"ok   {program.key:<28} {program.detection:<9} "
                f"poc={outcome.get('poc_status')} fixed={outcome.get('fixed_status')} "
                f"benign={outcome.get('benign_status')}"
            )

    print()
    good = len(PROGRAMMES) - len(failures)
    print(f"{good}/{len(PROGRAMMES)} programs behave as claimed")
    if args.json:
        Path(args.json).write_text(json.dumps(report, indent=2), encoding="utf-8")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
