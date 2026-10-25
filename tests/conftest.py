"""Shared fixtures for the Verdis test suite."""

from __future__ import annotations

import os
import shutil
import subprocess
import textwrap
from pathlib import Path

import pytest

from verdis.schemas.claim import Claim, ClaimComponent, ExpectedObservable, PoCCommand
from verdis.schemas.common import ReportSource
from verdis.schemas.plan import (
    BuildStep,
    CheckoutStep,
    CopyStep,
    ExpectStep,
    Plan,
    RunStep,
)
from verdis.schemas.report import Report, Target
from verdis.storage.db import Store
from verdis.storage.evidence import EvidenceStore

# -- stores -------------------------------------------------------------


@pytest.fixture()
def store(tmp_path: Path) -> Store:
    return Store(tmp_path / "store")


@pytest.fixture()
def evidence(tmp_path: Path) -> EvidenceStore:
    return EvidenceStore(tmp_path / "evidence")


# -- reports ------------------------------------------------------------

REPORT_TEXT = """\
# Heap overflow in parse_header

**Version**: 2.3.1
**Component**: src/hdr.c:parse_header
**Class**: CWE-122

Parsing a crafted header causes a heap buffer overflow in `parse_header()`.

## Steps to reproduce

```
./build/parse_demo poc.bin
```

The AddressSanitizer reports a heap-buffer-overflow in parse_header.
"""


@pytest.fixture()
def report_text() -> str:
    return REPORT_TEXT


@pytest.fixture()
def report() -> Report:
    return Report(
        id=Report.compute_id(REPORT_TEXT, Target(repo=".", ref="v2.3.1"), ReportSource.FILE),
        source=ReportSource.FILE,
        body=REPORT_TEXT,
        subject="Heap overflow in parse_header",
        reporter="reporter@example.org",
        target=Target(repo=".", ref="v2.3.1"),
    )


@pytest.fixture()
def claim() -> Claim:
    return Claim(
        component=ClaimComponent(name="parse_header", file="src/hdr.c", line=212),
        vuln_class="CWE-122",
        affected_version="2.3.1",
        poc_commands=(PoCCommand(command="./build/parse_demo poc.bin"),),
        impact={"summary": "memory corruption"},
        expected=ExpectedObservable(kind="sanitizer", signature="heap-buffer-overflow"),
    )


# -- plans --------------------------------------------------------------


@pytest.fixture()
def plan() -> Plan:
    return Plan(
        steps=(
            CheckoutStep(ref="v2.3.1"),
            BuildStep(recipe="cmake", flags=("asan", "ubsan")),
            CopyStep(artifact="poc.bin", to="/work/poc.bin"),
            RunStep(cmd="./build/parse_demo /work/poc.bin", timeout="30s", repeat=3),
            ExpectStep(oracle="sanitizer", signature="heap-buffer-overflow", function="parse_header"),
        ),
        comparison_ref="v2.3.2",
    )


# -- fixture projects ---------------------------------------------------

C_SOURCE = """\
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* parse_header copies the first `len` bytes of the buffer into a
 * 16-byte heap allocation. The length is never checked. */
void parse_header(const unsigned char *buf, size_t len) {
    unsigned char *header = (unsigned char *)malloc(16);
    if (header == NULL) {
        return;
    }
    /* Bug: len is not checked against the header size. */
    memcpy(header, buf, len);
    printf("magic=%02x%02x%02x%02x\\n", header[0], header[1], header[2], header[3]);
    free(header);
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s <file>\\n", argv[0]);
        return 2;
    }
    FILE *f = fopen(argv[1], "rb");
    if (!f) {
        fprintf(stderr, "cannot open %s\\n", argv[1]);
        return 2;
    }
    unsigned char buf[4096];
    size_t n = fread(buf, 1, sizeof(buf), f);
    fclose(f);
    parse_header(buf, n);
    return 0;
}
"""

C_MAKEFILE = """\
CC ?= clang
CFLAGS ?= -fsanitize=address -fno-omit-frame-pointer -g -O0
TARGET = build/parse_demo

all: $(TARGET)

$(TARGET): src/hdr.c
\tmkdir -p build
\t$(CC) $(CFLAGS) -o $(TARGET) src/hdr.c

clean:
\trm -rf build
"""

PY_SOURCE = '''\
"""A tiny parser with a bug the end-to-end tests can trigger."""


def parse_header(payload: bytes) -> bytes:
    """Return the first four bytes of the payload."""
    return payload[:4].upper()


def main() -> int:
    import sys

    if len(sys.argv) < 2:
        print("usage: parse_demo.py <file>", file=sys.stderr)
        return 2
    with open(sys.argv[1], "rb") as handle:
        data = handle.read()
    print("magic=" + parse_header(data).hex())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
'''


@pytest.fixture(scope="session")
def has_clang() -> bool:
    return shutil.which("clang") is not None or shutil.which("cc") is not None


@pytest.fixture()
def c_project(tmp_path: Path) -> Path:
    """A tiny C project with a real heap overflow, buildable with ASan."""
    project = tmp_path / "libfoo"
    (project / "src").mkdir(parents=True)
    (project / "src" / "hdr.c").write_text(C_SOURCE, encoding="utf-8")
    (project / "Makefile").write_text(C_MAKEFILE, encoding="utf-8")
    (project / "poc.bin").write_bytes(b"A" * 64)
    return project


@pytest.fixture()
def c_project_fixed(tmp_path: Path) -> Path:
    """The same project with the overflow fixed, for the negative case."""
    project = tmp_path / "libfoo-fixed"
    (project / "src").mkdir(parents=True)
    (project / "src" / "hdr.c").write_text(
        C_SOURCE.replace(
            "    /* Bug: len is not checked against the header size. */\n"
            "    memcpy(header, buf, len);",
            "    /* Fixed: the length is checked against the header size. */\n"
            "    if (len > 16) {\n"
            "        len = 16;\n"
            "    }\n"
            "    memcpy(header, buf, len);",
        ),
        encoding="utf-8",
    )
    (project / "Makefile").write_text(C_MAKEFILE, encoding="utf-8")
    (project / "poc.bin").write_bytes(b"A" * 64)
    return project


@pytest.fixture()
def git_repo(tmp_path: Path) -> Path:
    """A small git repository with a tag and a moving branch."""
    repo = tmp_path / "repo"
    repo.mkdir()
    env = {
        "PATH": "/usr/bin:/bin:/usr/local/bin",
        "HOME": str(repo),
        "GIT_AUTHOR_NAME": "t",
        "GIT_AUTHOR_EMAIL": "t@example.org",
        "GIT_COMMITTER_NAME": "t",
        "GIT_COMMITTER_EMAIL": "t@example.org",
    }
    subprocess.run(
        ["git", "init", "-b", "main"], cwd=str(repo), check=True, env=env,
        capture_output=True,
    )
    (repo / "file.txt").write_text("first\n", encoding="utf-8")
    subprocess.run(
        ["git", "add", "file.txt"], cwd=str(repo), check=True, env=env, capture_output=True
    )
    subprocess.run(
        ["git", "commit", "-m", "first"], cwd=str(repo), check=True, env=env,
        capture_output=True,
    )
    # The tag points at the first commit; the branch moves on.
    subprocess.run(
        ["git", "tag", "v1.0"], cwd=str(repo), check=True, env=env, capture_output=True
    )
    (repo / "file.txt").write_text("second\n", encoding="utf-8")
    subprocess.run(
        ["git", "add", "file.txt"], cwd=str(repo), check=True, env=env, capture_output=True
    )
    subprocess.run(
        ["git", "commit", "-m", "second"], cwd=str(repo), check=True, env=env,
        capture_output=True,
    )
    return repo


@pytest.fixture()
def py_project(tmp_path: Path) -> Path:
    """A tiny Python project."""
    project = tmp_path / "pyfoo"
    project.mkdir(parents=True)
    (project / "parse_demo.py").write_text(PY_SOURCE, encoding="utf-8")
    (project / "poc.bin").write_bytes(b"hello")
    return project


@pytest.fixture()
def policy_file(tmp_path: Path) -> Path:
    path = tmp_path / ".verdis" / "policy.yml"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        textwrap.dedent(
            """\
            supported_versions: ['2.x']
            in_scope: [parser, network-client]
            excluded_classes:
              - id: needs-malicious-config
                description: Requires attacker-controlled configuration files
            evidence_requirements:
              poc_required: true
              default_config_only: true
            """
        ),
        encoding="utf-8",
    )
    return path


@pytest.fixture()
def sandbox_env() -> dict[str, str]:
    """An environment with no inherited secrets."""
    return {"PATH": os.environ.get("PATH", "/usr/bin:/bin")}


def pytest_addoption(parser: pytest.Parser) -> None:
    parser.addoption(
        "--update-golden",
        action="store_true",
        default=False,
        help="refresh the golden files instead of comparing against them",
    )
