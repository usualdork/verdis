"""Determinism: the same input, the same verdict, three runs (PRD 13.2).

A triage tool that gives different answers for the same report is
worse than one that gives a wrong answer: a maintainer cannot tell
whether the tool is uncertain or unstable, and the evidence bundle
stops being evidence.

The test runs the whole pipeline three times over the same report and
the same target, and requires the same verdict, the same reasons and
the same evidence.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from verdis.config import Config
from verdis.intake.file import FileIntake
from verdis.pipeline.orchestrator import Orchestrator
from verdis.sandbox.local import LocalBackend
from verdis.storage.db import Store
from verdis.storage.evidence import EvidenceStore

REPORT = """\
# Heap buffer overflow in parse_header

**Version**: 2.3.1
**Component**: src/target.c:parse_header
**Class**: CWE-122

Parsing a crafted header causes a heap buffer overflow in `parse_header()`.

## Steps to reproduce

```
./build/target poc.bin
```

AddressSanitizer reports a heap-buffer-overflow in parse_header.
"""

SOURCE = """\
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void parse_header(const unsigned char *buf, size_t len) {
    unsigned char *header = (unsigned char *)malloc(16);
    if (header == NULL) {
        return;
    }
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

MAKEFILE = """\
CC ?= cc
CFLAGS ?= -fsanitize=address -fno-omit-frame-pointer -g -O0
TARGET = build/target

all: $(TARGET)

$(TARGET): src/target.c
\tmkdir -p build
\t$(CC) $(CFLAGS) -o $(TARGET) src/target.c
"""

RECIPE = """\
language: c
build:
  system: make
  steps:
    - make
run:
  workdir: /work
  repeat: 1
  env:
    ASAN_OPTIONS: detect_leaks=0
"""


@pytest.fixture()
def target(tmp_path: Path) -> Path:
    project = tmp_path / "project"
    (project / "src").mkdir(parents=True)
    (project / ".verdis").mkdir()
    (project / "src" / "target.c").write_text(SOURCE, encoding="utf-8")
    (project / "Makefile").write_text(MAKEFILE, encoding="utf-8")
    (project / ".verdis" / "recipe.yml").write_text(RECIPE, encoding="utf-8")
    (project / "poc.bin").write_bytes(b"A" * 64)
    return project


def _triage(target: Path, tmp_path: Path, run: int):
    """One run of the whole pipeline."""
    workdir = tmp_path / f"run{run}"
    evidence = EvidenceStore(workdir / "evidence")
    report = workdir / "report.md"
    report.write_text(REPORT, encoding="utf-8")
    intake = FileIntake(evidence)
    outcome = intake.fetch(report, repo=str(target))
    orchestrator = Orchestrator(
        config=Config(mode="shadow", sandbox="local", repeats=1),
        store=Store(workdir / "store"),
        evidence=evidence,
        backend=LocalBackend(),
    )
    return orchestrator.triage(outcome.report, repo_path=target)


class TestDeterminism:
    def test_the_same_report_gives_the_same_verdict_three_times(
        self, target: Path, tmp_path: Path
    ) -> None:
        verdicts = []
        for run in range(3):
            result = _triage(target, tmp_path, run)
            verdicts.append(
                (
                    str(result.verdict.verdict),
                    result.verdict.why,
                    tuple(point.summary for point in result.verdict.evidence),
                    str(result.verdict.build.status) if result.verdict.build else "",
                )
            )
        assert verdicts[0] == verdicts[1] == verdicts[2]

    def test_the_verdict_is_the_one_the_evidence_supports(
        self, target: Path, tmp_path: Path
    ) -> None:
        result = _triage(target, tmp_path, 0)
        assert str(result.verdict.verdict) == "REPRODUCED"
