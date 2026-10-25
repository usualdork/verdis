"""Golden-file tests (PRD 13.2).

Extraction and rendering are compared against committed golden files, so
an unintended change in the output is visible in the diff.

Run with ``pytest tests/golden --update-golden`` to refresh the files
after an intentional change.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from verdis.emit.card import render_card
from verdis.extract.extractor import ClaimExtractor
from verdis.extract.providers import NullProvider
from verdis.schemas.common import Verdict, VerdictFlag, VerdictTier
from verdis.schemas.verdict import EvidencePoint, VerdictResult

GOLDEN_DIR = Path(__file__).parent / "files"

REPORTS: dict[str, str] = {
    "heap_overflow": """\
# Heap buffer overflow in parse_header

**Version**: 2.3.1
**Component**: src/hdr.c:parse_header
**Class**: CWE-122

Parsing a crafted header causes a heap buffer overflow in `parse_header()`.

## Steps to reproduce

```
./build/parse_demo poc.bin
```

AddressSanitizer reports a heap-buffer-overflow in parse_header.
""",
    "command_injection": """\
# Command injection in the backup tool

**Version**: 1.4.0

The `--label` option is passed to a shell, so it allows command injection.

```
./backup --label "; id"
```

This gives remote code execution.
""",
    "vague": """\
# Something might be wrong

I am not sure, but the parser seems to misbehave with long inputs.
""",
    "with_rrs": """\
# Heap buffer overflow in parse_header

```yaml
rrs: 0.1
target:
  repo: https://github.com/example/libfoo
  ref: v2.3.1
claim:
  class: CWE-122
  component: src/hdr.c:parse_header
  impact: memory corruption leading to crash
steps:
  - build: default
  - run: ./build/parse_demo poc.bin
inputs:
  - path: poc.bin
    sha256: 0000000000000000000000000000000000000000000000000000000000000000
expect:
  oracle: sanitizer
  signature: heap-buffer-overflow in parse_header
config:
  default: true
```
""",
    "out_of_scope": """\
# Local denial of service in the report generator

**Version**: 2.3.1
**Class**: CWE-400

```
./build/report_demo --rows 100000000 big.csv
```

This is a denial of service from unbounded local CLI input.
""",
}


def _update(request: pytest.FixtureRequest) -> bool:
    return bool(request.config.getoption("--update-golden"))


@pytest.fixture()
def update(request: pytest.FixtureRequest) -> bool:
    return _update(request)


class TestExtractionGolden:
    @pytest.mark.parametrize("name", sorted(REPORTS))
    def test_the_claim_matches_the_golden_file(
        self, name: str, update: bool
    ) -> None:
        extractor = ClaimExtractor(NullProvider())
        outcome = extractor.extract(REPORTS[name])
        payload = {
            "method": outcome.method,
            "claim": json.loads(outcome.claim.model_dump_json()),
        }
        path = GOLDEN_DIR / f"claim-{name}.json"
        if update:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(
                json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8"
            )
            return
        assert path.is_file(), f"missing golden file {path}"
        expected = json.loads(path.read_text(encoding="utf-8"))
        assert payload == expected


def _verdict() -> VerdictResult:
    return VerdictResult(
        verdict=Verdict.REPRODUCED,
        tier=VerdictTier.TIER_1,
        report_id="VDS-0042",
        target_ref="libfoo@v2.3.1",
        why="The submitted PoC triggers a heap-buffer-overflow in parse_header().",
        evidence=(
            EvidencePoint(summary="ASan reports heap-buffer-overflow, frame #1 parse_header"),
            EvidencePoint(summary="The same PoC is clean on v2.3.2 (FIXED_AT_HEAD)"),
            EvidencePoint(summary="No network attempts; no writes outside /work"),
        ),
        flags=(VerdictFlag.FIXED_AT_HEAD,),
        not_established=("exploitability beyond a crash",),
        next_action="confirm severity; consider a coordinated release",
    )


class TestCardGolden:
    def test_the_card_matches_the_golden_file(self, update: bool) -> None:
        card = render_card(_verdict(), bundle_path="bundles/VDS-0042/")
        path = GOLDEN_DIR / "card-reproduced.md"
        if update:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(card, encoding="utf-8")
            return
        assert path.is_file(), f"missing golden file {path}"
        assert card == path.read_text(encoding="utf-8")

    def test_the_not_reproduced_card_matches(self, update: bool) -> None:
        verdict = VerdictResult(
            verdict=Verdict.NOT_REPRODUCED,
            report_id="VDS-0043",
            target_ref="libfoo@v2.3.1",
            why="the PoC ran and no oracle fired",
            next_action="reply with what was tried",
            not_established=("that the code is not vulnerable",),
        )
        card = render_card(verdict)
        path = GOLDEN_DIR / "card-not-reproduced.md"
        if update:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(card, encoding="utf-8")
            return
        assert path.is_file(), f"missing golden file {path}"
        assert card == path.read_text(encoding="utf-8")
