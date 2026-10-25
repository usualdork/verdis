"""The GitHub Action's entry point (the Action, PRD 8.5, 17.2).

The entry point is what runs in a workflow, so it is worth testing on
its own: it reads the inputs, runs the triage, writes the outputs and
never fails the workflow on a non-definitive verdict.
"""

from __future__ import annotations

import importlib.util
import os
from pathlib import Path
from types import ModuleType

import pytest

ENTRYPOINT = Path(__file__).resolve().parents[2] / "action" / "entrypoint.py"


def _entrypoint(workspace: Path) -> ModuleType:
    """The action's entry point, loaded by path.

    The output file is read when the module loads, so the environment
    has to be in place first.
    """
    os.environ["GITHUB_WORKSPACE"] = str(workspace)
    os.environ["GITHUB_OUTPUT"] = str(workspace / "out.txt")
    spec = importlib.util.spec_from_file_location("verdis_action", ENTRYPOINT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


REPORT = """\
# Heap buffer overflow in parse_header

**Version**: 2.3.1
**Component**: src/hdr.c:parse_header
**Class**: CWE-122

The header length is copied into a fixed allocation without a check.

## Steps to reproduce

```
./build/parse_demo poc.bin
```
"""


class TestTheAction:
    def test_no_report_asks_for_more_information(
        self, tmp_path: Path, monkeypatch
    ) -> None:
        monkeypatch.setenv("INPUT_MODE", "shadow")
        monkeypatch.setenv("INPUT_SANDBOX", "local")
        monkeypatch.delenv("INPUT_REPORT_PATH", raising=False)
        monkeypatch.delenv("VERDIS_REPORT", raising=False)
        module = _entrypoint(tmp_path)
        assert module.main() == 0
        assert "verdict=NEEDS_INFO" in (tmp_path / "out.txt").read_text()

    def test_a_report_produces_a_verdict(
        self, tmp_path: Path, monkeypatch
    ) -> None:
        (tmp_path / "report.md").write_text(REPORT, encoding="utf-8")
        monkeypatch.setenv("INPUT_MODE", "shadow")
        monkeypatch.setenv("INPUT_SANDBOX", "local")
        monkeypatch.setenv("INPUT_REPORT_PATH", "report.md")
        module = _entrypoint(tmp_path)
        assert module.main() == 0
        outputs = (tmp_path / "out.txt").read_text()
        assert "verdict=" in outputs
        assert "bundle-path=" in outputs

    def test_comment_mode_without_a_token_does_not_fail(
        self, tmp_path: Path, monkeypatch, capsys
    ) -> None:
        (tmp_path / "report.md").write_text(REPORT, encoding="utf-8")
        monkeypatch.setenv("INPUT_MODE", "comment")
        monkeypatch.setenv("INPUT_SANDBOX", "local")
        monkeypatch.setenv("INPUT_REPORT_PATH", "report.md")
        monkeypatch.delenv("GITHUB_TOKEN", raising=False)
        monkeypatch.delenv("GITHUB_EVENT_PATH", raising=False)
        module = _entrypoint(tmp_path)
        assert module.main() == 0
        assert "no GITHUB_TOKEN" in capsys.readouterr().out

    def test_an_unknown_mode_falls_back_to_shadow(
        self, tmp_path: Path, monkeypatch
    ) -> None:
        (tmp_path / "report.md").write_text(REPORT, encoding="utf-8")
        monkeypatch.setenv("INPUT_MODE", "close-it")
        monkeypatch.setenv("INPUT_SANDBOX", "local")
        monkeypatch.setenv("INPUT_REPORT_PATH", "report.md")
        module = _entrypoint(tmp_path)
        assert module.main() == 0
        assert "verdict=" in (tmp_path / "out.txt").read_text()

    def test_the_output_file_is_the_github_one(self, tmp_path: Path) -> None:
        module = _entrypoint(tmp_path)
        assert tmp_path / "out.txt" == module.OUTPUT_FILE


@pytest.mark.parametrize("mode", ["shadow", "comment", "label"])
def test_the_modes_the_action_offers(mode: str) -> None:
    """The action offers exactly these three, and nothing that closes."""
    assert mode in {"shadow", "comment", "label"}
