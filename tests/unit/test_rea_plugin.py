"""The optional REA preflight plugin (PRD 17.1, "the optional REA plugin").

The plugin inspects binaries with REA, which is not a sandbox, so it
refuses to run unless it is told it is inside one. The preflight has to
load it when it is configured, use it when it can run, and carry on
without it when it cannot.
"""

from __future__ import annotations

from pathlib import Path

from verdis.preflight.preflight import Preflight, load_plugin
from verdis.schemas.report import Attachment

PLUGIN = '''\
"""A stand-in for the REA plugin."""

import os
import shutil

from verdis.schemas.preflight import PreflightFinding, RiskLevel


class ReaPreflight:
    """A plugin that reports what it found.

    Like the real one, it refuses to run unless it is told it is inside
    the sandbox: REA runs the code it inspects.
    """

    def __init__(self, binary: str = "rea", timeout: int = 300) -> None:
        self.binary = binary
        self.timeout = timeout

    def available(self) -> bool:
        if os.environ.get("VERDIS_SANDBOXED", "") not in {"1", "true", "yes"}:
            return False
        return shutil.which(self.binary) is not None

    def findings(self, path):
        return [
            PreflightFinding(
                code="rea-network-imports",
                severity=RiskLevel.MEDIUM,
                message="the plugin found network imports",
                weight=20,
            )
        ]
'''

UNLOADABLE = "this is not python("

FAILING_PLUGIN = '''\
"""A plugin that fails when it is used."""

from verdis.schemas.preflight import PreflightFinding, RiskLevel


class ReaPreflight:
    def available(self) -> bool:
        return True

    def findings(self, path):
        raise RuntimeError("the plugin fell over")
'''


def _attachment(path: Path) -> Attachment:
    return Attachment(
        name=path.name,
        path=str(path),
        sha256="0" * 64,
        size=path.stat().st_size,
    )


class TestTheLoader:
    def test_a_plugin_that_does_not_exist_is_not_loaded(self, tmp_path: Path) -> None:
        assert load_plugin(str(tmp_path / "nope.py")) is None

    def test_nothing_configured_is_not_loaded(self) -> None:
        assert load_plugin("") is None

    def test_a_plugin_that_does_not_parse_is_not_loaded(self, tmp_path: Path) -> None:
        path = tmp_path / "broken.py"
        path.write_text(UNLOADABLE, encoding="utf-8")
        assert load_plugin(str(path)) is None

    def test_a_plugin_is_loaded(self, tmp_path: Path) -> None:
        path = tmp_path / "plugin.py"
        path.write_text(PLUGIN, encoding="utf-8")
        module = load_plugin(str(path))
        assert module is not None
        assert hasattr(module, "ReaPreflight")

    def test_a_plugin_that_raises_on_import_is_not_loaded(self, tmp_path: Path) -> None:
        path = tmp_path / "raises.py"
        path.write_text("raise RuntimeError('no')\n", encoding="utf-8")
        assert load_plugin(str(path)) is None


class TestThePluginIsUsed:
    def test_its_findings_join_the_analysis(
        self, tmp_path: Path, monkeypatch
    ) -> None:
        plugin = tmp_path / "plugin.py"
        plugin.write_text(PLUGIN, encoding="utf-8")
        binary = tmp_path / "a.bin"
        binary.write_bytes(b"\x7fELF" + b"\x00" * 64)
        # The plugin only runs inside the sandbox, with REA present.
        monkeypatch.setenv("VERDIS_SANDBOXED", "1")
        monkeypatch.setattr("shutil.which", lambda name: "/usr/bin/rea")
        preflight = Preflight(plugin=str(plugin))
        result = preflight.inspect(_attachment(binary))
        assert any(f.code == "rea-network-imports" for f in result.findings)

    def test_a_plugin_that_cannot_run_changes_nothing(self, tmp_path: Path) -> None:
        plugin = tmp_path / "plugin.py"
        plugin.write_text(PLUGIN, encoding="utf-8")
        binary = tmp_path / "a.bin"
        binary.write_bytes(b"\x7fELF" + b"\x00" * 64)
        # The plugin refuses to run outside the sandbox.
        preflight = Preflight(plugin=str(plugin))
        result = preflight.inspect(_attachment(binary))
        assert not any(f.code == "rea-network-imports" for f in result.findings)

    def test_a_text_file_is_not_handed_to_the_plugin(self, tmp_path: Path) -> None:
        plugin = tmp_path / "plugin.py"
        plugin.write_text(PLUGIN, encoding="utf-8")
        text = tmp_path / "a.txt"
        text.write_text("hello\n", encoding="utf-8")
        preflight = Preflight(plugin=str(plugin))
        result = preflight.inspect(_attachment(text))
        assert not any(f.code == "rea-network-imports" for f in result.findings)

    def test_a_plugin_that_is_not_python_is_not_loaded(self, tmp_path: Path) -> None:
        path = tmp_path / "plugin.txt"
        path.write_text("not python\n", encoding="utf-8")
        assert load_plugin(str(path)) is None

    def test_a_plugin_that_fails_when_used_changes_nothing(
        self, tmp_path: Path
    ) -> None:
        plugin = tmp_path / "plugin.py"
        plugin.write_text(FAILING_PLUGIN, encoding="utf-8")
        binary = tmp_path / "a.bin"
        binary.write_bytes(b"\x7fELF" + b"\x00" * 64)
        preflight = Preflight(plugin=str(plugin))
        result = preflight.inspect(_attachment(binary))
        assert not any(f.code == "rea-network-imports" for f in result.findings)

    def test_no_plugin_at_all_changes_nothing(self, tmp_path: Path) -> None:
        binary = tmp_path / "a.bin"
        binary.write_bytes(b"\x7fELF" + b"\x00" * 64)
        preflight = Preflight()
        result = preflight.inspect(_attachment(binary))
        assert result.findings is not None

    def test_a_plugin_without_the_class_is_ignored(self, tmp_path: Path) -> None:
        plugin = tmp_path / "plugin.py"
        plugin.write_text("x = 1\n", encoding="utf-8")
        binary = tmp_path / "a.bin"
        binary.write_bytes(b"\x7fELF" + b"\x00" * 64)
        preflight = Preflight(plugin=str(plugin))
        result = preflight.inspect(_attachment(binary))
        assert result.findings is not None
