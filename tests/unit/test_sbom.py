"""The software bill of materials (section 17.1)."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]


class TestTheBillOfMaterials:
    def test_it_is_well_formed(self, tmp_path: Path) -> None:
        out = tmp_path / "sbom.json"
        result = subprocess.run(
            [
                sys.executable,
                str(REPO_ROOT / "tools" / "sbom.py"),
                "--out",
                str(out),
            ],
            capture_output=True,
            text=True,
            timeout=300,
            check=False,
        )
        assert result.returncode == 0, result.stderr
        document = json.loads(out.read_text(encoding="utf-8"))
        assert document["bomFormat"] == "CycloneDX"
        assert document["metadata"]["component"]["name"] == "verdis"
        assert document["metadata"]["component"]["version"]
        assert document["components"], "the bill of materials is empty"
        for component in document["components"]:
            assert component["name"]
            assert component["version"]
            assert component["purl"].startswith("pkg:pypi/")
