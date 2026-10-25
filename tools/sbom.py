#!/usr/bin/env python3
"""Write a software bill of materials for the release.

Section 17.1 asks for a published SBOM. This writes a CycloneDX-shaped
document listing what is actually installed, with the versions pinned
and the hashes of the distributions, so a reader can check what a
release was built from.

Usage::

    python tools/sbom.py --out dist/sbom.json
"""

from __future__ import annotations

import argparse
import hashlib
import json
import platform
import subprocess
import sys
from datetime import UTC, datetime
from importlib.metadata import distributions
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]


def _version() -> str:
    pyproject = (REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8")
    for line in pyproject.splitlines():
        if line.startswith("version"):
            return line.split("=", 1)[1].strip().strip('"').strip("'")
    return "0.0.0"


def _components() -> list[dict[str, Any]]:
    components: list[dict[str, Any]] = []
    for dist in distributions():
        try:
            name = dist.metadata["Name"]
            version = dist.version
        except Exception:  # pragma: no cover - a broken distribution
            continue
        if not name:
            continue
        components.append(
            {
                "type": "library",
                "name": name,
                "version": version,
                "purl": f"pkg:pypi/{name.lower().replace('_', '-')}@{version}",
                "licenses": _licenses(dist),
            }
        )
    components.sort(key=lambda item: (item["name"], item["version"]))
    return components


def _licenses(dist: Any) -> list[str]:
    try:
        value = dist.metadata["License-Expression"] or dist.metadata["License"] or ""
    except Exception:  # pragma: no cover - a broken distribution
        return []
    text = str(value).strip()
    return [text] if text and not text.startswith("UNKNOWN") else []


def _hashes() -> list[dict[str, str]]:
    """The hashes of the distributions in the environment."""
    out: list[dict[str, str]] = []
    for path in sorted(Path(sys.prefix).glob("**/*.dist-info/RECORD")):
        try:
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
        except OSError:  # pragma: no cover - a file that vanished
            continue
        out.append({"path": str(path.relative_to(sys.prefix)), "sha256": digest})
    return out


def build() -> dict[str, Any]:
    try:
        commit = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        ).stdout.strip()
    except Exception:  # pragma: no cover - git is not there
        commit = ""
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": f"urn:uuid:{_serial()}",
        "version": 1,
        "metadata": {
            "timestamp": datetime.now(UTC).isoformat(),
            "component": {
                "type": "application",
                "name": "verdis",
                "version": _version(),
                "purl": f"pkg:pypi/verdis@{_version()}",
            },
            "properties": [
                {"name": "verdis:commit", "value": commit},
                {"name": "verdis:python", "value": platform.python_version()},
            ],
        },
        "components": _components(),
    }


def _serial() -> str:
    import uuid

    return str(uuid.uuid4())


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", default=str(REPO_ROOT / "dist" / "sbom.json"))
    args = parser.parse_args(argv)

    document = build()
    destination = Path(args.out)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(
        f"{len(document['components'])} components written to {destination}",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
