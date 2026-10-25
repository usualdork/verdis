"""Generate the published JSON schemas (PRD 9.5, 10.3, 17.1).

Run with::

    python -m verdis.schemas.generate schemas/

The generated files are committed, and a test checks that they are up to
date, so a change to a model without a schema change fails the build.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

from pydantic import BaseModel

from .bundle import BundleManifest
from .claim import Claim
from .plan import Plan
from .policy import Policy
from .report import Report
from .rrs import RRS
from .run import BuildResult, OracleResult, RunResult
from .verdict import VerdictResult

__all__ = ["MODELS", "generate", "main"]

MODELS: dict[str, type[BaseModel]] = {
    "report": Report,
    "claim": Claim,
    "plan": Plan,
    "policy": Policy,
    "build": BuildResult,
    "run": RunResult,
    "oracle-result": OracleResult,
    "verdict": VerdictResult,
    "bundle-manifest": BundleManifest,
    "rrs": RRS,
}


def generate(target: str | Path) -> list[Path]:
    """Write one JSON schema per model and return the paths written."""
    directory = Path(target)
    directory.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []
    for name, model in MODELS.items():
        path = directory / f"{name}.schema.json"
        schema = model.model_json_schema()
        schema["$schema"] = "https://json-schema.org/draft/2020-12/schema"
        schema["$id"] = f"https://usualdork.github.io/verdis/schemas/{name}.schema.json"
        path.write_text(json.dumps(schema, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        written.append(path)
    return written


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    target = argv[0] if argv else "schemas"
    written = generate(target)
    for path in written:
        print(path)
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
