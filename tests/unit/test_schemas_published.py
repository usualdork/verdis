"""The published JSON schemas must match the models (PRD 9.5)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from verdis.schemas.generate import MODELS, generate

SCHEMA_DIR = Path(__file__).resolve().parents[2] / "schemas"


class TestSchemas:
    @pytest.mark.parametrize("name", sorted(MODELS))
    def test_the_schema_exists(self, name: str) -> None:
        assert (SCHEMA_DIR / f"{name}.schema.json").is_file()

    @pytest.mark.parametrize("name", sorted(MODELS))
    def test_the_schema_is_valid_json(self, name: str) -> None:
        path = SCHEMA_DIR / f"{name}.schema.json"
        data = json.loads(path.read_text(encoding="utf-8"))
        assert data["$schema"].startswith("https://json-schema.org/")
        assert data["type"] == "object"
        assert data["title"]

    @pytest.mark.parametrize("name", sorted(MODELS))
    def test_the_schema_is_up_to_date(self, name: str, tmp_path: Path) -> None:
        generate(tmp_path)
        expected = (tmp_path / f"{name}.schema.json").read_text(encoding="utf-8")
        actual = (SCHEMA_DIR / f"{name}.schema.json").read_text(encoding="utf-8")
        assert actual == expected, (
            f"{name}.schema.json is out of date; run "
            "'python -m verdis.schemas.generate schemas/'"
        )

    def test_every_model_is_published(self) -> None:
        assert len(MODELS) >= 10

    def test_the_verdict_schema_lists_every_verdict(self) -> None:
        data = json.loads((SCHEMA_DIR / "verdict.schema.json").read_text(encoding="utf-8"))
        enum = data["$defs"]["Verdict"]["enum"]
        assert set(enum) == {
            "REPRODUCED",
            "NOT_REPRODUCED",
            "INCONCLUSIVE",
            "OUT_OF_SCOPE",
            "DUPLICATE",
            "NEEDS_INFO",
            "UNSAFE_ATTACHMENT",
        }

    def test_the_plan_schema_lists_every_step_kind(self) -> None:
        data = json.loads((SCHEMA_DIR / "plan.schema.json").read_text(encoding="utf-8"))
        steps = data["properties"]["steps"]["items"]
        kinds = set(steps["discriminator"]["mapping"])
        assert kinds == {"checkout", "build", "copy", "run", "expect", "compare"}
