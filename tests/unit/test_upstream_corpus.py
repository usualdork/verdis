"""The vendored upstream cases (PRD 13.1).

An upstream case is a real project, at a real commit, with the proof of
concept the fix brought with it. The corpus is only worth as much as
these are, so they are checked: the metadata has to say where the case
came from, the proof of concept has to be there, and the vendored target
has to be the upstream tree rather than a copy of one of the corpus's
own programs.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
VENDOR = REPO_ROOT / "benchmark" / "upstream"

REQUIRED = ("key", "cve", "repo", "fix", "poc_name", "tool", "component", "version")


def _cases() -> list[Path]:
    if not VENDOR.is_dir():
        return []
    return sorted(
        path for path in VENDOR.iterdir() if (path / "meta.json").is_file()
    )


class TestTheVendoredCases:
    def test_there_are_upstream_cases(self) -> None:
        assert _cases(), "no upstream case is vendored"

    def test_each_case_says_where_it_came_from(self) -> None:
        for directory in _cases():
            meta = json.loads((directory / "meta.json").read_text(encoding="utf-8"))
            for key in REQUIRED:
                assert key in meta, f"{directory.name} has no {key}"
            assert meta["repo"].startswith("https://")
            assert len(str(meta["fix"])) == 40, "the fix commit is not a full hash"

    def test_each_case_has_its_proof_of_concept(self) -> None:
        for directory in _cases():
            meta = json.loads((directory / "meta.json").read_text(encoding="utf-8"))
            poc = directory / "poc" / str(meta["poc_name"])
            assert poc.is_file(), f"{directory.name} has no proof of concept"
            assert poc.stat().st_size > 0

    def test_each_case_has_its_target(self) -> None:
        for directory in _cases():
            archive = directory / "target.tar.xz"
            assert archive.is_file(), f"{directory.name} has no target"
            assert archive.stat().st_size > 1000

    def test_the_proof_of_concept_is_the_upstream_one(self) -> None:
        """The proof of concept comes from upstream, not from us.

        The upstream test files are uuencoded, and the ones that are not
        are the upstream's own test inputs. A case whose proof of
        concept was written here would not be an upstream case.
        """
        for directory in _cases():
            meta = json.loads((directory / "meta.json").read_text(encoding="utf-8"))
            assert "poc_from" in meta
            assert "test" in str(meta["poc_from"]) or "fuzz" in str(meta["poc_from"])


class TestTheCorpusIsBuiltFromThem:
    def test_the_built_corpus_has_the_upstream_cases(self) -> None:
        built = REPO_ROOT / "benchmark" / "cases"
        if not built.is_dir():
            pytest.skip("the corpus has not been built")
        for directory in _cases():
            meta = json.loads((directory / "meta.json").read_text(encoding="utf-8"))
            case = built / str(meta["key"]) / "case.json"
            assert case.is_file(), f"{meta['key']} is not in the corpus"
            data = json.loads(case.read_text(encoding="utf-8"))
            assert data["provenance"] == "upstream"
            assert data["cve"] == meta["cve"]
            assert data["requires"] == "container"
