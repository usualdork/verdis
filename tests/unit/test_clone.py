"""Tests for cloning a repository and triaging a report from a URL."""

from __future__ import annotations

from pathlib import Path

import pytest

from verdis.build.checkout import CheckoutError, clone
from verdis.config import Config
from verdis.pipeline.orchestrator import Orchestrator
from verdis.sandbox.local import LocalBackend
from verdis.storage.db import Store
from verdis.storage.evidence import EvidenceStore


class TestClone:
    def test_a_repository_is_cloned(self, tmp_path: Path, git_repo: Path) -> None:
        target = tmp_path / "clone"
        clone(str(git_repo), target)
        assert (target / "file.txt").is_file()

    def test_a_clone_that_fails_is_an_error(self, tmp_path: Path) -> None:
        with pytest.raises(CheckoutError, match="could not clone"):
            clone("https://example.invalid/nope.git", tmp_path / "clone")


class TestTriagingAUrl:
    def test_a_remote_url_is_cloned(self, tmp_path: Path, monkeypatch) -> None:
        import verdis.build.checkout as checkout_module

        cloned: list[str] = []

        def fake_clone(url: str, destination: Path, *, depth: int = 1) -> Path:
            cloned.append(url)
            destination.mkdir(parents=True, exist_ok=True)
            (destination / "file.txt").write_text("cloned\n", encoding="utf-8")
            return destination

        monkeypatch.setattr(checkout_module, "clone", fake_clone)
        config = Config(mode="shadow", sandbox="local", repeats=1)
        orchestrator = Orchestrator(
            config=config,
            store=Store(tmp_path / "store"),
            evidence=EvidenceStore(tmp_path / "evidence"),
            backend=LocalBackend(),
        )
        source, cleanup = orchestrator._prepare_source(
            "https://example.org/libfoo.git", ""
        )
        try:
            assert cloned == ["https://example.org/libfoo.git"]
            assert (source / "file.txt").is_file()
        finally:
            cleanup()

    def test_a_url_is_cloned_and_triaged(
        self, tmp_path: Path, git_repo: Path
    ) -> None:
        config = Config(mode="shadow", sandbox="local", repeats=1)
        orchestrator = Orchestrator(
            config=config,
            store=Store(tmp_path / "store"),
            evidence=EvidenceStore(tmp_path / "evidence"),
            backend=LocalBackend(),
        )
        # The raw string, because pathlib collapses the "//" in a
        # file:// URL.
        source, cleanup = orchestrator._prepare_source(
            f"file://{git_repo}", ""
        )
        try:
            assert (source / "file.txt").is_file()
        finally:
            cleanup()
