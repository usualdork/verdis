"""Tests for opening a tool-made tree to the sandbox's unprivileged user.

On Linux a bind mount keeps the host's owner and mode, so a tree made by
``mkdtemp`` (mode 0700) or copied from a private repository cannot be read
from inside the sandbox. ``share_with_sandbox`` widens the modes it needs.
"""

from __future__ import annotations

import stat
from pathlib import Path

import pytest

from verdis.sandbox.base import share_with_sandbox


def _mode(path: Path) -> int:
    return stat.S_IMODE(path.stat().st_mode)


@pytest.fixture
def private_tree(tmp_path: Path) -> Path:
    root = tmp_path / "tree"
    (root / "nested").mkdir(parents=True)
    (root / "data.txt").write_text("data", encoding="utf-8")
    (root / "run.sh").write_text("#!/bin/sh\n", encoding="utf-8")
    (root / "nested" / "inner.txt").write_text("inner", encoding="utf-8")
    root.chmod(0o700)
    (root / "nested").chmod(0o700)
    (root / "data.txt").chmod(0o600)
    (root / "run.sh").chmod(0o700)
    (root / "nested" / "inner.txt").chmod(0o600)
    return root


class TestReadOnlyShare:
    def test_directories_become_searchable_and_files_readable(self, private_tree: Path) -> None:
        share_with_sandbox(private_tree)
        assert _mode(private_tree) == 0o755
        assert _mode(private_tree / "nested") == 0o755
        assert _mode(private_tree / "data.txt") == 0o644
        assert _mode(private_tree / "nested" / "inner.txt") == 0o644

    def test_an_executable_stays_executable_for_everyone(self, private_tree: Path) -> None:
        share_with_sandbox(private_tree)
        assert _mode(private_tree / "run.sh") == 0o755

    def test_nothing_becomes_writable_by_others(self, private_tree: Path) -> None:
        share_with_sandbox(private_tree)
        for path in (private_tree, private_tree / "data.txt", private_tree / "nested"):
            assert _mode(path) & 0o022 == 0

    def test_a_tree_that_is_already_open_is_left_alone(self, private_tree: Path) -> None:
        share_with_sandbox(private_tree)
        before = _mode(private_tree / "data.txt")
        share_with_sandbox(private_tree)
        assert _mode(private_tree / "data.txt") == before


class TestWritableShare:
    def test_everything_becomes_writable(self, private_tree: Path) -> None:
        share_with_sandbox(private_tree, writable=True)
        assert _mode(private_tree) == 0o777
        assert _mode(private_tree / "nested") == 0o777
        assert _mode(private_tree / "data.txt") == 0o666
        assert _mode(private_tree / "run.sh") == 0o777


class TestWhatItDoesNotTouch:
    def test_a_symbolic_link_and_its_target_are_left_alone(
        self, private_tree: Path, tmp_path: Path
    ) -> None:
        outside = tmp_path / "outside"
        outside.mkdir()
        outside.chmod(0o700)
        secret = outside / "secret.txt"
        secret.write_text("secret", encoding="utf-8")
        secret.chmod(0o600)
        (private_tree / "to-dir").symlink_to(outside, target_is_directory=True)
        (private_tree / "to-file").symlink_to(secret)

        share_with_sandbox(private_tree, writable=True)

        assert _mode(outside) == 0o700
        assert _mode(secret) == 0o600

    def test_a_link_given_as_the_root_is_ignored(self, private_tree: Path, tmp_path: Path) -> None:
        link = tmp_path / "link"
        link.symlink_to(private_tree, target_is_directory=True)
        share_with_sandbox(link)
        assert _mode(private_tree) == 0o700

    def test_a_missing_path_and_a_file_are_ignored(self, tmp_path: Path) -> None:
        share_with_sandbox(tmp_path / "missing")
        single = tmp_path / "single.txt"
        single.write_text("x", encoding="utf-8")
        single.chmod(0o600)
        share_with_sandbox(single)
        assert _mode(single) == 0o600

    def test_a_path_that_cannot_be_changed_does_not_raise(
        self, private_tree: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        def refuse(self: Path, mode: int) -> None:
            raise PermissionError("not yours")

        monkeypatch.setattr(Path, "chmod", refuse)
        share_with_sandbox(private_tree)
        assert _mode(private_tree) == 0o700
