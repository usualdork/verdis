"""Getting the target source at the claimed ref (FR-6, FR-7).

Two cases: a local git repository (checked out with ``git worktree``) and a
plain directory (copied). Nothing here executes code from the target.
"""

from __future__ import annotations

import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path

__all__ = ["Checkout", "CheckoutError", "checkout_ref", "clone", "default_branch"]


class CheckoutError(RuntimeError):
    """Raised when the target source cannot be prepared."""


@dataclass(frozen=True)
class Checkout:
    """A prepared working copy of the target."""

    path: Path
    ref: str
    method: str
    commit: str = ""

    def cleanup(self) -> None:
        if self.method == "worktree":
            shutil.rmtree(self.path, ignore_errors=True)


def _run_git(args: list[str], cwd: Path, timeout: int = 120) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(
            ["git", *args],
            cwd=str(cwd),
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise CheckoutError(f"git {' '.join(args)} failed: {exc}") from exc


def _is_git_repo(path: Path) -> bool:
    return (path / ".git").exists() or _run_git(["rev-parse", "--git-dir"], path, timeout=30).returncode == 0


def default_branch(repo: str | Path) -> str:
    """The branch a repository maintains, or "" when it has none."""
    repo_path = Path(repo).expanduser()
    if not repo_path.is_dir() or not _is_git_repo(repo_path):
        return ""
    for candidate in ("main", "master", "trunk", "develop"):
        result = _run_git(
            ["rev-parse", "--verify", f"refs/heads/{candidate}"], repo_path, timeout=30
        )
        if result.returncode == 0:
            return candidate
    head = _run_git(["symbolic-ref", "--short", "HEAD"], repo_path, timeout=30)
    if head.returncode == 0:
        return head.stdout.strip()
    return ""


def checkout_ref(repo: str | Path, ref: str = "", *, workdir: str | Path | None = None) -> Checkout:
    """Prepare the target source at ``ref``.

    When ``ref`` is empty the current checkout is used as-is.
    """
    repo_path = Path(repo).expanduser()
    if not repo_path.exists():
        raise CheckoutError(f"target path does not exist: {repo_path}")

    if not repo_path.is_dir():
        raise CheckoutError(f"target path is not a directory: {repo_path}")

    if not ref:
        return Checkout(path=repo_path, ref="", method="existing")

    if not _is_git_repo(repo_path):
        raise CheckoutError(
            f"{repo_path} is not a git repository, so ref {ref!r} cannot be checked out"
        )

    verify = _run_git(["rev-parse", "--verify", f"{ref}^{{commit}}"], repo_path)
    if verify.returncode != 0:
        raise CheckoutError(f"ref {ref!r} does not exist in {repo_path}")
    commit = verify.stdout.strip()

    parent = Path(workdir) if workdir else Path(tempfile.mkdtemp(prefix="verdis-src-"))
    parent.mkdir(parents=True, exist_ok=True)
    target = parent / (ref.replace("/", "_") or "worktree")

    result = _run_git(["worktree", "add", "--detach", str(target), commit], repo_path)
    if result.returncode != 0:
        # Fall back to an archive export, which needs no worktree bookkeeping.
        archive = parent / "source.tar"
        export = _run_git(["archive", "--format=tar", "-o", str(archive), commit], repo_path)
        if export.returncode != 0:
            raise CheckoutError(
                f"could not check out {ref!r}: {result.stderr.strip()[:200]}"
            )
        target.mkdir(parents=True, exist_ok=True)
        unpack = subprocess.run(
            ["tar", "-xf", str(archive), "-C", str(target)],
            capture_output=True,
            text=True,
            timeout=300,
            check=False,
        )
        if unpack.returncode != 0:
            raise CheckoutError(f"could not unpack the source archive: {unpack.stderr[:200]}")
        return Checkout(path=target, ref=ref, method="archive", commit=commit)

    return Checkout(path=target, ref=ref, method="worktree", commit=commit)


def clone(url: str, destination: str | Path, *, depth: int = 1) -> Path:
    """Clone a repository into ``destination``.

    The CLI accepts a URL as well as a path, so a report can be triaged
    against a project the maintainer has not checked out.
    """
    target = Path(destination)
    target.parent.mkdir(parents=True, exist_ok=True)
    result = _run_git(
        ["clone", "--depth", str(depth), "--quiet", url, str(target)],
        Path.cwd(),
        timeout=900,
    )
    if result.returncode != 0:
        raise CheckoutError(f"could not clone {url}: {result.stderr.strip()[:200]}")
    return target
