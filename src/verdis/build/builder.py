"""The builder (FR-7).

The build happens in a sandbox, never on the host. Two-phase networking
(FR-7.4) is respected: the dependency fetch step may reach an allowlisted
mirror, and the run phase has no network at all.

A build failure is not a verdict: it produces INCONCLUSIVE with the failing
step, a log excerpt and a suggested recipe fix (FR-7.6).
"""

from __future__ import annotations

import hashlib
import json
import logging
import shutil
import tempfile
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from ..sandbox.base import (
    Mount,
    SandboxBackend,
    SandboxLimits,
    SandboxProfile,
    SandboxRequest,
    SandboxResult,
)
from ..schemas.run import BuildResult, BuildStatus
from .recipe import Recipe, RecipeError, detect_recipe, load_recipe_file

log = logging.getLogger(__name__)

__all__ = ["DEFAULT_MIRRORS", "BuildCache", "Builder"]

#: Dependency mirrors the build stage may reach (FR-7.4, 11.4 item 5).
DEFAULT_MIRRORS: tuple[str, ...] = (
    "pypi.org",
    "files.pythonhosted.org",
    "registry.npmjs.org",
    "proxy.golang.org",
    "crates.io",
    "deb.debian.org",
    "archive.ubuntu.com",
)

DEFAULT_IMAGE = "ghcr.io/usualdork/verdis/base:latest"

#: The scratch area of the build stage: a tmpfs the build may write to.
BUILD_SCRATCH = "/build-scratch"

#: The home the build stage's toolchains use.
BUILD_HOME = BUILD_SCRATCH


@dataclass
class BuildCache:
    """A small on-disk cache of build outputs (FR-7.5)."""

    root: Path
    max_bytes: int = 2 * 1024 * 1024 * 1024

    def __post_init__(self) -> None:
        self.root = Path(self.root)
        self.root.mkdir(parents=True, exist_ok=True)

    def key(self, ref: str, recipe: Recipe, source_hash: str = "") -> str:
        material = f"{ref}\n{recipe.hash}\n{source_hash}"
        return hashlib.sha256(material.encode("utf-8")).hexdigest()[:32]

    def path_for(self, key: str) -> Path:
        return self.root / key

    def get(self, key: str) -> Path | None:
        path = self.path_for(key)
        if path.is_dir() and (path / ".verdis-cache-ok").is_file():
            return path
        return None

    def store(self, key: str, source: Path) -> Path:
        target = self.path_for(key)
        if target.exists():
            shutil.rmtree(target, ignore_errors=True)
        shutil.copytree(source, target, symlinks=False, dirs_exist_ok=True)
        (target / ".verdis-cache-ok").write_text("ok\n", encoding="utf-8")
        return target

    def size(self) -> int:
        total = 0
        for path in self.root.rglob("*"):
            if path.is_file():
                try:
                    total += path.stat().st_size
                except OSError:  # pragma: no cover
                    continue
        return total

    def enforce_cap(self) -> list[str]:
        """Delete the oldest entries until the cache fits the cap."""
        removed: list[str] = []
        entries = [
            (path.stat().st_mtime, path)
            for path in self.root.iterdir()
            if path.is_dir()
        ]
        total = self.size()
        if total <= self.max_bytes:
            return removed
        for _mtime, path in sorted(entries):
            if total <= self.max_bytes:
                break  # pragma: no cover - the cache fits
            size = sum(
                f.stat().st_size for f in path.rglob("*") if f.is_file()
            )
            shutil.rmtree(path, ignore_errors=True)
            total -= size
            removed.append(path.name)
        return removed


@dataclass
class Builder:
    """Builds the target inside a sandbox."""

    backend: SandboxBackend
    image: str = DEFAULT_IMAGE
    cache: BuildCache | None = None
    mirrors: tuple[str, ...] = DEFAULT_MIRRORS
    mirror_proxy: str = ""
    work_dir: str = ""

    def resolve_recipe(self, repo_path: Path) -> tuple[Recipe, str]:
        """Resolve the recipe using the priority order of FR-7.1."""
        explicit = repo_path / ".verdis" / "recipe.yml"
        if explicit.is_file():
            try:
                return load_recipe_file(explicit), "recipe.yml"
            except RecipeError as exc:
                log.warning("falling back to auto-detection: %s", exc)
        detected = detect_recipe(repo_path)
        if detected is not None:
            return detected, "auto-detect"
        return (
            Recipe(
                language="unknown",
                build={"system": "none", "steps": ()},
                source="none",
                confidence=0.0,
                notes=("no build recipe could be detected for this repository",),
            ),
            "none",
        )

    def build(
        self,
        *,
        repo_path: Path,
        ref: str = "",
        recipe: Recipe | None = None,
        workdir: Path | None = None,
        in_place: bool = False,
    ) -> BuildResult:
        """Build the target at ``ref`` and return the outcome.

        With ``in_place`` the build happens directly in ``repo_path``, which
        is what the orchestrator uses: it prepares a private copy of the
        source first, and the run stage then uses the same tree, so the
        built artefacts are where the PoC expects them.
        """
        started = time.monotonic()
        if recipe is None:
            recipe, _source = self.resolve_recipe(repo_path)

        if not recipe.build.steps:
            return BuildResult(
                status=BuildStatus.UNSUPPORTED,
                ref=ref,
                recipe=recipe.source,
                recipe_hash=recipe.hash,
                duration_ms=int((time.monotonic() - started) * 1000),
                failure_step="",
                log_excerpt="",
                suggested_fix=(
                    "no build recipe is available; add .verdis/recipe.yml with the "
                    "commands that build this project"
                ),
            )

        source_hash = self._source_hash(repo_path)
        cache_key = self.cache.key(ref, recipe, source_hash) if self.cache else ""
        if self.cache is not None and cache_key:
            cached = self.cache.get(cache_key)
            if cached is not None:
                # The cached tree is the *built* source. It has to be put
                # back where the run stage expects it, or the PoC would run
                # against an unbuilt tree and the verdict would be wrong.
                restored = self._restore(cached, repo_path)
                return BuildResult(
                    status=BuildStatus.OK,
                    ref=ref,
                    recipe=recipe.source,
                    recipe_hash=recipe.hash,
                    duration_ms=int((time.monotonic() - started) * 1000),
                    cached=True,
                    artifact_path=str(restored),
                    logs=("the build was served from the local cache",),
                )

        staging: Path | None = None
        if in_place:
            build_dir = repo_path
        else:
            staging = Path(
                tempfile.mkdtemp(
                    prefix="verdis-build-", dir=self.work_dir or None
                )
            )
            build_dir = staging / "source"
            shutil.copytree(
                repo_path, build_dir, symlinks=False, dirs_exist_ok=True,
                ignore=self._ignore(repo_path),
            )

        try:
            request = SandboxRequest(
                image=recipe.build.image or self.image,
                command=["/bin/sh", "-c", "\n".join(recipe.build.steps)],
                workdir="/src",
                scratch=BUILD_SCRATCH,
                env=self._build_env(recipe),
                mounts=[Mount(source=str(build_dir), target="/src", readonly=False)],
                profile=self._build_profile(recipe),
                limits=self._build_limits(),
                workdir_source=str(build_dir),
            )
            result = self.backend.run(request)
            duration = int((time.monotonic() - started) * 1000)

            if result.exit_code == 0:
                artifact_path = ""
                if self.cache is not None and cache_key:
                    artifact_path = str(self.cache.store(cache_key, build_dir))
                    self.cache.enforce_cap()
                return BuildResult(
                    status=BuildStatus.OK,
                    ref=ref,
                    recipe=recipe.source,
                    recipe_hash=recipe.hash,
                    logs=self._log_lines(result),
                    duration_ms=duration,
                    image_digest=result.image_digest,
                    artifact_path=artifact_path,
                )

            excerpt = self._excerpt(result)
            failing = self._failing_step(recipe, result)
            return BuildResult(
                status=BuildStatus.FAILED,
                ref=ref,
                recipe=recipe.source,
                recipe_hash=recipe.hash,
                logs=self._log_lines(result),
                duration_ms=duration,
                failure_step=failing,
                log_excerpt=excerpt,
                suggested_fix=self._suggest_fix(recipe, result),
                image_digest=result.image_digest,
            )
        finally:
            if staging is not None:
                shutil.rmtree(staging, ignore_errors=True)

    # -- helpers --------------------------------------------------------

    def _build_profile(self, recipe: Recipe) -> SandboxProfile:
        """The profile the build stage runs in.

        The build stage is the only stage that may reach the network, and
        even then only through an allowlisted mirror: the run stage is
        always offline (FR-7.4, PRD 11.2).
        """
        from ..sandbox.base import SandboxProfile, default_profile

        profile = default_profile()
        if recipe.build.network == "none" or not self.mirror_proxy:
            # Without a configured mirror the build stage has no network
            # either. The build and the run are then equally isolated.
            return profile
        # The dependency fetch phase may reach the mirror; the run phase
        # never does.
        return SandboxProfile(
            name="build",
            network="mirror",
            read_only_root=profile.read_only_root,
            drop_capabilities=profile.drop_capabilities,
            no_new_privileges=profile.no_new_privileges,
            user=profile.user,
            seccomp=profile.seccomp,
            userns=profile.userns,
        )

    @staticmethod
    def _build_limits() -> SandboxLimits:
        return SandboxLimits(timeout_s=900, memory_mb=4096, cpus=4.0, pids=1024)

    def _ignore(self, repo_path: Path) -> Callable[[str, list[str]], set[str]]:
        """What the staging copy leaves out.

        The usual build noise, and the work directory itself: an
        operator may well point the work directory inside the project,
        and a copy that includes it copies itself.
        """
        patterns = shutil.ignore_patterns(
            ".git", "__pycache__", "*.pyc", "node_modules"
        )
        work_dir = Path(self.work_dir).resolve() if self.work_dir else None

        def ignore(directory: str, names: list[str]) -> set[str]:
            skip = set(patterns(directory, names))
            if work_dir is not None:
                here = Path(directory).resolve()
                for name in names:
                    candidate = (here / name).resolve()
                    try:
                        candidate.relative_to(work_dir)
                    except ValueError:
                        continue
                    skip.add(name)
            return skip

        return ignore

    def _build_env(self, recipe: Recipe) -> dict[str, str]:
        """The environment of the build stage.

        It carries the allowlist of mirrors the build may reach, and
        nothing else: no token, no secret, and nothing the run stage
        would ever see.
        """
        env = dict(recipe.build.env)
        env["VERDIS_ALLOWED_MIRRORS"] = ",".join(self.mirrors)
        # A toolchain needs a home it can write to: Go puts its build
        # cache under $HOME, npm and pip keep theirs there too. The
        # scratch area is a tmpfs, so nothing is left behind and the
        # source tree stays read-only.
        env.setdefault("HOME", BUILD_HOME)
        if self.mirror_proxy:
            env["HTTP_PROXY"] = self.mirror_proxy
            env["HTTPS_PROXY"] = self.mirror_proxy
            env["NO_PROXY"] = ",".join(self.mirrors)
        return env

    @staticmethod
    def _restore(cached: Path, target: Path) -> Path:
        """Copy a cached build back over the source tree.

        The cached tree is what the build produced, so restoring it gives
        the run stage exactly the artefacts the original build left behind.
        """
        shutil.copytree(
            cached,
            target,
            symlinks=False,
            dirs_exist_ok=True,
            ignore=shutil.ignore_patterns(".verdis-cache-ok"),
        )
        return target

    @staticmethod
    def _source_hash(repo_path: Path) -> str:
        digest = hashlib.sha256()
        for path in sorted(repo_path.rglob("*")):
            if path.is_file() and ".git" not in path.parts:
                try:
                    digest.update(str(path.relative_to(repo_path)).encode("utf-8"))
                    digest.update(path.read_bytes()[:4096])
                except OSError:  # pragma: no cover
                    continue
        return digest.hexdigest()

    @staticmethod
    def _log_lines(result: SandboxResult) -> tuple[str, ...]:
        blob = f"{result.stdout}\n{result.stderr}".strip()
        if not blob:
            return ()
        return tuple(blob.splitlines()[-200:])

    @staticmethod
    def _excerpt(result: SandboxResult) -> str:
        blob = f"{result.stdout}\n{result.stderr}".strip()
        if not blob:
            return "the build produced no output"
        lines = blob.splitlines()
        return "\n".join(lines[-40:])[:4000]

    @staticmethod
    def _failing_step(recipe: Recipe, result: SandboxResult) -> str:
        """Guess which build step failed by looking for its output."""
        blob = f"{result.stdout}\n{result.stderr}"
        for index, step in enumerate(recipe.build.steps):
            head = step.split()[0] if step.split() else ""
            # A very short name matches too easily to be evidence.
            if head and len(head) >= 3 and head in blob:
                return f"step {index + 1}: {step}"
        if recipe.build.steps:
            return f"step {len(recipe.build.steps)}: {recipe.build.steps[-1]}"
        return ""

    @staticmethod
    def _suggest_fix(recipe: Recipe, result: SandboxResult) -> str:
        blob = f"{result.stdout}\n{result.stderr}".lower()
        if "command not found" in blob:
            return "a tool used by the recipe is missing from the build image"
        if "no such file or directory" in blob:
            return (
                "a file or a tool the build needs is missing; check the recipe's paths "
                "and the build image"
            )
        if "permission denied" in blob:
            return "the build tried to write somewhere it may not; add the right mount"
        if "network is unreachable" in blob or "could not resolve host" in blob:
            return (
                "the build needed the network; add an allowlisted mirror or vendor the "
                "dependencies"
            )
        if "undefined reference" in blob:
            return "the build did not link; check the recipe's flags and libraries"
        return (
            "review .verdis/recipe.yml; the build failed at "
            + (recipe.build.steps[-1] if recipe.build.steps else "an unknown step")
        )


_ = json
