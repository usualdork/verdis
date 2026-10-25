"""Build recipes (FR-7.1, FR-7.2, FR-7.3).

Recipe sources, in priority order:

1. the maintainer's ``.verdis/recipe.yml``;
2. Dockerfile mode;
3. auto-detection from the repository;
4. a model-suggested recipe, which is stored for maintainer review.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Protocol

import yaml
from pydantic import Field, field_validator

from ..schemas.common import HashableModel, sha256_text

__all__ = [
    "BuildSpec",
    "Recipe",
    "RecipeError",
    "RecipeProvider",
    "detect_recipe",
    "load_recipe_file",
    "recipe_from_dict",
]


class RecipeError(ValueError):
    """Raised when a recipe cannot be understood."""


class BuildSpec(HashableModel):
    """How to build the target."""

    system: str = "auto"
    flags: tuple[str, ...] = ()
    steps: tuple[str, ...] = ()
    workdir: str = "."
    env: dict[str, str] = Field(default_factory=dict)
    image: str = ""
    network: str = "mirror"

    @field_validator("flags", "steps")
    @classmethod
    def _as_tuple(cls, value: tuple[str, ...] | list[str]) -> tuple[str, ...]:
        return tuple(value)


class RunSpec(HashableModel):
    """How the PoC is run."""

    workdir: str = "/work"
    default_timeout: str = "30s"
    repeat: int = Field(default=3, ge=1, le=20)
    env: dict[str, str] = Field(default_factory=dict)


class Recipe(HashableModel):
    """A build recipe."""

    language: str = "unknown"
    build: BuildSpec = Field(default_factory=BuildSpec)
    run: RunSpec = Field(default_factory=RunSpec)
    source: str = "auto"
    confidence: float = Field(default=0.5, ge=0.0, le=1.0)
    notes: tuple[str, ...] = ()
    property_script: str = Field(
        default="",
        description="A maintainer-supplied assertion script, relative to the source root.",
    )

    @field_validator("notes")
    @classmethod
    def _as_tuple(cls, value: tuple[str, ...] | list[str]) -> tuple[str, ...]:
        return tuple(value)

    @property
    def hash(self) -> str:
        """Content hash, used as part of the build cache key (FR-7.5)."""
        return sha256_text(self.canonical_json())


class RecipeProvider(Protocol):
    """A source of build recipes."""

    name: str

    def get(self, repo_path: Path) -> Recipe | None:
        ...


def recipe_from_dict(data: dict[str, Any], *, source: str = "auto") -> Recipe:
    """Build a :class:`Recipe` from a parsed mapping."""
    if not isinstance(data, dict):
        raise RecipeError("recipe must be a mapping")
    build_data = data.get("build", {}) or {}
    run_data = data.get("run", {}) or {}
    if not isinstance(build_data, dict) or not isinstance(run_data, dict):
        raise RecipeError("recipe 'build' and 'run' must be mappings")
    return Recipe(
        language=str(data.get("language", "unknown")),
        build=BuildSpec.model_validate(build_data),
        run=RunSpec.model_validate(run_data),
        source=source,
        property_script=str(data.get("property_script", "") or ""),
    )


def load_recipe_file(path: str | Path) -> Recipe:
    """Load ``.verdis/recipe.yml``."""
    path = Path(path)
    try:
        raw = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise RecipeError(f"cannot read recipe {path}: {exc}") from exc
    try:
        data = yaml.safe_load(raw)
    except yaml.YAMLError as exc:
        raise RecipeError(f"invalid YAML in {path}: {exc}") from exc
    if data is None:
        data = {}
    return recipe_from_dict(data, source=str(path))


# -- auto-detection -----------------------------------------------------

_C_FLAGS = {
    "asan": ["-fsanitize=address", "-fno-omit-frame-pointer"],
    "ubsan": ["-fsanitize=undefined", "-fno-omit-frame-pointer"],
    "tsan": ["-fsanitize=thread"],
    "msan": ["-fsanitize=memory"],
}

_LANGUAGES = ("c", "cpp", "python", "node", "go", "rust", "java")


def detect_recipe(repo_path: str | Path) -> Recipe | None:
    """Detect a build recipe from the repository layout (FR-7.1)."""
    repo_path = Path(repo_path)
    if not repo_path.is_dir():
        return None

    dockerfile = repo_path / "Dockerfile"
    if dockerfile.is_file():
        base = _dockerfile_base_image(dockerfile)
        return Recipe(
            language="docker",
            build=BuildSpec(
                system="docker",
                image=base,
                steps=(),
                network="mirror",
            ),
            source="dockerfile",
            confidence=0.7,
            notes=(
                "Dockerfile mode: the base image becomes the sandbox image and the "
                "source is mounted into it. The Dockerfile's own RUN steps are not "
                "executed; copy the ones you trust into the recipe's build steps.",
            ),
        )

    if (repo_path / "CMakeLists.txt").is_file():
        return Recipe(
            language="c",
            build=BuildSpec(
                system="cmake",
                flags=("asan", "ubsan"),
                steps=(
                    "cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug "
                    "-DCMAKE_C_FLAGS='-fsanitize=address,undefined -fno-omit-frame-pointer' "
                    "-DCMAKE_CXX_FLAGS='-fsanitize=address,undefined -fno-omit-frame-pointer'",
                    "cmake --build build -j",
                ),
            ),
            source="auto-detect",
            confidence=0.8,
            notes=("C/C++ project detected (CMake); built with ASan and UBSan",),
        )

    if (repo_path / "Makefile").is_file():
        return Recipe(
            language="c",
            build=BuildSpec(
                system="make",
                flags=("asan", "ubsan"),
                steps=(
                    "make CFLAGS='-fsanitize=address,undefined -fno-omit-frame-pointer' "
                    "CXXFLAGS='-fsanitize=address,undefined -fno-omit-frame-pointer'",
                ),
            ),
            source="auto-detect",
            confidence=0.7,
            notes=("Makefile project detected; built with ASan and UBSan",),
        )

    for autotools in ("configure.ac", "configure"):
        if (repo_path / autotools).is_file():
            return Recipe(
                language="c",
                build=BuildSpec(
                    system="autotools",
                    flags=("asan", "ubsan"),
                    steps=(
                        "./configure --disable-shared "
                        "CFLAGS='-fsanitize=address,undefined -fno-omit-frame-pointer'",
                        "make -j",
                    ),
                ),
                source="auto-detect",
                confidence=0.6,
                notes=("Autotools project detected",),
            )

    if (repo_path / "go.mod").is_file():
        return Recipe(
            language="go",
            build=BuildSpec(
                system="go",
                flags=("race",),
                steps=("go build -race ./...",),
            ),
            source="auto-detect",
            confidence=0.8,
            notes=("Go project detected; built with the race detector",),
        )

    if (repo_path / "pyproject.toml").is_file() or (repo_path / "setup.py").is_file():
        return Recipe(
            language="python",
            build=BuildSpec(
                system="pip",
                steps=("python -m pip install --no-input .",),
            ),
            source="auto-detect",
            confidence=0.7,
            notes=("Python project detected; installed into the sandbox",),
        )

    if (repo_path / "package.json").is_file():
        return Recipe(
            language="node",
            build=BuildSpec(
                system="npm",
                steps=("npm install --ignore-scripts", "npm run build --if-present"),
            ),
            source="auto-detect",
            confidence=0.6,
            notes=("Node project detected; lifecycle scripts are disabled",),
        )

    if (repo_path / "Cargo.toml").is_file():
        return Recipe(
            language="rust",
            build=BuildSpec(system="cargo", steps=("cargo build --release",)),
            source="auto-detect",
            confidence=0.5,
            notes=("Rust project detected; community recipe territory",),
        )

    if (repo_path / "pom.xml").is_file() or (repo_path / "build.gradle").is_file():
        return Recipe(
            language="java",
            build=BuildSpec(system="gradle", steps=("gradle build -x test",)),
            source="auto-detect",
            confidence=0.4,
            notes=("Java project detected; community recipe territory",),
        )

    return None


_FROM_RE = re.compile(r"(?im)^\s*FROM\s+([\w./:@-]+)")


def _dockerfile_base_image(dockerfile: Path) -> str:
    """The image a Dockerfile starts from."""
    try:
        text = dockerfile.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""
    match = _FROM_RE.search(text)
    if match is None:
        return ""
    base = match.group(1).strip()
    # A multi-stage build's first FROM is the one the build starts from.
    return base


def sanitizer_flags(flags: tuple[str, ...]) -> list[str]:
    """Compiler flags for the requested sanitizers (FR-7.3)."""
    out: list[str] = []
    for flag in flags:
        out.extend(_C_FLAGS.get(flag.lower(), []))
    return out


def has_flag(flags: tuple[str, ...], name: str) -> bool:
    return any(flag.lower() == name.lower() for flag in flags)


_ = (re, _LANGUAGES)
