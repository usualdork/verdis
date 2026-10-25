"""Configuration (PRD 9.3, Appendix C).

``.verdis/config.yml`` holds the maintainer's settings. Every value has a
safe default, and the file is optional.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from .extract.providers import ProviderConfig
from .preflight.preflight import DEFAULT_THRESHOLD

__all__ = ["CONFIG_FILENAME", "Config", "ConfigError", "default_config", "load_config"]

CONFIG_FILENAME = Path(".verdis/config.yml")

VALID_MODES = ("shadow", "comment", "label")
VALID_SANDBOX = ("default", "hardened", "local", "podman", "docker")


class ConfigError(ValueError):
    """Raised when a configuration file cannot be understood."""


@dataclass
class Config:
    """The tool's settings."""

    mode: str = "shadow"
    sandbox: str = "default"
    llm: ProviderConfig = field(default_factory=ProviderConfig)
    post_comment: bool = False
    apply_labels: bool = False
    auto_close: bool = False
    auto_reply_needs_info: bool = False
    dedupe_threshold: float = 0.82
    preflight_threshold: int = DEFAULT_THRESHOLD
    rea_plugin: str = ""
    """The optional REA preflight plugin, by path.

    The plugin inspects binaries with REA, which is not a sandbox, so it
    refuses to run unless it is told it is inside one. When it is not
    configured, or it cannot run, the built-in analysis stands alone.
    """
    stop_on_duplicate: bool = False
    advisory_lookups: bool = False
    advisory_ecosystem: str = ""
    """The package ecosystem the advisory lookup uses.

    The advisory database needs one: "Debian", "PyPI", "npm", "Go",
    "crates.io". Without it the lookup cannot be made, so it is not
    made.
    """
    build_cache_dir: str = ""
    build_cache_max_bytes: int = 2 * 1024 * 1024 * 1024
    store_dir: str = ""
    evidence_dir: str = ""
    base_image: str = ""
    """The image the build and run stages use.

    A digest pins the exact bits that ran, which a tag does not. The
    operator's own image, by digest, keeps the supply chain under their
    control (PRD 11.2).
    """
    work_dir: str = field(
        default_factory=lambda: os.environ.get("VERDIS_WORK_DIR", "")
    )
    run_timeout: int = 60
    report_budget_seconds: float = 900.0
    build_timeout: int = 900
    repeats: int = 3
    comparison_ref: str = ""
    extras: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.mode not in VALID_MODES:
            raise ConfigError(
                f"mode must be one of {VALID_MODES}, got {self.mode!r}"
            )
        if self.sandbox not in VALID_SANDBOX:
            raise ConfigError(
                f"sandbox must be one of {VALID_SANDBOX}, got {self.sandbox!r}"
            )
        if not 0.0 <= self.dedupe_threshold <= 1.0:
            raise ConfigError("dedupe.threshold must be between 0 and 1")
        if self.auto_close:
            # The tool never closes a report on its own (PRD section 3).
            self.auto_close = False
        if not 0 <= self.preflight_threshold <= 100:
            raise ConfigError("preflight.threshold must be between 0 and 100")

    @property
    def is_shadow(self) -> bool:
        return self.mode == "shadow"


def default_config() -> Config:
    """A conservative default configuration."""
    return Config(work_dir=os.environ.get("VERDIS_WORK_DIR", ""))


def config_from_dict(data: dict[str, Any]) -> Config:
    """Build a :class:`Config` from a parsed mapping."""
    if not isinstance(data, dict):
        raise ConfigError("configuration must be a mapping")
    llm_data = data.get("llm", {}) or {}
    if not isinstance(llm_data, dict):
        raise ConfigError("llm must be a mapping")
    actions = data.get("actions", {}) or {}
    if not isinstance(actions, dict):
        raise ConfigError("actions must be a mapping")
    dedupe = data.get("dedupe", {}) or {}
    if not isinstance(dedupe, dict):
        raise ConfigError("dedupe must be a mapping")
    advisories = data.get("advisories", {}) or {}
    if not isinstance(advisories, dict):
        raise ConfigError("advisories must be a mapping")
    preflight = data.get("preflight", {}) or {}
    if not isinstance(preflight, dict):
        raise ConfigError("preflight must be a mapping")
    build = data.get("build", {}) or {}
    if not isinstance(build, dict):
        raise ConfigError("build must be a mapping")
    run = data.get("run", {}) or {}
    if not isinstance(run, dict):
        raise ConfigError("run must be a mapping")

    known = {
        "mode", "sandbox", "llm", "actions", "dedupe", "preflight", "build", "run",
        "advisories",
    }
    extras = {k: v for k, v in data.items() if k not in known}

    return Config(
        mode=str(data.get("mode", "shadow")),
        sandbox=str(data.get("sandbox", "default")),
        llm=ProviderConfig.from_dict(llm_data),
        post_comment=bool(actions.get("post_comment", False)),
        apply_labels=bool(actions.get("apply_labels", False)),
        auto_close=bool(actions.get("auto_close", False)),
        auto_reply_needs_info=bool(actions.get("auto_reply_needs_info", False)),
        dedupe_threshold=float(dedupe.get("threshold", 0.82)),
        preflight_threshold=int(preflight.get("threshold", DEFAULT_THRESHOLD)),
        rea_plugin=str(preflight.get("rea_plugin", "") or ""),
        stop_on_duplicate=bool(dedupe.get("stop_on_duplicate", False)),
        advisory_lookups=bool(advisories.get("lookup", False)),
        advisory_ecosystem=str(advisories.get("ecosystem", "") or ""),
        build_cache_dir=str(build.get("cache_dir", "")),
        build_cache_max_bytes=int(build.get("cache_max_bytes", 2 * 1024 * 1024 * 1024)),
        store_dir=str(data.get("store_dir", "")),
        evidence_dir=str(data.get("evidence_dir", "")),
        work_dir=str(data.get("work_dir", "") or os.environ.get("VERDIS_WORK_DIR", "")),
        base_image=str(
            data.get("base_image", "") or os.environ.get("VERDIS_BASE_IMAGE", "")
        ),
        run_timeout=int(run.get("timeout", 60)),
        report_budget_seconds=float(run.get("report_budget_seconds", 900.0)),
        build_timeout=int(run.get("build_timeout", 900)),
        repeats=int(run.get("repeats", 3)),
        comparison_ref=str(run.get("comparison_ref", "")),
        extras=extras,
    )


def load_config(repo_path: str | Path | None = None) -> Config:
    """Load the configuration for a repository, falling back to defaults."""
    if repo_path is None:
        return default_config()
    path = Path(repo_path) / CONFIG_FILENAME
    if not path.is_file():
        return default_config()
    try:
        raw = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ConfigError(f"cannot read {path}: {exc}") from exc
    try:
        data = yaml.safe_load(raw)
    except yaml.YAMLError as exc:
        raise ConfigError(f"invalid YAML in {path}: {exc}") from exc
    if data is None:
        return default_config()
    return config_from_dict(data)
