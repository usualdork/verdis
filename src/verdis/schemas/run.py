"""Build, run and oracle result models (PRD FR-7, FR-8)."""

from __future__ import annotations

from enum import StrEnum
from typing import Any, Self

from pydantic import Field, field_validator, model_validator

from .common import HashableModel, OracleType, normalize_text

__all__ = [
    "BuildResult",
    "BuildStatus",
    "CommandResult",
    "OracleResult",
    "ResourceUsage",
    "RunResult",
    "RunStatus",
]


class BuildStatus(StrEnum):
    OK = "ok"
    FAILED = "failed"
    SKIPPED = "skipped"
    UNSUPPORTED = "unsupported"


class RunStatus(StrEnum):
    COMPLETED = "completed"
    TIMEOUT = "timeout"
    FAILED_TO_RUN = "failed_to_run"
    BLOCKED = "blocked"
    SKIPPED = "skipped"


class CommandResult(HashableModel):
    """One execution inside the sandbox."""

    cmd: str
    exit_code: int | None = None
    signal: int | None = None
    stdout: str = ""
    stderr: str = ""
    duration_ms: int = Field(default=0, ge=0)
    timed_out: bool = False
    truncated: bool = False

    @property
    def combined(self) -> str:
        if self.stdout and self.stderr:
            return f"{self.stdout}\n{self.stderr}"
        return self.stdout or self.stderr


class ResourceUsage(HashableModel):
    """Resource consumption observed for a run (FR-8.5, FR-8.6)."""

    wall_ms: int = Field(default=0, ge=0)
    cpu_ms: int = Field(default=0, ge=0)
    max_rss_kb: int = Field(default=0, ge=0)
    exit_status: int | None = None


class OracleResult(HashableModel):
    """The result of evaluating one oracle against a run (FR-8.2, FR-8.3)."""

    oracle: OracleType
    fired: bool = False
    reason: str = ""
    evidence: tuple[str, ...] = ()
    matched_claim: bool = False
    matching_reason: str = ""
    run_index: int = Field(default=0, ge=0)
    extra: dict[str, str] = Field(default_factory=dict)

    @field_validator("evidence")
    @classmethod
    def _as_tuple(cls, value: tuple[str, ...] | list[str]) -> tuple[str, ...]:
        return tuple(value)

    @property
    def headline(self) -> str:
        if not self.evidence:
            return self.reason
        return self.evidence[0]


class BuildResult(HashableModel):
    """Outcome of building the target (FR-7)."""

    status: BuildStatus = BuildStatus.SKIPPED
    ref: str = ""
    recipe: str = ""
    recipe_hash: str = ""
    image_digest: str = ""
    logs: tuple[str, ...] = ()
    duration_ms: int = Field(default=0, ge=0)
    failure_step: str = ""
    log_excerpt: str = ""
    suggested_fix: str = ""
    cached: bool = False
    artifact_path: str = ""

    @field_validator("logs")
    @classmethod
    def _as_tuple(cls, value: tuple[str, ...] | list[str]) -> tuple[str, ...]:
        return tuple(value)

    @property
    def ok(self) -> bool:
        return self.status is BuildStatus.OK


class RunResult(HashableModel):
    """Outcome of running the PoC in the sandbox (FR-8)."""

    status: RunStatus = RunStatus.COMPLETED
    ref: str = ""
    runs: tuple[CommandResult, ...] = ()
    oracles: tuple[OracleResult, ...] = ()
    resource: ResourceUsage = Field(default_factory=ResourceUsage)
    filesystem_changes: tuple[str, ...] = ()
    blocked_network: tuple[str, ...] = ()
    canary_hits: tuple[str, ...] = ()
    sandbox_profile: str = "default"
    sandbox_backend: str = ""
    isolation: str = ""
    """The isolation the run actually had, as the runtime reported it."""
    image_digest: str = ""

    @field_validator("runs", "oracles", "filesystem_changes", "blocked_network", "canary_hits")
    @classmethod
    def _as_tuple(cls, value: tuple[Any, ...] | list[Any]) -> tuple[Any, ...]:
        return tuple(value)

    @model_validator(mode="after")
    def _default_ref(self) -> Self:
        return self

    @property
    def any_fired(self) -> bool:
        return any(o.fired for o in self.oracles)

    @property
    def matched_fired(self) -> bool:
        """An oracle fired *and* it matched the claim (FR-8.3)."""
        return any(o.fired and o.matched_claim for o in self.oracles)

    @property
    def ran_as_intended(self) -> bool:
        """True when the PoC command actually executed.

        A command that could not be started (missing binary) is *not* the same
        as a command that ran and produced no crash (PRD 8.1).
        """
        if not self.runs:
            return False
        return all(
            r.exit_code is not None or r.signal is not None or r.timed_out
            for r in self.runs
        )

    @property
    def stdout(self) -> str:
        return "\n".join(r.stdout for r in self.runs if r.stdout)

    @property
    def stderr(self) -> str:
        return "\n".join(r.stderr for r in self.runs if r.stderr)

    @property
    def combined_output(self) -> str:
        return "\n".join(r.combined for r in self.runs if r.combined)

    @property
    def exit_codes(self) -> tuple[int | None, ...]:
        return tuple(r.exit_code for r in self.runs)

    @property
    def exit_code(self) -> int | None:
        """The exit code of the first run, if there is one."""
        return self.runs[0].exit_code if self.runs else None

    @property
    def fired_count(self) -> int:
        return sum(1 for o in self.oracles if o.fired)

    def evidence_lines(self) -> tuple[str, ...]:
        out: list[str] = []
        for oracle in self.oracles:
            if oracle.fired:
                out.extend(oracle.evidence)
        return tuple(out)

    def normalized_output(self) -> str:
        return normalize_text(self.combined_output)
