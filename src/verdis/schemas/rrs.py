"""Reproducible Report Spec (RRS) v0.1 — draft (PRD section 9.4, Appendix D).

A reporter can embed a small YAML block in their report. When present it is
parsed deterministically, without a model, which is what makes the no-LLM
mode fully functional and dedupe reliable.
"""

from __future__ import annotations

from typing import Any, Self

from pydantic import Field, field_validator, model_validator

from .common import HashableModel, OracleType, normalize_cwe

__all__ = [
    "RRS",
    "SUPPORTED_VERSIONS",
    "RRSInput",
    "RRSPlanStep",
    "RRSTarget",
    "rsr_version_supported",
]

SUPPORTED_VERSIONS = ("0.1", "0.1.0")


def rsr_version_supported(version: str) -> bool:
    """Only RRS 0.1 exists today; unknown versions are rejected."""
    return str(version).strip() in SUPPORTED_VERSIONS


class RRSTarget(HashableModel):
    repo: str = Field(min_length=1)
    ref: str = ""


class RRSInput(HashableModel):
    path: str = Field(min_length=1)
    sha256: str = Field(default="", pattern=r"^$|^[0-9a-f]{64}$")
    role: str = "input"

    @field_validator("sha256", mode="before")
    @classmethod
    def _as_text(cls, value: Any) -> str:
        if value is None:
            return ""
        if isinstance(value, bool):
            raise ValueError("sha256 must be a string")
        if isinstance(value, int):
            # YAML turns an all-digit hash into an integer and loses the
            # leading zeros; put them back.
            if value < 0:
                raise ValueError("sha256 must be a non-negative hash")
            return f"{value:064x}"
        return str(value).strip()


class RRSPlanStep(HashableModel):
    """One entry of the RRS ``steps`` list.

    The spec is intentionally loose here: a step is a free-form instruction
    such as ``build: default`` or ``run: ./demo poc.bin``. The planner
    translates them into the restricted plan language; anything that cannot
    be expressed is rejected there, not here.
    """

    action: str = Field(min_length=1)
    value: str = ""
    raw: str = ""

    @field_validator("action", "value", "raw")
    @classmethod
    def _strip(cls, value: str) -> str:
        return str(value).strip()

    @model_validator(mode="before")
    @classmethod
    def _accept_single_key(cls, data: Any) -> Any:
        """Accept ``{"run": "./demo"}`` and ``"run: ./demo"``."""
        if isinstance(data, str):
            if ":" in data:
                action, _, value = data.partition(":")
                return {"action": action.strip(), "value": value.strip(), "raw": data}
            return {"action": data.strip(), "value": "", "raw": data}
        if isinstance(data, dict) and "action" not in data:
            if len(data) == 1:
                action, value = next(iter(data.items()))
                return {
                    "action": str(action).strip(),
                    "value": str(value).strip(),
                    "raw": f"{action}: {value}",
                }
            if "build" in data:
                return {
                    "action": "build",
                    "value": str(data.get("build", "")),
                    "raw": "build",
                }
            if "run" in data:
                return {
                    "action": "run",
                    "value": str(data.get("run", "")),
                    "raw": "run",
                }
        return data


class RRS(HashableModel):
    """A parsed RRS block."""

    version: str = "0.1"
    target: RRSTarget
    claim_class: str = Field(default="", alias="class")
    component: str = ""
    impact: str = ""
    steps: tuple[RRSPlanStep, ...] = ()
    inputs: tuple[RRSInput, ...] = ()
    expect: dict[str, Any] = Field(default_factory=dict)
    config: dict[str, Any] = Field(default_factory=dict)
    raw: dict[str, Any] = Field(default_factory=dict)

    # The RRS is an open format: unknown fields are kept, not rejected.
    model_config = {"populate_by_name": True, "extra": "allow", "frozen": True}  # noqa: RUF012

    @field_validator("claim_class", mode="before")
    @classmethod
    def _norm_class(cls, value: Any) -> str:
        if value in (None, ""):
            return ""
        return normalize_cwe(str(value))

    @field_validator("steps", "inputs")
    @classmethod
    def _as_tuple(cls, value: tuple[Any, ...] | list[Any]) -> tuple[Any, ...]:
        return tuple(value)

    @model_validator(mode="before")
    @classmethod
    def _accept_legacy_keys(cls, data: Any) -> Any:
        if not isinstance(data, dict):
            return data
        data = dict(data)
        if "version" not in data and "rrs" in data:
            data["version"] = data.pop("rrs")
        data.pop("rrs", None)
        claim = data.get("claim")
        if isinstance(claim, dict):
            data = dict(data)
            data.pop("claim", None)
            if "class" in claim and "claim_class" not in data:
                data["claim_class"] = claim["class"]
            if "component" in claim and "component" not in data:
                data["component"] = claim["component"]
            if "impact" in claim and "impact" not in data:
                data["impact"] = claim["impact"]
        if "expect" in data and isinstance(data["expect"], dict):
            expect = dict(data["expect"])
            if "oracle" in expect:
                expect["oracle"] = str(expect["oracle"]).strip().lower()
            data["expect"] = expect
        return data

    @model_validator(mode="after")
    def _check_version(self) -> Self:
        if not rsr_version_supported(self.version):
            raise ValueError(
                f"unsupported RRS version {self.version!r}; "
                f"supported: {', '.join(SUPPORTED_VERSIONS)}"
            )
        return self

    @property
    def oracle(self) -> OracleType | None:
        raw = str(self.expect.get("oracle", "")).strip().lower()
        if not raw:
            return None
        try:
            return OracleType(raw)
        except ValueError:
            return None

    @property
    def regex(self) -> str:
        """The pattern the report expects in the output, if it gave one."""
        return str(self.expect.get("regex", "")).strip()

    @property
    def exit_code(self) -> int | None:
        """The exit code the report expects, if it gave one."""
        raw = self.expect.get("exit_code")
        if raw is None:
            return None
        try:
            return int(raw)
        except (TypeError, ValueError):
            return None

    @property
    def signature(self) -> str:
        return str(self.expect.get("signature", "")).strip()

    @property
    def default_config(self) -> bool:
        value = self.config.get("default")
        return True if value is None else bool(value)

    def run_commands(self) -> tuple[str, ...]:
        return tuple(step.value for step in self.steps if step.action == "run" and step.value)

    def build_instructions(self) -> tuple[str, ...]:
        return tuple(step.value for step in self.steps if step.action == "build" and step.value)
