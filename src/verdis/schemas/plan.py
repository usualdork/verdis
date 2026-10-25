"""The restricted plan step language (PRD FR-6.1).

A plan is a small, typed sequence of steps. The vocabulary is deliberately
tiny: it can express checkout, build, copy, run, expect and compare, and
*cannot* express network access, host access or secret access. Anything that
does not fit is rejected by the validator rather than "best effort" compiled.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Annotated, Literal, Self

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from .common import HashableModel, OracleType, normalize_text

__all__ = [
    "BuildStep",
    "CheckoutStep",
    "CompareStep",
    "CopyStep",
    "ExpectStep",
    "Plan",
    "PlanSource",
    "RunStep",
    "Step",
]

_TIMEOUT_RE = r"^\d+(ms|s|m|h)$"


class PlanSource(StrEnum):
    RRS = "rrs"
    MODEL = "model"
    HEURISTIC = "heuristic"
    HUMAN = "human"


class _StepBase(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class CheckoutStep(_StepBase):
    """Check out a ref of the target repository."""

    kind: Literal["checkout"] = "checkout"
    ref: str = Field(min_length=1)
    subdir: str = ""

    @field_validator("ref", "subdir")
    @classmethod
    def _strip(cls, value: str) -> str:
        return value.strip()


class BuildStep(_StepBase):
    """Build the target from a recipe."""

    kind: Literal["build"] = "build"
    recipe: str = Field(default="default")
    flags: tuple[str, ...] = ()
    steps: tuple[str, ...] = ()
    timeout: str = Field(default="600s", pattern=_TIMEOUT_RE)

    @field_validator("flags", "steps")
    @classmethod
    def _as_tuple(cls, value: tuple[str, ...] | list[str]) -> tuple[str, ...]:
        return tuple(value)


class CopyStep(_StepBase):
    """Copy a PoC artifact into the sandbox workdir."""

    kind: Literal["copy"] = "copy"
    artifact: str = Field(min_length=1)
    to: str = Field(min_length=1)

    @field_validator("artifact", "to")
    @classmethod
    def _strip(cls, value: str) -> str:
        return value.strip()


class RunStep(_StepBase):
    """Run the PoC command inside the sandbox."""

    kind: Literal["run"] = "run"
    cmd: str = Field(min_length=1)
    timeout: str = Field(default="30s", pattern=_TIMEOUT_RE)
    repeat: int = Field(default=3, ge=1, le=20)
    cwd: str = ""
    env: dict[str, str] = Field(default_factory=dict)

    @field_validator("cmd", "cwd")
    @classmethod
    def _strip(cls, value: str) -> str:
        return value.strip()

    @field_validator("env", mode="before")
    @classmethod
    def _as_mapping(cls, value: object) -> dict[str, str]:
        """The environment is a mapping.

        A list of "NAME=value" strings is accepted, because that is how
        it is written in a report block.
        """
        if value is None:
            return {}
        if isinstance(value, dict):
            return {str(key): str(item) for key, item in value.items()}
        if isinstance(value, (list, tuple)):
            out: dict[str, str] = {}
            for entry in value:
                text = str(entry)
                name, separator, item = text.partition("=")
                if separator:
                    out[name.strip()] = item
            return out
        return {}


class ExpectStep(_StepBase):
    """Declare what should be observed if the claim is true."""

    kind: Literal["expect"] = "expect"
    oracle: OracleType = OracleType.OUTPUT
    signature: str = ""
    function: str = ""
    regex: str = ""
    exit_code: int | None = None
    class_id: str = ""

    @field_validator("signature", "function", "regex", "class_id")
    @classmethod
    def _strip(cls, value: str) -> str:
        return value.strip()


class CompareStep(_StepBase):
    """Run the same plan against a comparison ref (FR-6.4)."""

    kind: Literal["compare"] = "compare"
    ref: str = Field(min_length=1)
    note: str = ""

    @field_validator("ref", "note")
    @classmethod
    def _strip(cls, value: str) -> str:
        return value.strip()


Step = Annotated[
    CheckoutStep | BuildStep | CopyStep | RunStep | ExpectStep | CompareStep,
    Field(discriminator="kind"),
]


class Plan(HashableModel):
    """A validated, restricted plan."""

    steps: tuple[Step, ...] = ()
    comparison_ref: str = ""
    default_config: bool = True
    source: PlanSource = PlanSource.HEURISTIC
    notes: tuple[str, ...] = ()
    model_name: str = ""

    @field_validator("steps", "notes")
    @classmethod
    def _as_tuple(cls, value: tuple[object, ...] | list[object]) -> tuple[object, ...]:
        return tuple(value)

    @model_validator(mode="after")
    def _check_shape(self) -> Self:
        kinds = [step.kind for step in self.steps]
        if "run" not in kinds:
            raise ValueError("a plan must contain at least one run step")
        if kinds.count("run") > 1:
            raise ValueError("a plan must contain exactly one run step")
        if "expect" not in kinds:
            raise ValueError("a plan must contain at least one expect step")
        if kinds.index("expect") < kinds.index("run"):
            raise ValueError("expect step must follow the run step it describes")
        return self

    @property
    def run_step(self) -> RunStep:
        for step in self.steps:
            if step.kind == "run":
                return step
        raise ValueError("plan has no run step")  # pragma: no cover - guarded by validator

    @property
    def expect_steps(self) -> tuple[ExpectStep, ...]:
        return tuple(step for step in self.steps if step.kind == "expect")

    @property
    def build_step(self) -> BuildStep | None:
        for step in self.steps:
            if step.kind == "build":
                return step
        return None

    @property
    def checkout_step(self) -> CheckoutStep | None:
        for step in self.steps:
            if step.kind == "checkout":
                return step
        return None

    @property
    def copy_steps(self) -> tuple[CopyStep, ...]:
        return tuple(step for step in self.steps if step.kind == "copy")

    @property
    def compare_steps(self) -> tuple[CompareStep, ...]:
        return tuple(step for step in self.steps if step.kind == "compare")

    def expected_signature(self) -> str:
        for step in self.expect_steps:
            if step.signature:
                return normalize_text(step.signature)
        return ""

    def to_text(self) -> str:
        """Render the plan in the human-readable form used in Appendix A."""
        lines: list[str] = []
        for step in self.steps:
            if step.kind == "checkout":
                lines.append(f"checkout ref={step.ref}")
            elif step.kind == "build":
                flags = ",".join(step.flags)
                lines.append(f"build recipe={step.recipe}" + (f" flags={flags}" if flags else ""))
            elif step.kind == "copy":
                lines.append(f"copy artifact={step.artifact} to={step.to}")
            elif step.kind == "run":
                lines.append(
                    f"run cmd='{step.cmd}' timeout={step.timeout} repeat={step.repeat}"
                )
            elif step.kind == "expect":
                bits = [f"oracle={step.oracle}"]
                if step.class_id:
                    bits.append(f"class={step.class_id}")
                if step.function:
                    bits.append(f"function={step.function}")
                if step.signature:
                    bits.append(f"signature={step.signature}")
                lines.append("expect " + " ".join(bits))
            elif step.kind == "compare":
                lines.append(f"compare ref={step.ref}")
        return "\n".join(lines)
