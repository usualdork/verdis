"""Evidence bundle models (PRD section 8.3)."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import Field, field_validator

from .common import HashableModel, now_utc

__all__ = ["BundleFile", "BundleManifest", "EnvironmentInfo", "ModelInfo"]


class BundleFile(HashableModel):
    """One file in the bundle, with its hash (evidence-tampering defence)."""

    path: str
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    size: int = Field(default=0, ge=0)


class EnvironmentInfo(HashableModel):
    """Environment recorded in the manifest (section 8.3)."""

    image_digests: tuple[str, ...] = ()
    sandbox_profile: str = "default"
    sandbox_backend: str = ""
    isolation: str = ""
    """The isolation the run actually had, as the runtime reported it."""
    kernel: str = ""
    tool_versions: dict[str, str] = Field(default_factory=dict)
    os: str = ""

    @field_validator("image_digests")
    @classmethod
    def _as_tuple(cls, value: tuple[str, ...] | list[str]) -> tuple[str, ...]:
        return tuple(value)


class ModelInfo(HashableModel):
    """Which model produced which part, and at what version."""

    provider: str = ""
    name: str = ""
    version: str = ""
    used_for: tuple[str, ...] = ()
    prompt_hash: str = ""
    response_hash: str = ""
    redactions: tuple[str, ...] = ()
    tokens_used: int = Field(default=0, ge=0)
    cost_usd: float = Field(
        default=0.0, ge=0.0, description="The modelled cost of the model calls."
    )

    @field_validator("used_for", "redactions")
    @classmethod
    def _as_tuple(cls, value: tuple[str, ...] | list[str]) -> tuple[str, ...]:
        return tuple(value)

    @property
    def used(self) -> bool:
        return bool(self.name)


class BundleManifest(HashableModel):
    """The manifest at the root of an evidence bundle."""

    report_id: str
    created_at: datetime = Field(default_factory=now_utc)
    tool_version: str = ""
    tool_commit: str = ""
    schema_version: str = "1.0"
    verdict: str = ""
    target: dict[str, Any] = Field(default_factory=dict)
    files: tuple[BundleFile, ...] = ()
    environment: EnvironmentInfo = Field(default_factory=EnvironmentInfo)
    model: ModelInfo = Field(default_factory=ModelInfo)
    extra: dict[str, Any] = Field(default_factory=dict)

    @field_validator("files")
    @classmethod
    def _as_tuple(cls, value: tuple[BundleFile, ...] | list[BundleFile]) -> tuple[BundleFile, ...]:
        return tuple(value)
