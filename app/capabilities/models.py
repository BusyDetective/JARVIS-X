from __future__ import annotations

import re
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field, field_validator, model_validator

from app.security.permissions import PermissionLevel

_ID_RE = re.compile(r"^[a-z][a-z0-9_]*$")
_SEMVER_RE = re.compile(r"^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$")

# Severity order of the existing permission levels (least -> most
# restrictive). Used only to COMPARE levels for reporting; it never
# changes what any tool requires.
PERMISSION_RANK: dict[PermissionLevel, int] = {
    PermissionLevel.SAFE: 0,
    PermissionLevel.CONFIRM: 1,
    PermissionLevel.DANGEROUS: 2,
    PermissionLevel.BLOCKED: 3,
}


def max_permission(levels: list[PermissionLevel]) -> PermissionLevel:
    return max(levels, key=PERMISSION_RANK.__getitem__, default=PermissionLevel.SAFE)


def is_valid_version(version: str) -> bool:
    return bool(_SEMVER_RE.match(version))


class CapabilityCategory(str, Enum):
    CORE = "core"
    INFORMATION = "information"
    PRODUCTIVITY = "productivity"
    DEVELOPMENT = "development"
    SYSTEM = "system"
    INTEGRATION = "integration"
    OTHER = "other"


class CapabilitySource(str, Enum):
    """Where a capability came from. Only BUILTIN and LOCAL can be
    installed in Phase 5; PLUGIN and FUTURE_EXTERNAL are reserved so the
    model can express them later without a schema change."""

    BUILTIN = "builtin"
    LOCAL = "local"
    PLUGIN = "plugin"
    FUTURE_EXTERNAL = "future_external"


class Capability(BaseModel):
    """Descriptive, provider-agnostic declaration of a usable ability.

    CONTROL-PLANE DATA ONLY: nothing here grants anything. `max_permission`
    is a *declared* ceiling for reporting/validation; each Tool's own
    `permission_level` stays authoritative at execution time, and a
    capability can never raise or lower it.

    `id` is a stable human-readable slug (not a UUID — there is nothing
    to disambiguate, and slugs are what `depends_on` refers to).
    """

    model_config = {"frozen": True}

    id: str
    name: str
    description: str = ""
    version: str = "1.0.0"
    category: CapabilityCategory = CapabilityCategory.OTHER
    enabled: bool = True
    source: CapabilitySource = CapabilitySource.LOCAL
    max_permission: PermissionLevel = PermissionLevel.SAFE
    tool_names: tuple[str, ...] = ()
    depends_on: tuple[str, ...] = ()
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("id")
    @classmethod
    def _valid_id(cls, v: str) -> str:
        if not _ID_RE.match(v):
            raise ValueError("capability id must match ^[a-z][a-z0-9_]*$")
        return v

    @field_validator("name")
    @classmethod
    def _name_not_blank(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("capability name cannot be blank")
        return v

    @field_validator("version")
    @classmethod
    def _valid_version(cls, v: str) -> str:
        if not is_valid_version(v):
            raise ValueError("version must look like MAJOR.MINOR.PATCH[-prerelease]")
        return v

    @field_validator("tool_names")
    @classmethod
    def _tool_names_ok(cls, v: tuple[str, ...]) -> tuple[str, ...]:
        if any(not n.strip() for n in v):
            raise ValueError("tool names cannot be blank")
        if len(set(v)) != len(v):
            raise ValueError("tool_names must be unique")
        return v

    @model_validator(mode="after")
    def _deps_ok(self) -> "Capability":
        if len(set(self.depends_on)) != len(self.depends_on):
            raise ValueError("depends_on must be unique")
        if self.id in self.depends_on:
            raise ValueError("a capability cannot depend on itself")
        for dep in self.depends_on:
            if not _ID_RE.match(dep):
                raise ValueError(f"invalid dependency id: {dep!r}")
        return self


# --- Descriptions (serializable, model/diagnostics-facing) -------------------


class ToolInfo(BaseModel):
    """Public description of one tool. Deliberately excludes Python class
    names/modules, paths, state, and anything secret. `input_schema` is the
    same JSON Schema the model receives. `permission_level` is the TOOL's
    own level (authoritative)."""

    name: str
    description: str
    version: str
    permission_level: PermissionLevel
    requires_approval: bool
    timeout_seconds: float
    input_schema: dict[str, Any]
    capability_id: str | None
    category: CapabilityCategory | None
    enabled: bool


class DependencyStatus(BaseModel):
    satisfied: bool
    missing: list[str] = Field(default_factory=list)
    disabled: list[str] = Field(default_factory=list)


class CapabilityInfo(BaseModel):
    id: str
    name: str
    description: str
    version: str
    category: CapabilityCategory
    source: CapabilitySource
    enabled: bool
    declared_max_permission: PermissionLevel
    effective_max_permission: PermissionLevel
    permission_mismatch: bool  # declared < effective: the declaration understates its tools
    tools: list[ToolInfo]
    depends_on: list[str]
    dependency_status: DependencyStatus
    metadata: dict[str, Any]


class CapabilitySnapshot(BaseModel):
    """Deterministic, serializable picture of the installed capabilities
    (sorted by id, tools by name, no timestamps): diagnosable and
    diff-able. Phase 5 only reports installed versions; it never updates."""

    schema_version: int = 1
    capabilities: list[CapabilityInfo]

    def to_json(self) -> str:
        return self.model_dump_json(indent=2)

    def canonical_dict(self) -> dict[str, Any]:
        return self.model_dump(mode="json")


class UsabilityReport(BaseModel):
    usable: bool
    reasons: list[str] = Field(default_factory=list)
