from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, Field


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class FileEntry(BaseModel):
    path: str
    sha256: str
    size: int


class TestBaseline(BaseModel):
    __test__ = False  # not a pytest class

    passed: int = Field(ge=0)
    failed: int = Field(default=0, ge=0)
    skipped: int = Field(default=0, ge=0)
    duration_seconds: float | None = None
    recorded_at: datetime = Field(default_factory=utcnow)


class SystemManifest(BaseModel):
    """Reproducible description of one source tree. Contains file hashes and
    metadata only — never file contents, secrets or environment values."""

    schema_version: int = 1
    project_version: str
    git_commit: str | None = None
    config_schema_version: int = 1
    config_schema_hash: str | None = None  # sha256 of app/config/settings.py, when present
    dependencies: dict[str, list[str]] = Field(default_factory=dict)
    files: list[FileEntry]
    test_baseline: TestBaseline | None = None
    content_hash: str  # over files + dependencies + config hash (deterministic; no timestamps)
    created_at: datetime = Field(default_factory=utcnow)


class UpdateManifest(BaseModel):
    version: str
    parent_version: str | None = None
    created_at: datetime = Field(default_factory=utcnow)
    change_id: str | None = None
    risk_level: str = "low"
    validation_status: str = "none"
    approval_status: str = "none"
    files_changed: list[str] = Field(default_factory=list)
    test_summary: dict[str, Any] = Field(default_factory=dict)


class PointerState(BaseModel):
    """The controlled "current" pointer. `history` is the stack of earlier
    known-good versions, most recent last (rollback walks it backwards)."""

    schema_version: int = 1
    version: str
    history: list[str] = Field(default_factory=list)
    switched_at: datetime = Field(default_factory=utcnow)


class IntegrityReport(BaseModel):
    version: str
    valid: bool
    missing: list[str] = Field(default_factory=list)
    modified: list[str] = Field(default_factory=list)
    unexpected: list[str] = Field(default_factory=list)


class ManifestDiff(BaseModel):
    added: list[str]
    removed: list[str]
    modified: list[str]
    dependencies_changed: bool
    config_changed: bool
    test_count_delta: int | None = None
