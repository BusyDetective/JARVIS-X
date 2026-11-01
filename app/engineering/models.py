from __future__ import annotations

import re
from datetime import datetime, timezone
from enum import Enum
from typing import Literal

from pydantic import BaseModel, Field, field_validator

from app.workspace.models import SearchMatch

_HASH_RE = re.compile(r"^[0-9a-f]{64}$")


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class ProjectStructure(BaseModel):
    path: str = "."
    total_files: int
    total_dirs: int
    files: list[str]  # bounded sample, sorted
    directories: list[str]
    languages: dict[str, int]  # language -> file count
    config_files: list[str]
    entry_points: list[str]
    truncated: bool = False


class SourceFile(BaseModel):
    path: str
    language: str | None = None
    size: int
    line_count: int
    sha256: str
    content: str
    truncated: bool = False


class CodeSearchResult(BaseModel):
    query: str
    matches: list[SearchMatch]
    files_scanned: int
    truncated: bool = False


class FileChange(BaseModel):
    """A PROPOSED change to one file (never applied by Phase 7).
    `original_hash` is the SHA-256 of the file as the proposal was based on it
    (None only when proposing a brand-new file)."""

    path: str = Field(min_length=1, max_length=1024)
    original_hash: str | None = None
    new_content: str
    reason: str = Field(min_length=1, max_length=500)

    @field_validator("original_hash")
    @classmethod
    def _hash_ok(cls, v: str | None) -> str | None:
        if v is not None and not _HASH_RE.match(v):
            raise ValueError("original_hash must be a lowercase 64-character SHA-256 hex digest")
        return v


class DiffFile(BaseModel):
    path: str
    status: Literal["added", "modified", "unchanged"]
    additions: int = 0
    deletions: int = 0


class Diff(BaseModel):
    files: list[DiffFile]
    unified_diff: str
    summary: str
    truncated: bool = False
    applied: Literal[False] = False  # a Diff is a proposal; Phase 7 has no way to apply it


class PlanStage(str, Enum):
    INSPECT_PROJECT = "inspect_project"
    IDENTIFY_FILES = "identify_files"
    UNDERSTAND_DEPENDENCIES = "understand_dependencies"
    PROPOSE_CHANGES = "propose_changes"
    GENERATE_PATCH = "generate_patch"
    VALIDATE = "validate"
    APPROVAL = "approval"


class EngineeringTask(BaseModel):
    id: str
    stage: PlanStage
    title: str
    description: str
    files: list[str] = Field(default_factory=list)
    depends_on: list[str] = Field(default_factory=list)
    status: Literal["pending"] = "pending"


class EngineeringPlan(BaseModel):
    goal: str
    tasks: list[EngineeringTask]
    created_at: datetime = Field(default_factory=utcnow)
    requires_approval: Literal[True] = True
    status: Literal["proposed"] = "proposed"
    notes: list[str] = Field(default_factory=list)
