from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field


class WorkspaceEntry(BaseModel):
    path: str  # always relative to the workspace root, POSIX separators
    type: Literal["file", "dir"]
    size: int | None = None
    protected: bool = False  # likely secret-bearing: listed as metadata only, never readable


class WorkspaceListing(BaseModel):
    path: str
    entries: list[WorkspaceEntry]
    truncated: bool = False


class WorkspaceFileContent(BaseModel):
    path: str
    size: int
    sha256: str  # of the raw file bytes (usable as FileChange.original_hash)
    line_count: int
    content: str  # secret-looking spans redacted; capped at workspace_max_output_chars
    truncated: bool = False
    redactions: int = 0


class SearchMatch(BaseModel):
    path: str
    line_number: int = Field(ge=1)
    line: str


class WorkspaceSearchResult(BaseModel):
    query: str
    matches: list[SearchMatch]
    files_scanned: int
    truncated: bool = False
