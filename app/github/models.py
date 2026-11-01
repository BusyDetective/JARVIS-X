from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field, field_validator


def _utc(v: datetime | None) -> datetime | None:
    if v is not None and v.tzinfo is None:
        raise ValueError("datetime fields must be timezone-aware (UTC), not naive")
    return v


class _Model(BaseModel):
    pass


class GitHubRepository(_Model):
    id: int
    full_name: str
    name: str
    owner: str
    description: str | None = None
    default_branch: str | None = None
    private: bool = False
    archived: bool = False
    fork: bool = False
    language: str | None = None
    stars: int = 0
    open_issues: int = 0
    topics: list[str] = Field(default_factory=list)
    html_url: str


class GitHubSearchResult(_Model):
    query: str
    total_count: int
    incomplete: bool = False
    repositories: list[GitHubRepository]


class GitHubFile(_Model):
    """`content` is decoded UTF-8 text, or None when the file is binary or too
    large (see `note`). `size` is GitHub's reported byte size."""

    path: str
    name: str
    size: int
    sha: str
    content: str | None = None
    encoding: Literal["utf-8", "binary", "omitted"] = "utf-8"
    truncated: bool = False
    note: str | None = None
    url: str | None = None


class GitHubDirectoryEntry(_Model):
    name: str
    path: str
    type: str
    size: int = 0
    sha: str | None = None
    html_url: str | None = None


class GitHubDirectoryListing(_Model):
    path: str
    entries: list[GitHubDirectoryEntry]
    total_entries: int
    truncated: bool = False


class GitHubIssue(_Model):
    number: int
    title: str
    state: str
    author: str | None = None
    body: str | None = None
    labels: list[str] = Field(default_factory=list)
    comments: int = 0
    is_pull_request: bool = False
    created_at: datetime | None = None
    updated_at: datetime | None = None
    html_url: str

    _tz = field_validator("created_at", "updated_at")(_utc)


class GitHubPullRequest(_Model):
    number: int
    title: str
    state: str
    author: str | None = None
    body: str | None = None
    head_branch: str | None = None
    base_branch: str | None = None
    merged: bool = False
    draft: bool = False
    created_at: datetime | None = None
    updated_at: datetime | None = None
    html_url: str

    _tz = field_validator("created_at", "updated_at")(_utc)


class GitHubCommitFile(_Model):
    filename: str
    status: str
    additions: int = 0
    deletions: int = 0


class GitHubCommit(_Model):
    sha: str
    message: str
    author_name: str | None = None
    author_login: str | None = None
    date: datetime | None = None
    html_url: str | None = None
    files: list[GitHubCommitFile] = Field(default_factory=list)
    files_truncated: bool = False

    _tz = field_validator("date")(_utc)


class GitHubBranch(_Model):
    name: str
    sha: str
    protected: bool = False


class GitHubRateLimit(_Model):
    limit: int | None = None
    remaining: int | None = None
    reset_at: datetime | None = None

    _tz = field_validator("reset_at")(_utc)
