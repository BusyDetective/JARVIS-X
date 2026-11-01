"""Validated identifiers and response normalization for the GitHub client.

Nothing here performs I/O. `RepositoryRef`, `validate_path`, `validate_ref` and
`validate_query` are the only way caller-supplied text can influence an API
path, so the model cannot turn the client into a generic HTTP client."""
from __future__ import annotations

import base64
import binascii
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlsplit

from app.github.errors import GitHubAPIError, GitHubInvalidReferenceError
from app.github.models import (
    GitHubBranch,
    GitHubCommit,
    GitHubCommitFile,
    GitHubDirectoryEntry,
    GitHubFile,
    GitHubIssue,
    GitHubPullRequest,
    GitHubRateLimit,
    GitHubRepository,
)

_OWNER_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$")
_REPO_RE = re.compile(r"^[A-Za-z0-9._-]{1,100}$")
_REF_RE = re.compile(r"^[A-Za-z0-9._/\-]{1,255}$")
_ENCODED_TRICKS = re.compile(r"%(?:2e|2f|5c|00)", re.IGNORECASE)
_GITHUB_HOSTS = {"github.com", "www.github.com"}
MAX_PATH_LENGTH = 1024
MAX_QUERY_LENGTH = 256


@dataclass(frozen=True)
class RepositoryRef:
    owner: str
    name: str

    @property
    def full_name(self) -> str:
        return f"{self.owner}/{self.name}"

    @classmethod
    def parse(cls, value: str) -> "RepositoryRef":
        """Accepts 'owner/repo' or an https://github.com/owner/repo[/...] URL.
        Anything else — other hosts, schemes, credentials, ports, extra path
        tricks — is rejected."""
        if not isinstance(value, str) or not value.strip():
            raise GitHubInvalidReferenceError("repository reference is empty")
        text = value.strip()
        if any(ord(c) < 0x21 or ord(c) == 0x7F for c in text) or len(text) > 300:
            raise GitHubInvalidReferenceError("repository reference contains invalid characters")
        if "://" in text or text.startswith(("github.com/", "www.github.com/")):
            if "://" not in text:
                text = "https://" + text
            try:
                parts = urlsplit(text)
                port = parts.port
            except ValueError as exc:
                raise GitHubInvalidReferenceError("repository URL is malformed") from exc
            if parts.scheme != "https" or (parts.hostname or "").lower() not in _GITHUB_HOSTS:
                raise GitHubInvalidReferenceError("only https://github.com repository URLs are accepted")
            if parts.username is not None or parts.password is not None or port is not None or "@" in parts.netloc:
                raise GitHubInvalidReferenceError("repository URL must not contain credentials or a port")
            segments = [s for s in parts.path.split("/") if s]
            if len(segments) < 2:
                raise GitHubInvalidReferenceError("repository URL must look like https://github.com/owner/repo")
            owner, name = segments[0], segments[1]
        else:
            segments = text.split("/")
            if len(segments) != 2:
                raise GitHubInvalidReferenceError("repository must look like 'owner/repo'")
            owner, name = segments
        if name.endswith(".git"):
            name = name[:-4]
        if not _OWNER_RE.match(owner) or not _REPO_RE.match(name) or name in (".", ".."):
            raise GitHubInvalidReferenceError("invalid repository owner or name")
        return cls(owner, name)


def validate_path(path: str | None) -> str:
    """Repository-relative path: '' (root) or segments without traversal."""
    if path is None:
        return ""
    if not isinstance(path, str):
        raise GitHubInvalidReferenceError("path must be a string")
    p = path.strip().strip("/")
    if not p:
        return ""
    if len(p) > MAX_PATH_LENGTH or "\\" in p or any(ord(c) < 0x20 or ord(c) == 0x7F for c in p):
        raise GitHubInvalidReferenceError("path contains invalid characters")
    if _ENCODED_TRICKS.search(p):
        raise GitHubInvalidReferenceError("path contains encoded traversal sequences")
    segments = p.split("/")
    if any(s in ("", ".", "..") for s in segments):
        raise GitHubInvalidReferenceError("path must not contain '.', '..' or empty segments")
    return "/".join(segments)


def validate_ref(ref: str | None) -> str | None:
    """Branch, tag or commit SHA."""
    if ref is None or not ref.strip():
        return None
    r = ref.strip()
    if (not _REF_RE.match(r) or ".." in r or r.startswith(("/", "-")) or r.endswith(("/", ".lock"))
            or "//" in r or "@{" in r):
        raise GitHubInvalidReferenceError("invalid branch, tag or commit reference")
    return r


def validate_query(query: str) -> str:
    q = " ".join((query or "").split())
    if not q:
        raise GitHubInvalidReferenceError("search query is empty")
    if len(q) > MAX_QUERY_LENGTH:
        raise GitHubInvalidReferenceError("search query is too long")
    return q


# --- Normalization -----------------------------------------------------------


def _dt(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def _require_dict(raw: Any, what: str) -> dict[str, Any]:
    if not isinstance(raw, dict):
        raise GitHubAPIError(f"GitHub returned a malformed {what} response")
    return raw


def _login(user: Any) -> str | None:
    return user.get("login") if isinstance(user, dict) and isinstance(user.get("login"), str) else None


def _wrap(what: str, fn, raw: Any):
    data = _require_dict(raw, what)
    try:
        return fn(data)
    except (KeyError, TypeError, ValueError, AttributeError) as exc:
        raise GitHubAPIError(f"GitHub returned a malformed {what} response") from exc


def parse_repository(raw: Any) -> GitHubRepository:
    def build(d: dict[str, Any]) -> GitHubRepository:
        return GitHubRepository(
            id=d["id"], full_name=d["full_name"], name=d["name"], owner=_login(d.get("owner")) or "",
            description=d.get("description"), default_branch=d.get("default_branch"),
            private=bool(d.get("private")), archived=bool(d.get("archived")), fork=bool(d.get("fork")),
            language=d.get("language"), stars=int(d.get("stargazers_count") or 0),
            open_issues=int(d.get("open_issues_count") or 0),
            topics=[t for t in (d.get("topics") or []) if isinstance(t, str)][:20],
            html_url=d["html_url"],
        )
    return _wrap("repository", build, raw)


def parse_issue(raw: Any) -> GitHubIssue:
    def build(d: dict[str, Any]) -> GitHubIssue:
        return GitHubIssue(
            number=d["number"], title=d["title"], state=d["state"], author=_login(d.get("user")),
            body=d.get("body"),
            labels=[(lbl.get("name") if isinstance(lbl, dict) else str(lbl)) for lbl in (d.get("labels") or [])][:30],
            comments=int(d.get("comments") or 0), is_pull_request="pull_request" in d,
            created_at=_dt(d.get("created_at")), updated_at=_dt(d.get("updated_at")), html_url=d["html_url"],
        )
    return _wrap("issue", build, raw)


def parse_pull_request(raw: Any) -> GitHubPullRequest:
    def build(d: dict[str, Any]) -> GitHubPullRequest:
        head, base = d.get("head") or {}, d.get("base") or {}
        return GitHubPullRequest(
            number=d["number"], title=d["title"], state=d["state"], author=_login(d.get("user")),
            body=d.get("body"), head_branch=head.get("ref"), base_branch=base.get("ref"),
            merged=bool(d.get("merged") or d.get("merged_at")), draft=bool(d.get("draft")),
            created_at=_dt(d.get("created_at")), updated_at=_dt(d.get("updated_at")), html_url=d["html_url"],
        )
    return _wrap("pull request", build, raw)


def parse_commit(raw: Any, max_files: int = 100) -> GitHubCommit:
    def build(d: dict[str, Any]) -> GitHubCommit:
        commit = d.get("commit") or {}
        author = commit.get("author") or {}
        files_raw = [f for f in (d.get("files") or []) if isinstance(f, dict) and "filename" in f]
        return GitHubCommit(
            sha=d["sha"], message=str(commit.get("message") or ""), author_name=author.get("name"),
            author_login=_login(d.get("author")), date=_dt(author.get("date")), html_url=d.get("html_url"),
            files=[GitHubCommitFile(filename=f["filename"], status=str(f.get("status", "")),
                                    additions=int(f.get("additions") or 0), deletions=int(f.get("deletions") or 0))
                   for f in files_raw[:max_files]],
            files_truncated=len(files_raw) > max_files,
        )
    return _wrap("commit", build, raw)


def parse_branch(raw: Any) -> GitHubBranch:
    def build(d: dict[str, Any]) -> GitHubBranch:
        return GitHubBranch(name=d["name"], sha=(d.get("commit") or {})["sha"], protected=bool(d.get("protected")))
    return _wrap("branch", build, raw)


def parse_directory_entry(raw: Any) -> GitHubDirectoryEntry:
    def build(d: dict[str, Any]) -> GitHubDirectoryEntry:
        return GitHubDirectoryEntry(
            name=d["name"], path=d["path"], type=str(d.get("type", "")), size=int(d.get("size") or 0),
            sha=d.get("sha"), html_url=d.get("html_url"),
        )
    return _wrap("directory entry", build, raw)


def parse_file(raw: Any, max_size: int) -> GitHubFile:
    d = _require_dict(raw, "file")
    kind = d.get("type")
    if kind == "dir":
        raise GitHubAPIError("path is a directory; use the directory listing operation")
    if kind != "file":
        raise GitHubAPIError(f"unsupported GitHub content type '{str(kind)[:20]}'")
    try:
        size, path, name, sha = int(d.get("size") or 0), d["path"], d["name"], d["sha"]
    except (KeyError, TypeError, ValueError) as exc:
        raise GitHubAPIError("GitHub returned a malformed file response") from exc
    base = dict(path=path, name=name, size=size, sha=sha, url=d.get("html_url"))
    if size > max_size:
        return GitHubFile(**base, content=None, encoding="omitted", truncated=True,
                          note=f"file is {size} bytes, above the {max_size}-byte limit; content omitted")
    if d.get("encoding") != "base64" or not isinstance(d.get("content"), str):
        return GitHubFile(**base, content=None, encoding="omitted", truncated=True,
                          note="GitHub did not return inline content for this file")
    try:
        data = base64.b64decode(d["content"], validate=False)
    except (binascii.Error, ValueError) as exc:
        raise GitHubAPIError("GitHub returned undecodable file content") from exc
    if b"\x00" in data[:8192]:
        return GitHubFile(**base, content=None, encoding="binary", note="binary file; content not returned")
    return GitHubFile(**base, content=data.decode("utf-8", errors="replace"), encoding="utf-8")


def parse_rate_limit(headers: Any) -> GitHubRateLimit | None:
    def num(name: str) -> int | None:
        try:
            return int(headers.get(name))
        except (TypeError, ValueError):
            return None

    limit, remaining, reset = num("x-ratelimit-limit"), num("x-ratelimit-remaining"), num("x-ratelimit-reset")
    if limit is None and remaining is None and reset is None:
        return None
    return GitHubRateLimit(
        limit=limit, remaining=remaining,
        reset_at=datetime.fromtimestamp(reset, tz=timezone.utc) if reset is not None else None,
    )
