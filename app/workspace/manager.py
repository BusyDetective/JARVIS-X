from __future__ import annotations

import fnmatch
import hashlib
import logging
import os
import re
from pathlib import Path

from pydantic import BaseModel, Field

from app.memory.secrets import redact_secrets
from app.workspace.errors import (
    WorkspaceAccessDeniedError,
    WorkspaceError,
    WorkspaceFileTooLargeError,
    WorkspacePathError,
    WorkspaceUnsupportedFileError,
)
from app.workspace.models import (
    SearchMatch,
    WorkspaceEntry,
    WorkspaceFileContent,
    WorkspaceListing,
    WorkspaceSearchResult,
)

logger = logging.getLogger(__name__)

MAX_PATH_LENGTH = 1024
MAX_QUERY_LENGTH = 200
MAX_LINE_CHARS = 300
_ENCODED_TRICKS = re.compile(r"%(?:2e|2f|5c|00)", re.IGNORECASE)
# Names that very likely hold secrets. Listed as metadata only, never read.
_PROTECTED_NAMES = (
    ".env", ".env.*", "*.pem", "*.key", "*.p12", "*.pfx", "*.jks", "*.keystore", "*.secret", "*.token",
    "id_rsa*", "id_dsa*", "id_ecdsa*", "id_ed25519*", "credentials", "credentials.*", "secrets",
    "secrets.*", ".netrc", ".pypirc", ".npmrc", ".git-credentials", "token", "tokens.json", "token.json",
    "token.txt",
)
_PUBLIC_ENV_TEMPLATES = {".env.example", ".env.sample", ".env.template", ".env.dist"}
_PROTECTED_DIRS = {".git", ".ssh", ".aws", ".gnupg", ".kube", ".docker"}
# Noise directories skipped when walking (still readable if asked for by path).
_IGNORED_DIRS = {"__pycache__", "node_modules", ".venv", "venv", ".mypy_cache", ".pytest_cache",
                 ".ruff_cache", ".tox", ".idea", ".eggs"}


class WorkspaceLimits(BaseModel):
    model_config = {"frozen": True}

    max_file_size: int = Field(default=200_000, ge=100, le=5_000_000)
    max_files: int = Field(default=2_000, ge=1, le=50_000)
    max_search_results: int = Field(default=50, ge=1, le=500)
    max_output_chars: int = Field(default=24_000, ge=500, le=500_000)

    @classmethod
    def from_settings(cls) -> "WorkspaceLimits":
        from app.config.settings import settings

        return cls(
            max_file_size=settings.workspace_max_file_size, max_files=settings.workspace_max_files,
            max_search_results=settings.workspace_max_search_results,
            max_output_chars=settings.workspace_max_output_chars,
        )


def is_protected_path(rel_posix: str) -> bool:
    """True for paths that likely hold secrets (by name or protected folder)."""
    parts = [p for p in rel_posix.split("/") if p]
    if any(p in _PROTECTED_DIRS for p in parts[:-1]) or (parts and parts[-1] in _PROTECTED_DIRS):
        return True
    if not parts:
        return False
    name = parts[-1].lower()
    if name in _PUBLIC_ENV_TEMPLATES:
        return False
    return any(fnmatch.fnmatchcase(name, pat) for pat in _PROTECTED_NAMES)


def _looks_binary(sample: bytes) -> bool:
    if b"\x00" in sample:
        return True
    if not sample:
        return False
    control = sum(1 for b in sample if b < 9 or (13 < b < 32))
    return control / len(sample) > 0.30


def _has_private_key(text: str) -> bool:
    return "-----BEGIN" in text and "PRIVATE KEY-----" in text


class WorkspaceManager:
    """Read-only, confined access to one project directory.

    Guarantees (all enforced here — tools never touch the filesystem):
    - every path is resolved canonically and must stay under the root
      (rejects `..`, absolute paths, drive letters, encoded traversal and
      symlinks that lead outside);
    - symlinks are never followed while walking;
    - likely secret files (.env, keys, credentials, tokens, .git, .ssh, ...)
      are metadata-only; other files are scanned for secret patterns, which
      are redacted, and files containing private-key blocks are refused;
    - binary and oversized files are refused; output is capped;
    - nothing is written, executed or installed. Ordering is deterministic.
    Only relative POSIX paths are ever reported (no absolute paths leak).
    """

    def __init__(self, root: Path | str, limits: WorkspaceLimits | None = None) -> None:
        resolved = Path(root).resolve()
        if not resolved.is_dir():
            raise WorkspaceError("workspace root is not an existing directory")
        self._root = resolved
        self.limits = limits or WorkspaceLimits()

    # --- paths ---------------------------------------------------------------

    def get_project_root(self) -> Path:
        """Internal use only: never include this absolute path in model-facing output."""
        return self._root

    def _rel(self, resolved: Path) -> str:
        return "." if resolved == self._root else resolved.relative_to(self._root).as_posix()

    def _resolve(self, rel: str | None) -> Path:
        if rel is None:
            return self._root
        if not isinstance(rel, str):
            raise WorkspacePathError("path must be a string")
        if rel.strip() in ("", "."):
            return self._root
        if len(rel) > MAX_PATH_LENGTH or "\\" in rel or any(ord(c) < 0x20 or ord(c) == 0x7F for c in rel):
            raise WorkspacePathError("path contains invalid characters")
        if rel.startswith(("/", "~")) or re.match(r"^[A-Za-z]:", rel):
            raise WorkspacePathError("absolute paths are not allowed; use a path relative to the workspace")
        if _ENCODED_TRICKS.search(rel):
            raise WorkspacePathError("path contains encoded traversal sequences")
        parts = [p for p in rel.split("/") if p not in ("", ".")]
        if any(p == ".." for p in parts):
            raise WorkspacePathError("'..' is not allowed in paths")
        resolved = self._root.joinpath(*parts).resolve()
        if resolved != self._root and self._root not in resolved.parents:
            raise WorkspacePathError("path resolves outside the workspace")
        return resolved

    def _check_readable(self, requested: str, resolved: Path) -> str:
        rel = self._rel(resolved)
        if is_protected_path(rel) or is_protected_path(requested.strip().strip("/")):
            raise WorkspaceAccessDeniedError(f"'{rel}' is a protected file; its contents are never returned")
        return rel

    def _safe_child(self, entry_path: Path) -> Path | None:
        """Resolved path of a directory entry if it stays inside the root."""
        try:
            resolved = entry_path.resolve()
        except (OSError, RuntimeError):
            return None
        return resolved if (resolved == self._root or self._root in resolved.parents) else None

    # --- listing ---------------------------------------------------------------

    def _walk(self, start: Path, recursive: bool):
        """Yield (resolved_path, is_dir) deterministically, never following
        symlinks out of the root and pruning noise/protected directories."""
        stack = [start]
        while stack:
            current = stack.pop()
            try:
                children = sorted(os.scandir(current), key=lambda e: e.name)
            except OSError:
                continue
            subdirs = []
            for child in children:
                resolved = self._safe_child(Path(child.path))
                if resolved is None:
                    continue  # symlink (or similar) leading outside the root
                is_dir = resolved.is_dir()
                yield resolved, is_dir
                if recursive and is_dir and not child.is_symlink():
                    name = child.name
                    if name not in _PROTECTED_DIRS and name not in _IGNORED_DIRS:
                        subdirs.append(resolved)
            stack.extend(reversed(subdirs))

    def list_files(self, path: str = "", recursive: bool = False) -> WorkspaceListing:
        start = self._resolve(path)
        if not start.is_dir():
            raise WorkspacePathError("path is not a directory")
        entries: list[WorkspaceEntry] = []
        truncated = False
        for resolved, is_dir in self._walk(start, recursive):
            rel = self._rel(resolved)
            name = resolved.name
            if is_dir and (name in _PROTECTED_DIRS or name in _IGNORED_DIRS):
                continue  # listed neither as content nor as hints
            if len(entries) >= self.limits.max_files:
                truncated = True
                break
            if is_dir:
                entries.append(WorkspaceEntry(path=rel, type="dir"))
            else:
                protected = is_protected_path(rel)
                try:
                    size = None if protected else resolved.stat().st_size
                except OSError:
                    continue
                entries.append(WorkspaceEntry(path=rel, type="file", size=size, protected=protected))
        entries.sort(key=lambda e: e.path)
        return WorkspaceListing(path=self._rel(start), entries=entries, truncated=truncated)

    # --- reading -----------------------------------------------------------------

    def _read_checked(self, requested: str) -> tuple[str, bytes, str]:
        resolved = self._resolve(requested)
        if not resolved.exists():
            raise WorkspacePathError("file not found")
        if not resolved.is_file():
            raise WorkspacePathError("path is not a regular file")
        rel = self._check_readable(requested, resolved)
        size = resolved.stat().st_size
        if size > self.limits.max_file_size:
            raise WorkspaceFileTooLargeError(
                f"'{rel}' is {size} bytes, above the {self.limits.max_file_size}-byte limit")
        data = resolved.read_bytes()
        if _looks_binary(data[:8192]):
            raise WorkspaceUnsupportedFileError(f"'{rel}' looks like a binary file; it is not returned as text")
        text = data.decode("utf-8", errors="replace")
        if _has_private_key(text):
            raise WorkspaceAccessDeniedError(f"'{rel}' contains a private key; its contents are never returned")
        return rel, data, text

    def read_file(self, path: str) -> WorkspaceFileContent:
        rel, data, text = self._read_checked(path)
        redacted, count = redact_secrets(text)
        truncated = len(redacted) > self.limits.max_output_chars
        if truncated:
            redacted = redacted[: self.limits.max_output_chars].rstrip()
        logger.info("workspace: op=read path=%s bytes=%d redactions=%d", rel, len(data), count)
        return WorkspaceFileContent(
            path=rel, size=len(data), sha256=hashlib.sha256(data).hexdigest(),
            line_count=text.count("\n") + (1 if text and not text.endswith("\n") else 0),
            content=redacted, truncated=truncated, redactions=count,
        )

    def read_text(self, path: str) -> tuple[str, str]:
        """(full raw text, sha256) under the same protections as read_file —
        for internal consumers such as diff generation. NOT for model output."""
        _, data, text = self._read_checked(path)
        return text, hashlib.sha256(data).hexdigest()

    def exists(self, path: str) -> bool:
        return self._resolve(path).is_file()

    def validate_writable_target(self, path: str, allow_code_files: bool = False) -> str:
        """Confinement + protection checks for a path that does NOT have to
        exist (used when proposing a change). Returns its relative path.
        Nothing is created or written. `allow_code_files=True` lets Python
        source files through the filename-based secret check (e.g. a module
        named secrets.py); protected folders such as .git/.ssh stay blocked."""
        resolved = self._resolve(path)
        if resolved == self._root:
            raise WorkspacePathError("a file path is required")
        if resolved.exists() and resolved.is_dir():
            raise WorkspacePathError("path is a directory")
        rel = self._rel(resolved)
        if allow_code_files and rel.endswith(".py") and not any(p in _PROTECTED_DIRS for p in rel.split("/")):
            return rel
        return self._check_readable(path, resolved)

    # --- search --------------------------------------------------------------------

    def search_files(
        self,
        query: str,
        path: str = "",
        extensions: list[str] | None = None,
        glob: str | None = None,
        max_results: int | None = None,
        case_sensitive: bool = False,
    ) -> WorkspaceSearchResult:
        """Plain-text (not regex) search. Deterministic order; bounded by
        max_files scanned and max_search_results."""
        q = query if isinstance(query, str) else ""
        if not q.strip() or len(q) > MAX_QUERY_LENGTH or "\x00" in q:
            raise WorkspacePathError("search query must be 1-200 characters")
        start = self._resolve(path)
        if not start.is_dir():
            raise WorkspacePathError("search path is not a directory")
        exts = {("." + e.lower().lstrip(".")) for e in (extensions or []) if e.strip()}
        if glob is not None and (len(glob) > 200 or "\x00" in glob or glob.startswith("/") or ".." in glob):
            raise WorkspacePathError("invalid glob pattern")
        limit = self.limits.max_search_results if max_results is None else max(1, min(max_results, self.limits.max_search_results))
        needle = q if case_sensitive else q.lower()
        matches: list[SearchMatch] = []
        scanned = 0
        truncated = False
        for resolved, is_dir in self._walk(start, recursive=True):
            if is_dir:
                continue
            rel = self._rel(resolved)
            if is_protected_path(rel) or any(p in _IGNORED_DIRS or p in _PROTECTED_DIRS for p in rel.split("/")[:-1]):
                continue
            if exts and resolved.suffix.lower() not in exts:
                continue
            if glob and not fnmatch.fnmatchcase(rel, glob):
                continue
            if scanned >= self.limits.max_files:
                truncated = True
                break
            scanned += 1
            try:
                if resolved.stat().st_size > self.limits.max_file_size:
                    continue
                data = resolved.read_bytes()
            except OSError:
                continue
            if _looks_binary(data[:8192]):
                continue
            text = data.decode("utf-8", errors="replace")
            if _has_private_key(text):
                continue
            for number, line in enumerate(text.splitlines(), 1):
                hay = line if case_sensitive else line.lower()
                if needle in hay:
                    shown, _ = redact_secrets(line.strip()[:MAX_LINE_CHARS])
                    matches.append(SearchMatch(path=rel, line_number=number, line=shown))
                    if len(matches) >= limit:
                        truncated = True
                        break
            if len(matches) >= limit:
                break
        logger.info("workspace: op=search scanned=%d matches=%d", scanned, len(matches))
        return WorkspaceSearchResult(query=q, matches=matches, files_scanned=scanned, truncated=truncated)
