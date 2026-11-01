from __future__ import annotations

import difflib
from typing import Sequence

from app.config.settings import settings
from app.engineering.errors import InvalidPatchError
from app.engineering.models import Diff, DiffFile, FileChange
from app.workspace.errors import WorkspaceError
from app.workspace.manager import WorkspaceManager

MAX_FILES_PER_DIFF = 50


def _lines(text: str) -> list[str]:
    out = text.splitlines(keepends=True)
    if out and not out[-1].endswith("\n"):
        out[-1] += "\n\\ No newline at end of file\n"
    return out


class DiffGenerator:
    """Turns proposed FileChanges into a unified diff. READ-ONLY: the
    workspace is only read (to compute the original text and hash); this class
    has no way to write, and the resulting Diff always has applied=False."""

    def __init__(self, workspace: WorkspaceManager, max_diff_chars: int | None = None) -> None:
        self._ws = workspace
        self.max_diff_chars = max_diff_chars if max_diff_chars is not None else settings.engineering_max_diff_chars

    def generate(self, changes: Sequence[FileChange]) -> Diff:
        if not changes:
            raise InvalidPatchError("no changes were provided")
        if len(changes) > MAX_FILES_PER_DIFF:
            raise InvalidPatchError(f"too many files in one proposal (max {MAX_FILES_PER_DIFF})")
        seen: set[str] = set()
        files: list[DiffFile] = []
        chunks: list[str] = []
        for change in changes:
            try:
                rel = self._ws.validate_writable_target(change.path)
            except WorkspaceError as exc:
                raise InvalidPatchError(f"invalid path in proposal: {exc}") from None
            if rel in seen:
                raise InvalidPatchError(f"'{rel}' appears more than once in the proposal")
            seen.add(rel)
            if "\x00" in change.new_content:
                raise InvalidPatchError(f"new content for '{rel}' looks binary")
            if len(change.new_content.encode("utf-8", "replace")) > self._ws.limits.max_file_size:
                raise InvalidPatchError(f"new content for '{rel}' exceeds the {self._ws.limits.max_file_size}-byte limit")
            original, status = self._original(rel, change)
            if original == change.new_content:
                files.append(DiffFile(path=rel, status="unchanged"))
                continue
            diff_lines = list(difflib.unified_diff(
                _lines(original), _lines(change.new_content),
                fromfile="/dev/null" if status == "added" else f"a/{rel}", tofile=f"b/{rel}",
            ))
            adds = sum(1 for ln in diff_lines if ln.startswith("+") and not ln.startswith("+++"))
            dels = sum(1 for ln in diff_lines if ln.startswith("-") and not ln.startswith("---"))
            files.append(DiffFile(path=rel, status=status, additions=adds, deletions=dels))
            chunks.append("".join(ln if ln.endswith("\n") else ln + "\n" for ln in diff_lines))
        unified = "".join(chunks)
        truncated = len(unified) > self.max_diff_chars
        if truncated:
            unified = unified[: self.max_diff_chars].rstrip() + "\n… (diff truncated)\n"
        changed = [f for f in files if f.status != "unchanged"]
        summary = (f"{len(changed)} file(s) changed (+{sum(f.additions for f in changed)} "
                   f"-{sum(f.deletions for f in changed)}): "
                   f"{sum(f.status == 'added' for f in changed)} added, "
                   f"{sum(f.status == 'modified' for f in changed)} modified; "
                   f"{len(files) - len(changed)} unchanged. Proposal only — nothing was written.")
        return Diff(files=files, unified_diff=unified, summary=summary, truncated=truncated)

    def _original(self, rel: str, change: FileChange) -> tuple[str, str]:
        if self._ws.exists(rel):
            try:
                text, actual = self._ws.read_text(rel)
            except WorkspaceError as exc:
                raise InvalidPatchError(f"cannot base a change on '{rel}': {exc}") from None
            if change.original_hash is None:
                raise InvalidPatchError(f"'{rel}' already exists; original_hash is required to modify it")
            if change.original_hash != actual:
                raise InvalidPatchError(f"'{rel}' has changed since the proposal was based on it (hash mismatch)")
            return text, "modified"
        if change.original_hash is not None:
            raise InvalidPatchError(f"'{rel}' does not exist but an original_hash was given")
        return "", "added"
