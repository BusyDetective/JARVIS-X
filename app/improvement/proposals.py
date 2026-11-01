from __future__ import annotations

import difflib
import hashlib
import uuid
from dataclasses import dataclass

from pydantic import BaseModel, Field, ValidationError

from app.improvement.classification import classify_changes
from app.improvement.errors import InvalidProposalError
from app.improvement.models import (
    ChangeFile,
    ChangeOperation,
    ChangeSet,
    ImprovementProposal,
)
from app.versioning.manager import ReleaseStore
from app.versioning.manifest import is_snapshot_path, sha256_file
from app.workspace.errors import WorkspaceError
from app.workspace.manager import WorkspaceLimits, WorkspaceManager

MAX_CONTENT_CHARS = 200_000


class ProposedChange(BaseModel):
    """What a caller (or the model, through a tool) may supply for one file.
    Note what is NOT here: executables, arguments, environment, absolute paths."""

    path: str = Field(min_length=1, max_length=1024)
    operation: ChangeOperation
    new_content: str | None = Field(default=None, max_length=MAX_CONTENT_CHARS)
    original_hash: str | None = Field(default=None, max_length=64)
    reason: str = Field(min_length=1, max_length=500)


@dataclass
class BuiltProposal:
    proposal: ImprovementProposal
    staged: dict[str, bytes]  # content_ref -> proposed bytes (kept out of the database)
    diff_preview: str


def _lines(text: str) -> list[str]:
    out = text.splitlines(keepends=True)
    if out and not out[-1].endswith("\n"):
        out[-1] += "\n\\ No newline at end of file\n"
    return out


def _unified(rel: str, old: str | None, new: str | None) -> tuple[str, int, int]:
    """Unified diff for one file plus (additions, deletions). old/new None = absent."""
    lines = list(difflib.unified_diff(
        _lines(old or ""), _lines(new or ""),
        fromfile="/dev/null" if old is None else f"a/{rel}", tofile="/dev/null" if new is None else f"b/{rel}"))
    adds = sum(1 for ln in lines if ln.startswith("+") and not ln.startswith("+++"))
    dels = sum(1 for ln in lines if ln.startswith("-") and not ln.startswith("---"))
    return "".join(ln if ln.endswith("\n") else ln + "\n" for ln in lines), adds, dels


class ProposalBuilder:
    """Turns proposed changes into a ChangeSet against the CURRENT release.
    Reads the release only; validates paths (confinement, protected folders,
    snapshot-eligible), hashes (stale proposals are rejected) and content;
    classifies risk. Nothing is written anywhere. Path confinement reuses the
    Phase 7 WorkspaceManager (read-only view of the release)."""

    def __init__(self, store: ReleaseStore, max_diff_chars: int | None = None) -> None:
        self._store = store
        self._max_diff_chars = max_diff_chars

    def build(self, improvement_id: uuid.UUID, base_version: str, title: str, rationale: str,
              changes: list[ProposedChange]) -> BuiltProposal:
        if not changes:
            raise InvalidProposalError("no changes were provided")
        if len(changes) > 50:
            raise InvalidProposalError("too many files in one proposal (max 50)")
        source = self._store.release_source(base_version)
        ws = WorkspaceManager(source, WorkspaceLimits(max_file_size=MAX_CONTENT_CHARS))
        files: list[ChangeFile] = []
        staged: dict[str, bytes] = {}
        diffs: list[str] = []
        adds = dels = 0
        seen: set[str] = set()
        for i, ch in enumerate(changes):
            try:
                rel = ws.validate_writable_target(ch.path, allow_code_files=True)
            except WorkspaceError as exc:
                raise InvalidProposalError(f"invalid path: {exc}") from None
            if not is_snapshot_path(rel):
                raise InvalidProposalError(f"'{rel}' is outside the managed source tree")
            if rel in seen:
                raise InvalidProposalError(f"'{rel}' appears more than once in the proposal")
            seen.add(rel)
            target = source / rel
            exists = target.is_file()
            old_text: str | None = None
            if ch.operation == ChangeOperation.ADD:
                if exists:
                    raise InvalidProposalError(f"'{rel}' already exists; use modify")
                original_hash = None
            else:
                if not exists:
                    raise InvalidProposalError(f"'{rel}' does not exist in release {base_version}")
                original_hash = sha256_file(target)
                if ch.original_hash is None:
                    raise InvalidProposalError(f"original_hash is required to {ch.operation.value} '{rel}'")
                if ch.original_hash != original_hash:
                    raise InvalidProposalError(f"'{rel}' changed since the proposal was based on it (stale hash)")
                try:
                    old_text = target.read_text(encoding="utf-8")
                except (UnicodeDecodeError, OSError):
                    old_text = None
                    if ch.operation == ChangeOperation.MODIFY:
                        raise InvalidProposalError(f"'{rel}' is not a text file and cannot be modified") from None
            if ch.operation == ChangeOperation.DELETE:
                if ch.new_content is not None:
                    raise InvalidProposalError("a delete must not carry content")
                files.append(ChangeFile(path=rel, operation=ch.operation, original_hash=original_hash, reason=ch.reason))
                if old_text is None:
                    diffs.append(f"--- a/{rel}\n+++ /dev/null\n(binary or unreadable file deleted)\n")
                else:
                    d, a, r = _unified(rel, old_text, None)
                    diffs.append(d)
                    dels += r
                continue
            if ch.new_content is None:
                raise InvalidProposalError(f"new_content is required to {ch.operation.value} '{rel}'")
            if "\x00" in ch.new_content:
                raise InvalidProposalError(f"invalid change: new content for '{rel}' looks binary")
            data = ch.new_content.encode("utf-8")
            if len(data) > MAX_CONTENT_CHARS:
                raise InvalidProposalError(f"invalid change: new content for '{rel}' is too large")
            ref = f"{i:03d}.bin"
            staged[ref] = data
            files.append(ChangeFile(path=rel, operation=ch.operation, original_hash=original_hash,
                                    proposed_hash=hashlib.sha256(data).hexdigest(), content_ref=ref, reason=ch.reason))
            if old_text == ch.new_content:
                continue  # unchanged file: nothing to show
            d, a, r = _unified(rel, old_text if ch.operation == ChangeOperation.MODIFY else None, ch.new_content)
            diffs.append(d)
            adds += a
            dels += r

        diff_text = "".join(diffs)
        if self._max_diff_chars and len(diff_text) > self._max_diff_chars:
            diff_text = diff_text[: self._max_diff_chars].rstrip() + "\n… (diff truncated)\n"
        try:
            change_set = ChangeSet(files=files)
            assessment = classify_changes([(f.path, f.operation) for f in files])
            proposal = ImprovementProposal(
                improvement_id=improvement_id, title=title, rationale=rationale, base_version=base_version,
                change_set=change_set, risk_level=assessment.risk, risk_reasons=assessment.reasons,
                mode=assessment.mode, requires_approval=True, flags=sorted(assessment.flags),
                diff_summary=f"{len(files)} file(s) (+{adds} -{dels})")
        except ValidationError as exc:
            raise InvalidProposalError("invalid proposal: " + "; ".join(str(e["msg"]) for e in exc.errors())[:200]) from None
        return BuiltProposal(proposal=proposal, staged=staged, diff_preview=diff_text)
