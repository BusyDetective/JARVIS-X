from __future__ import annotations

import hashlib
import logging
import re
import shutil
from pathlib import Path
from typing import Sequence

from app.sandbox.errors import (
    IsolationFailure,
    IsolationUnavailableError,
    SandboxChangeError,
    SandboxError,
    SandboxPathError,
    SandboxPolicyViolation,
)
from app.sandbox.isolation import IsolationBackend
from app.sandbox.models import ChangeOperation, ExecutionResult, IsolationAttestation, SandboxChange, SandboxOperation, SandboxPaths
from app.sandbox.policy import SandboxPolicy
from app.versioning.manifest import iter_snapshot_files, is_snapshot_path, sha256_file
from app.workspace.manager import WorkspaceManager

logger = logging.getLogger(__name__)
_ID_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{5,63}$")
_ENCODED = re.compile(r"%(?:2e|2f|5c|00)", re.IGNORECASE)


class SandboxManager:
    """Builds candidate trees under <root>/candidates/<id>/ and runs the allowlisted
    validation operations — ONLY through an isolation backend.

        candidates/<id>/source/     snapshot of the CURRENT release + proposed changes
                                    (mounted READ-ONLY into the validation container)

    All JARVIS-side file operations are resolved and confined to the sandbox. Candidate
    code is never executed by this class: `run()` hands the fixed operation to the
    configured IsolationBackend, and with no backend (or one that cannot establish its
    restrictions) it raises IsolationUnavailableError. There is no host-execution fallback.
    """

    def __init__(self, root: Path | str, policy: SandboxPolicy | None = None, backend: IsolationBackend | None = None) -> None:
        self.root = Path(root).resolve()
        self.policy = policy or SandboxPolicy()
        self.backend = backend
        self.candidates_dir = self.root / "candidates"
        self.candidates_dir.mkdir(parents=True, exist_ok=True)

    # --- lifecycle -----------------------------------------------------------

    def _dir(self, sandbox_id: str) -> Path:
        if not isinstance(sandbox_id, str) or not _ID_RE.match(sandbox_id):
            raise SandboxPathError("invalid sandbox id")
        return self.candidates_dir / sandbox_id

    def paths(self, sandbox_id: str) -> SandboxPaths:
        d = self._dir(sandbox_id)
        if not (d / "source").is_dir():
            raise SandboxPathError("sandbox does not exist")
        return SandboxPaths(id=sandbox_id, root=d, source=d / "source")

    def exists(self, sandbox_id: str) -> bool:
        return (self._dir(sandbox_id) / "source").is_dir()

    def create(self, sandbox_id: str, snapshot_source: Path) -> SandboxPaths:
        """Copy a snapshot (a release's source/) into a fresh sandbox. Protected
        and non-snapshot files (secrets, .env, .git, data/, logs/...) are never copied."""
        d = self._dir(sandbox_id)
        if d.exists():
            raise SandboxError("sandbox already exists")
        (d / "source").mkdir(parents=True)
        try:
            for rel, full in iter_snapshot_files(snapshot_source):
                dest = d / "source" / rel
                dest.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(full, dest)
        except BaseException:
            shutil.rmtree(d, ignore_errors=True)
            raise
        return self.paths(sandbox_id)

    def destroy(self, sandbox_id: str) -> None:
        d = self._dir(sandbox_id)
        if d.exists():
            shutil.rmtree(d)

    # --- confined access -----------------------------------------------------------

    def resolve(self, sandbox_id: str, rel: str) -> Path:
        """Resolve a relative path inside the candidate source; never outside."""
        source = self.paths(sandbox_id).source.resolve()
        if not isinstance(rel, str) or not rel.strip() or len(rel) > 1024:
            raise SandboxPathError("invalid path")
        if (rel.startswith(("/", "~")) or "\\" in rel or re.match(r"^[A-Za-z]:", rel) or _ENCODED.search(rel)
                or any(ord(c) < 0x20 or ord(c) == 0x7F for c in rel)):
            raise SandboxPathError("path is not a safe relative path")
        parts = [p for p in rel.split("/") if p not in ("", ".")]
        if not parts or any(p == ".." for p in parts):
            raise SandboxPathError("path is not a safe relative path")
        resolved = source.joinpath(*parts).resolve()
        if source not in resolved.parents:
            raise SandboxPathError("path resolves outside the sandbox")
        return resolved

    def workspace(self, sandbox_id: str) -> WorkspaceManager:
        """Read-only Phase 7 view of the candidate source."""
        return WorkspaceManager(self.paths(sandbox_id).source)

    def source_hashes(self, sandbox_id: str) -> dict[str, str]:
        return {rel: sha256_file(full) for rel, full in iter_snapshot_files(self.paths(sandbox_id).source)}

    def apply_changes(self, sandbox_id: str, changes: Sequence[SandboxChange]) -> list[str]:
        """Apply a change set to the CANDIDATE source only. Verifies, for every
        file, that the sandbox still matches the hash the proposal was based on
        (stale proposals are rejected) and that written content matches the
        proposed hash. All checks run before the first write."""
        plan: list[tuple[SandboxChange, Path]] = []
        seen: set[str] = set()
        for change in changes:
            if not is_snapshot_path(change.path):
                raise SandboxChangeError(f"'{change.path}' is not a changeable path")
            target = self.resolve(sandbox_id, change.path)
            rel = target.relative_to(self.paths(sandbox_id).source.resolve()).as_posix()
            if rel in seen:
                raise SandboxChangeError(f"'{rel}' appears more than once")
            seen.add(rel)
            exists = target.is_file()
            if change.operation == ChangeOperation.ADD:
                if exists or target.exists():
                    raise SandboxChangeError(f"'{rel}' already exists")
                if change.content is None or change.proposed_hash is None:
                    raise SandboxChangeError(f"content is required to add '{rel}'")
            else:
                if not exists:
                    raise SandboxChangeError(f"'{rel}' does not exist")
                if change.original_hash is None or sha256_file(target) != change.original_hash:
                    raise SandboxChangeError(f"'{rel}' no longer matches the version the proposal was based on")
                if change.operation == ChangeOperation.MODIFY and (change.content is None or change.proposed_hash is None):
                    raise SandboxChangeError(f"content is required to modify '{rel}'")
            if change.content is not None:
                if hashlib.sha256(change.content).hexdigest() != change.proposed_hash:
                    raise SandboxChangeError(f"content for '{rel}' does not match its proposed hash")
            plan.append((change, target))
        for change, target in plan:
            if change.operation == ChangeOperation.DELETE:
                target.unlink()
            else:
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(change.content or b"")
        return sorted(seen)

    # --- execution (isolated only) ---------------------------------------------------------------------

    async def ensure_isolation(self) -> IsolationAttestation:
        """Verify the isolation backend NOW. Raises IsolationUnavailableError (executing nothing)
        when there is no backend or it cannot establish its restrictions."""
        if self.backend is None:
            raise IsolationUnavailableError(
                IsolationFailure.NO_BACKEND_CONFIGURED,
                "no isolation backend is configured; validation is disabled and nothing was executed")
        return await self.backend.preflight()

    async def run(self, sandbox_id: str, operation: SandboxOperation) -> ExecutionResult:
        """Run one fixed operation against the candidate, isolated. The caller supplies an enum
        value only. Fails closed: no backend or failed verification -> IsolationUnavailableError."""
        if not isinstance(operation, SandboxOperation) or operation not in self.policy.allowed_operations:
            raise SandboxPolicyViolation("this operation is not allowed in the sandbox")
        paths = self.paths(sandbox_id)
        if self.backend is None:
            raise IsolationUnavailableError(
                IsolationFailure.NO_BACKEND_CONFIGURED,
                "no isolation backend is configured; validation is disabled and nothing was executed")
        return await self.backend.run(paths, operation)

    def isolation_report(self) -> dict[str, str]:
        desc = self.backend.describe() if self.backend is not None else "NONE configured: validation is disabled (fails closed)"
        return self.policy.isolation_report(desc)
