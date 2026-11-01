from __future__ import annotations

import json
import os
import shutil
import uuid
from pathlib import Path

from app.versioning.manifest import (
    build_manifest,
    hash_tree,
    iter_snapshot_files,
    parse_version,
)
from app.versioning.models import (
    IntegrityReport,
    PointerState,
    SystemManifest,
    TestBaseline,
    UpdateManifest,
    utcnow,
)


class VersioningError(Exception):
    """Release-store failure. Messages are safe: version ids and fixed text only."""


class ReleaseNotFoundError(VersioningError):
    pass


class ReleaseExistsError(VersioningError):
    pass


def atomic_write_json(path: Path, data: dict) -> None:
    """Write-then-rename so readers (and crash recovery) never see a partial file."""
    tmp = path.with_name(f".{path.name}.{uuid.uuid4().hex[:8]}.tmp")
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2, sort_keys=True, default=str)
        fh.flush()
        os.fsync(fh.fileno())
    os.replace(tmp, path)


class ReleaseStore:
    """Local, filesystem-based release store.

        <root>/releases/<version>/source/...     immutable snapshot of a release
        <root>/releases/<version>/manifest.json  SystemManifest (file hashes)
        <root>/releases/<version>/update.json    UpdateManifest
        <root>/releases/<version>/baseline.json  recorded test baseline (write-once)
        <root>/current.json                      the "current" pointer (atomic swap)
        <root>/promotion.journal.json            present only during a promotion

    A release directory is created by writing to a temporary directory and
    renaming it into place, so a half-written release is never visible under
    its final name. Releases are never modified afterwards and never deleted
    by rollback. Single-process design: no cross-process locking.
    """

    def __init__(self, root: Path | str) -> None:
        self.root = Path(root).resolve()
        self.releases_dir = self.root / "releases"
        self.pointer_path = self.root / "current.json"
        self.journal_path = self.root / "promotion.journal.json"
        self.releases_dir.mkdir(parents=True, exist_ok=True)

    # --- lookups -----------------------------------------------------------

    def _release_dir(self, version: str) -> Path:
        if parse_version(version) is None:
            raise ReleaseNotFoundError("invalid release version identifier")
        return self.releases_dir / version

    def has_release(self, version: str) -> bool:
        return parse_version(version) is not None and (self.releases_dir / version / "manifest.json").is_file()

    def release_source(self, version: str) -> Path:
        d = self._release_dir(version)
        if not (d / "manifest.json").is_file():
            raise ReleaseNotFoundError(f"release {version} not found")
        return d / "source"

    def list_releases(self) -> list[str]:
        versions = [p.name for p in self.releases_dir.iterdir() if p.is_dir() and parse_version(p.name) is not None
                    and (p / "manifest.json").is_file()]
        return sorted(versions, key=lambda v: parse_version(v) or 0)

    def read_manifest(self, version: str) -> SystemManifest:
        manifest = SystemManifest.model_validate_json(
            (self._release_dir(version) / "manifest.json").read_text())
        baseline = self.get_baseline(version)
        return manifest.model_copy(update={"test_baseline": baseline}) if baseline else manifest

    def read_update(self, version: str) -> UpdateManifest:
        return UpdateManifest.model_validate_json((self._release_dir(version) / "update.json").read_text())

    def get_baseline(self, version: str) -> TestBaseline | None:
        path = self._release_dir(version) / "baseline.json"
        return TestBaseline.model_validate_json(path.read_text()) if path.is_file() else None

    def record_baseline(self, version: str, baseline: TestBaseline) -> None:
        """Write-once: a recorded baseline cannot be replaced."""
        path = self._release_dir(version) / "baseline.json"
        if not (self._release_dir(version) / "manifest.json").is_file():
            raise ReleaseNotFoundError(f"release {version} not found")
        if path.exists():
            raise ReleaseExistsError(f"baseline for {version} is already recorded")
        atomic_write_json(path, json.loads(baseline.model_dump_json()))

    # --- pointer -----------------------------------------------------------

    def current(self) -> PointerState | None:
        if not self.pointer_path.is_file():
            return None
        try:
            return PointerState.model_validate_json(self.pointer_path.read_text())
        except ValueError as exc:
            raise VersioningError("current-release pointer is unreadable") from exc

    def current_version(self) -> str | None:
        state = self.current()
        return state.version if state else None

    def write_pointer(self, version: str, history: list[str]) -> PointerState:
        if not self.has_release(version):
            raise ReleaseNotFoundError(f"release {version} not found")
        state = PointerState(version=version, history=list(history), switched_at=utcnow())
        atomic_write_json(self.pointer_path, json.loads(state.model_dump_json()))
        return state

    # --- integrity -----------------------------------------------------------

    def verify_release(self, version: str) -> IntegrityReport:
        """Strict: every file under source/ must match the manifest exactly."""
        try:
            manifest = self.read_manifest(version)
            actual = hash_tree(self.release_source(version), only_snapshot=False)
        except (OSError, ValueError, VersioningError):
            return IntegrityReport(version=version, valid=False, missing=["<release unreadable>"])
        expected = {f.path: f.sha256 for f in manifest.files}
        missing = sorted(set(expected) - set(actual))
        unexpected = sorted(set(actual) - set(expected))
        modified = sorted(p for p in expected.keys() & actual.keys() if expected[p] != actual[p])
        return IntegrityReport(version=version, valid=not (missing or unexpected or modified),
                               missing=missing, modified=modified, unexpected=unexpected)

    def hash_release(self, version: str) -> dict[str, str]:
        return hash_tree(self.release_source(version), only_snapshot=False)

    # --- creation ----------------------------------------------------------------

    def _next_index(self) -> int:
        return max((parse_version(v) or 0 for v in self.list_releases()), default=0) + 1

    def create_release(
        self, source_dir: Path, update: UpdateManifest | None = None, baseline: TestBaseline | None = None,
        project_version: str | None = None,
    ) -> str:
        """Snapshot `source_dir` (snapshot-eligible files only) as a new
        immutable release and return its version id. Atomic via rename."""
        source_dir = source_dir.resolve()
        tmp = self.releases_dir / f".tmp-{uuid.uuid4().hex}"
        (tmp / "source").mkdir(parents=True)
        try:
            for rel, full in iter_snapshot_files(source_dir):
                dest = tmp / "source" / rel
                dest.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(full, dest)
            manifest = build_manifest(tmp / "source", baseline) if project_version is None else build_manifest(
                tmp / "source", baseline, project_version)
            version = f"v{self._next_index():04d}-{manifest.content_hash[:10]}"
            final = self.releases_dir / version
            if final.exists():
                raise ReleaseExistsError(f"release {version} already exists")
            upd = (update or UpdateManifest(version=version)).model_copy(update={"version": version})
            atomic_write_json(tmp / "manifest.json", json.loads(manifest.model_copy(update={"test_baseline": None}).model_dump_json()))
            atomic_write_json(tmp / "update.json", json.loads(upd.model_dump_json()))
            if baseline is not None:
                atomic_write_json(tmp / "baseline.json", json.loads(baseline.model_dump_json()))
            os.replace(tmp, final)
            return version
        except BaseException:
            shutil.rmtree(tmp, ignore_errors=True)
            raise

    def remove_unreferenced_release(self, version: str) -> bool:
        """Delete a release that is neither current nor in the rollback history
        (used only to clean up a failed or interrupted promotion)."""
        state = self.current()
        if state is not None and (version == state.version or version in state.history):
            raise VersioningError("refusing to delete a release that is current or in rollback history")
        d = self._release_dir(version)
        if d.exists():
            shutil.rmtree(d)
            return True
        return False

    def cleanup_temp_dirs(self) -> int:
        removed = 0
        for p in self.releases_dir.glob(".tmp-*"):
            shutil.rmtree(p, ignore_errors=True)
            removed += 1
        return removed

    def bootstrap(self, project_root: Path, baseline: TestBaseline | None = None) -> str:
        """Create the first release (the CURRENT system) from a project tree and
        point at it. Reads the tree; never modifies it. No-op if already set up."""
        existing = self.current_version()
        if existing is not None:
            return existing
        version = self.create_release(project_root, UpdateManifest(version="pending", risk_level="low",
                                                                   validation_status="baseline", approval_status="n/a"), baseline)
        self.write_pointer(version, [])
        return version
