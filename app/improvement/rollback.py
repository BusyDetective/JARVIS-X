from __future__ import annotations

import logging

from app.improvement.models import RollbackResult
from app.versioning.manager import ReleaseStore

logger = logging.getLogger(__name__)


class RollbackManager:
    """Switches "current" back to the previous known-good release.

    It identifies the previous release from the pointer history, verifies its
    integrity (every file hash), and only then swaps the pointer atomically.
    The release being rolled back from is KEPT on disk. Any failure returns a
    typed RollbackResult and leaves the current release untouched."""

    def __init__(self, store: ReleaseStore) -> None:
        self._store = store

    def rollback(self) -> RollbackResult:
        state = self._store.current()
        if state is None:
            return RollbackResult(success=False, error_type="NO_CURRENT", error="there is no current release")
        if not state.history:
            return RollbackResult(success=False, from_version=state.version, error_type="NO_PREVIOUS_RELEASE",
                                  error="there is no earlier release to roll back to")
        previous = state.history[-1]
        if not self._store.has_release(previous):
            return RollbackResult(success=False, from_version=state.version, error_type="INTEGRITY_FAILURE",
                                  error=f"previous release {previous} is missing")
        report = self._store.verify_release(previous)
        if not report.valid:
            return RollbackResult(
                success=False, from_version=state.version, error_type="INTEGRITY_FAILURE",
                error=f"previous release {previous} failed integrity verification "
                      f"({len(report.modified)} modified, {len(report.missing)} missing, {len(report.unexpected)} unexpected files)")
        try:
            self._store.write_pointer(previous, state.history[:-1])
        except Exception as exc:  # noqa: BLE001
            logger.error("rollback switch failed: %s", type(exc).__name__)
            return RollbackResult(success=False, from_version=state.version, error_type="SWITCH_FAILED",
                                  error="could not switch the current-release pointer; current release unchanged")
        logger.info("rollback: %s -> %s", state.version, previous)
        return RollbackResult(success=True, from_version=state.version, restored_version=previous)
