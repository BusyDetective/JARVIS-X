from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from app.security.permissions import PermissionLevel


class ApprovalHandler(ABC):
    """Injectable approval mechanism.

    The orchestrator calls this whenever a tool's permission level is
    CONFIRM or DANGEROUS, before executing it. Kept abstract and injected
    (rather than hardcoded as e.g. an `input()` prompt) so:

    - unit tests never require interactive input or real stdin,
    - a future CLI can supply an interactive implementation,
    - a future web UI can supply one backed by a request/response flow,

    without the orchestrator itself changing at all.
    """

    @abstractmethod
    async def approve(
        self, tool_name: str, arguments: dict[str, Any], level: PermissionLevel
    ) -> bool:
        """Return True to allow execution, False to deny it."""
        ...


class AutoApproveHandler(ApprovalHandler):
    """Approves every CONFIRM/DANGEROUS request. Useful for tests and for
    a future explicit non-interactive/--yes mode. Must never be the
    default in a real interactive CLI."""

    async def approve(
        self, tool_name: str, arguments: dict[str, Any], level: PermissionLevel
    ) -> bool:
        return True


class AutoDenyHandler(ApprovalHandler):
    """Denies every CONFIRM/DANGEROUS request. A safe default when no
    interactive handler is configured, and useful for tests that assert
    denial behavior without needing a real approval flow."""

    async def approve(
        self, tool_name: str, arguments: dict[str, Any], level: PermissionLevel
    ) -> bool:
        return False
