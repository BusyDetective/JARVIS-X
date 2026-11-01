from __future__ import annotations

from pathlib import Path

from app.config.settings import settings


class WorkspaceViolationError(Exception):
    """Raised when a requested path resolves outside the configured
    workspace root — including via `..` traversal or symlink tricks."""


def get_workspace_root() -> Path:
    """Returns the workspace root, creating it if needed.

    Configurable via WORKSPACE_ROOT in settings/.env. Relative paths are
    resolved against the process's current working directory; set an
    absolute path in .env to pin it explicitly regardless of where
    JARVIS-X is launched from.
    """
    root = settings.workspace_root.resolve()
    root.mkdir(parents=True, exist_ok=True)
    return root


def resolve_in_workspace(relative_path: str) -> Path:
    """Resolve a (possibly untrusted) relative path and guarantee the
    result stays inside the workspace root.

    Every future filesystem/coding tool must route paths through this
    function before touching disk. Raises WorkspaceViolationError on any
    attempt to escape the workspace (e.g. `../../etc/passwd`, an absolute
    path outside the root, or a symlink that resolves outside it).
    """
    root = get_workspace_root()
    candidate = (root / relative_path).resolve()
    try:
        candidate.relative_to(root)
    except ValueError as exc:
        raise WorkspaceViolationError(
            f"Path '{relative_path}' resolves outside workspace root '{root}'"
        ) from exc
    return candidate
