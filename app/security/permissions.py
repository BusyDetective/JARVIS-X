from __future__ import annotations

from enum import Enum


class PermissionLevel(str, Enum):
    """How much oversight a tool's execution requires.

    SAFE       — executes immediately, no approval needed.
    CONFIRM    — requires explicit approval before executing.
    DANGEROUS  — requires explicit approval before executing (same
                 mechanism as CONFIRM; kept as a distinct level so a
                 future policy/UI can treat it with extra weight — e.g.
                 a stronger warning — without changing this module).
    BLOCKED    — never executes, regardless of approval.

    Deliberately NOT a YAML/config-driven policy engine yet — a clean,
    small abstraction here is more valuable right now than configuration
    surface area. Per-tool level currently comes from the Tool
    implementation itself (`Tool.permission_level`).
    """

    SAFE = "safe"
    CONFIRM = "confirm"
    DANGEROUS = "dangerous"
    BLOCKED = "blocked"


def requires_approval(level: PermissionLevel) -> bool:
    """True for any level that must go through the ApprovalHandler before
    executing. SAFE never does; BLOCKED never executes regardless of
    approval, so it isn't "requiring" approval — it's refused outright."""
    return level in (PermissionLevel.CONFIRM, PermissionLevel.DANGEROUS)
