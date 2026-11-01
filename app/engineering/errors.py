from __future__ import annotations


class EngineeringError(Exception):
    """Base for engineering errors (safe messages: relative paths and fixed text only)."""


class InvalidPatchError(EngineeringError):
    pass
