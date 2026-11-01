from __future__ import annotations

from enum import Enum


class SandboxError(Exception):
    """Base for sandbox errors (safe messages: relative paths and fixed text only)."""


class SandboxPathError(SandboxError):
    pass


class SandboxPolicyViolation(SandboxError):
    pass


class SandboxChangeError(SandboxError):
    """A proposed change could not be applied to the candidate (stale hash, bad path...)."""


class IsolationFailure(str, Enum):
    NO_BACKEND_CONFIGURED = "no_backend_configured"
    NO_CONTAINER_RUNTIME = "no_container_runtime"
    RUNTIME_NOT_USABLE = "runtime_not_usable"
    IMAGE_NOT_FOUND = "image_not_found"
    MISCONFIGURED = "misconfigured"
    RESTRICTIONS_NOT_ESTABLISHED = "restrictions_not_established"
    STARTUP_FAILED = "startup_failed"


class IsolationUnavailableError(SandboxError):
    """The isolated validation environment cannot be provided, so NOTHING was
    executed. There is deliberately no fallback to running candidate code on the
    host. `reason` is a stable code; the message is safe to show to a model."""

    def __init__(self, reason: IsolationFailure, message: str) -> None:
        super().__init__(message)
        self.reason = reason
