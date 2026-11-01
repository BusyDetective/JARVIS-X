from __future__ import annotations

from abc import ABC, abstractmethod

from app.sandbox.models import ExecutionResult, IsolationAttestation, SandboxOperation, SandboxPaths


class IsolationBackend(ABC):
    """Executes ONE fixed validation operation against a read-only candidate
    snapshot inside a real isolation boundary.

    Contract: if the boundary cannot be established and verified, raise
    `IsolationUnavailableError` and execute NOTHING. Implementations must never
    fall back to running candidate code in the host process/user context."""

    name: str

    @abstractmethod
    def describe(self) -> str:
        """Short, side-effect-free description (no probing) for status output."""

    @abstractmethod
    async def preflight(self) -> IsolationAttestation:
        """Verify the backend and its restrictions now; raise IsolationUnavailableError otherwise."""

    @abstractmethod
    async def run(self, paths: SandboxPaths, operation: SandboxOperation) -> ExecutionResult:
        """Run `operation` isolated. The result carries the attestation it ran under."""
