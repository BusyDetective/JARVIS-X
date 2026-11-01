from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

# Isolation backends this code base trusts to actually isolate. A validation is only
# promotable if it ran under one of these (a test may patch this set; production never does).
TRUSTED_BACKENDS = frozenset({"docker", "podman"})


class ChangeOperation(str, Enum):
    ADD = "add"
    MODIFY = "modify"
    DELETE = "delete"


class SandboxOperation(str, Enum):
    """The ONLY things the sandbox can execute. There is no operation that
    takes a command, executable, arguments or environment from a caller."""

    RUN_TEST_SUITE = "run_test_suite"
    RUN_STATIC_ANALYSIS = "run_static_analysis"


class SandboxPaths(BaseModel):
    id: str
    root: Path
    source: Path


class SandboxChange(BaseModel):
    path: str
    operation: ChangeOperation
    original_hash: str | None = None
    proposed_hash: str | None = None
    content: bytes | None = None


class IsolationAttestation(BaseModel):
    """Evidence of the restrictions that were actually ESTABLISHED (verified by a canary
    run inside a container with the same flags) before candidate code ran. It is evidence
    about the container boundary only; see SandboxPolicy.isolation_report() for residual risks."""

    backend: str
    cli_version: str | None = None
    image: str
    image_id: str
    network: str  # "none" = no network interface other than loopback
    user: str  # "uid:gid" the code ran as
    read_only_rootfs: bool
    capabilities_dropped: bool
    no_new_privileges: bool
    host_mounts: list[str]  # e.g. ["snapshot:ro"]
    writable_host_mounts: int
    limits: dict[str, Any] = Field(default_factory=dict)
    canary_passed: bool
    verified_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    def satisfies_requirements(self) -> bool:
        uid = self.user.split(":")[0]
        return bool(
            self.backend in TRUSTED_BACKENDS and self.canary_passed and self.network == "none"
            and uid.isdigit() and int(uid) != 0 and self.read_only_rootfs and self.capabilities_dropped
            and self.no_new_privileges and self.host_mounts == ["snapshot:ro"] and self.writable_host_mounts == 0)


class ExecutionResult(BaseModel):
    operation: SandboxOperation
    exit_code: int | None
    timed_out: bool = False
    duration_seconds: float
    stdout: str = ""
    stderr: str = ""
    output_truncated: bool = False
    killed_for_output: bool = False
    resource_limit_exit: bool = False  # exit code 137 without a timeout: killed (OOM / limit)
    reported: dict[str, Any] | None = None  # result line printed by the in-container runner
    isolation: IsolationAttestation | None = None
    limits_applied: dict[str, Any] = Field(default_factory=dict)
