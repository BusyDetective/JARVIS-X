from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field

from app.sandbox.models import SandboxOperation


class SandboxPolicy(BaseModel):
    """Limits and the fixed operation allowlist for isolated validation.

    The limits are applied to the CONTAINER (see app.sandbox.container); there is no
    host-process execution path anywhere. `network` can only be "none"."""

    model_config = {"frozen": True}

    timeout_seconds: float = Field(default=900.0, gt=0, le=7200)
    max_output_bytes: int = Field(default=200_000, ge=1_000, le=10_000_000)
    memory_limit_mb: int = Field(default=2048, ge=128, le=65_536)
    cpus: float = Field(default=2.0, gt=0, le=64)
    max_processes: int = Field(default=256, ge=16, le=65_536)
    max_open_files: int = Field(default=1024, ge=64, le=1_048_576)
    work_tmpfs_mb: int = Field(default=512, ge=16, le=16_384)
    tmp_tmpfs_mb: int = Field(default=64, ge=8, le=4_096)
    network: Literal["none"] = "none"
    allowed_operations: frozenset[SandboxOperation] = frozenset(SandboxOperation)

    @classmethod
    def from_settings(cls) -> "SandboxPolicy":
        from app.config.settings import settings

        return cls(
            timeout_seconds=settings.improvement_validation_timeout,
            max_output_bytes=settings.improvement_validation_max_output_bytes,
            memory_limit_mb=settings.improvement_validation_memory_mb,
            cpus=settings.improvement_validation_cpus,
            max_processes=settings.improvement_validation_pids,
        )

    def limits_summary(self) -> dict[str, object]:
        return {"timeout_seconds": self.timeout_seconds, "memory_mb": self.memory_limit_mb, "cpus": self.cpus,
                "pids": self.max_processes, "open_files": self.max_open_files, "work_tmpfs_mb": self.work_tmpfs_mb,
                "output_bytes": self.max_output_bytes}

    def isolation_report(self, backend_description: str) -> dict[str, str]:
        """What the boundary is, what it is not, and what remains risky. Stated so
        that nothing here is read as a guarantee of perfect isolation."""
        return {
            "backend": backend_description,
            "execution": "candidate code runs ONLY inside a disposable container; there is no host execution "
                         "path and no fallback — if the container backend is unavailable, validation fails and nothing runs",
            "operations": "fixed allowlist (test suite, static analysis); callers supply an enum value, never a command, "
                          "arguments, environment or mounts",
            "filesystem": "source is a read-only bind mount of the candidate snapshot; the container root is read-only; "
                          "the only writable areas are size-limited in-memory tmpfs; no home directory, SSH keys, "
                          "credentials, docker socket or other host path is mounted",
            "network": "disabled at the container boundary (--network none): only loopback exists; verified by a canary "
                       "run before every validation",
            "privileges": "unprivileged user (65534), all Linux capabilities dropped, no-new-privileges, default seccomp profile",
            "environment": "no host environment variable is passed; only a fixed allowlist of constants",
            "limits": f"memory, cpu, process-count and open-file limits plus a {self.timeout_seconds:g}s wall-clock "
                      "timeout enforced by the container runtime/host; output is capped",
            "cleanup": "containers are named, labelled and removed after every run (also on timeout/crash); "
                       "stale ones are removed at preflight",
            "residual_risk": "a container is NOT a perfect boundary: it shares the host kernel, so a kernel or runtime "
                             "vulnerability (container escape) could defeat it; rootless/gVisor/VM backends reduce this. "
                             "Validation results come from the candidate's own execution and hostile code can forge them, "
                             "so they are evidence for a human approver, not proof",
        }
