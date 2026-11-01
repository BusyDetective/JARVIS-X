"""Shared fixtures for the Phase 8 tests. A tiny real project is used so the
sandbox really runs pytest and pyflakes in a subprocess."""
from __future__ import annotations

import asyncio
import hashlib
import os
import shutil
import signal
import site
import sys
import tempfile
import uuid
from pathlib import Path

from app.improvement.manager import ImprovementManager
from app.improvement.models import (
    TestCounts,
    ValidationResult,
    ValidationStatus,
    ValidationSummary,
)
from app.improvement.repository import ImprovementRepository
from app.sandbox.container import ENTRY_SCRIPT, _parse_marker
from app.sandbox.isolation import IsolationBackend
from app.sandbox.manager import SandboxManager
from app.sandbox.models import ExecutionResult, IsolationAttestation, SandboxOperation, SandboxPaths
from app.sandbox.policy import SandboxPolicy
from app.security.approval import ApprovalHandler
from app.versioning.manager import ReleaseStore
from app.versioning.manifest import tree_digest
from app.versioning.models import TestBaseline

PROJECT_FILES = {
    "app/__init__.py": "",
    "app/util.py": "def add(a, b):\n    return a + b\n",
    "app/security/__init__.py": "",
    "app/security/approval.py": "def approve():\n    return False\n",
    "tests/__init__.py": "",
    "tests/test_util.py": "from app.util import add\n\n\ndef test_add():\n    assert add(1, 2) == 3\n\n\ndef test_add_zero():\n    assert add(0, 0) == 0\n",
    "README.md": "# Demo project\n",
    "docs/guide.md": "guide\n",
    "requirements.txt": "httpx>=0.27\n",
    "requirements-dev.txt": "-r requirements.txt\npytest>=8\n",
}


UTIL_ORIGINAL = PROJECT_FILES["app/util.py"]


def sha(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def make_project(root: Path, extra: dict[str, str] | None = None) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    for rel, content in {**PROJECT_FILES, **(extra or {})}.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)
    return root


def make_policy(**kw) -> SandboxPolicy:
    return SandboxPolicy(**{"timeout_seconds": 60, "memory_limit_mb": 1024, **kw})


def fake_attestation(**over) -> IsolationAttestation:
    """A MOCK attestation that satisfies the requirements. It is data only: it proves nothing
    about any real isolation and is used to test the policy/gate logic."""
    fields = dict(backend="podman", cli_version="mock", image="MOCK-IMAGE", image_id="f" * 64, network="none", user="65534:65534",
                  read_only_rootfs=True, capabilities_dropped=True, no_new_privileges=True, host_mounts=["snapshot:ro"],
                  writable_host_mounts=0, canary_passed=True)
    fields.update(over)
    return IsolationAttestation(**fields)


class HostTestBackend(IsolationBackend):
    """UNSAFE TEST DOUBLE — NOT ISOLATED. Runs the project's real in-container entry script as an
    ordinary host subprocess so validation LOGIC can be tested with real pytest/pyflakes runs. It is
    never used by production code (production wires ContainerBackend only) and its attestation is only
    accepted when a test opts in with the `trust_test_backend` fixture."""

    name = "test-double"

    def __init__(self, policy: SandboxPolicy | None = None, before_run=None):
        self.policy = policy or SandboxPolicy(timeout_seconds=60)
        self.before_run = before_run  # optional hook(paths, operation), e.g. to mutate the tree
        self.runs: list[str] = []

    def describe(self) -> str:
        return "UNSAFE host test double (not isolated)"

    def attestation(self) -> IsolationAttestation:
        return fake_attestation(backend="test-double", image="TEST-DOUBLE-NOT-ISOLATED")

    async def preflight(self) -> IsolationAttestation:
        return self.attestation()

    async def run(self, paths: SandboxPaths, operation: SandboxOperation) -> ExecutionResult:
        self.runs.append(operation.value)
        if self.before_run:
            self.before_run(paths, operation)
        work = tempfile.mkdtemp(prefix="hostdouble-")
        env = {"PATH": os.defpath, "HOME": work, "LANG": "C.UTF-8", "PYTHONDONTWRITEBYTECODE": "1", "PYTHONHASHSEED": "0",
               "JARVIS_VALIDATION_SANDBOX": "1", "PYTHONUSERBASE": site.getuserbase(), "JARVISX_OPERATION": operation.value,
               "JARVISX_SNAPSHOT": str(paths.source), "JARVISX_WORK": work}
        proc = await asyncio.create_subprocess_exec(sys.executable, "-c", ENTRY_SCRIPT, env=env, stdin=asyncio.subprocess.DEVNULL,
                                                    stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE, start_new_session=True)
        timed_out = False
        try:
            out, err = await asyncio.wait_for(proc.communicate(), timeout=self.policy.timeout_seconds)
        except asyncio.TimeoutError:
            timed_out = True
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            await proc.wait()
            out = err = b""
        finally:
            shutil.rmtree(work, ignore_errors=True)
        text = out.decode("utf-8", "replace")
        reported = _parse_marker(text)
        return ExecutionResult(operation=operation, exit_code=None if timed_out else proc.returncode, timed_out=timed_out,
                               duration_seconds=0.0, stdout=text.split("\n@@JARVISX@@ ")[0] if reported else text,
                               stderr=err.decode("utf-8", "replace"), reported=reported, isolation=self.attestation())


class FakeValidator:
    """Stands in for ValidationRunner in lifecycle tests that don't need a subprocess. Its summaries carry a
    MOCK isolation attestation (see fake_attestation) — gate logic only, not real isolation."""

    def __init__(self, store: ReleaseStore, passed: bool = True, baseline: int = 2, candidate: int = 2, suspicious=None,
                 isolated: bool = True, preflight_error=None, run_error=None):
        self.store, self.passed, self.baseline, self.candidate = store, passed, baseline, candidate
        self.suspicious = suspicious or []
        self.isolated, self.preflight_error, self.run_error = isolated, preflight_error, run_error
        self.calls = 0
        self.preflights = 0
        self.sandbox = None

    def bind(self, sandbox):
        self.sandbox = sandbox

    async def preflight(self):
        self.preflights += 1
        if self.preflight_error:
            raise self.preflight_error
        return fake_attestation()

    async def ensure_baseline(self, version):
        existing = self.store.get_baseline(version)
        if existing is None:
            existing = TestBaseline(passed=self.baseline)
            self.store.record_baseline(version, existing)
        return existing

    async def validate(self, candidate_id: uuid.UUID, sandbox_id, base_version, change_set) -> ValidationSummary:
        self.calls += 1
        if self.run_error:
            raise self.run_error
        base = await self.ensure_baseline(base_version)
        ok = self.passed
        digest = tree_digest(self.sandbox.paths(sandbox_id).source) if self.sandbox else None
        return ValidationSummary(
            candidate_id=candidate_id, status=ValidationStatus.PASSED if ok else ValidationStatus.FAILED,
            baseline=TestCounts(passed=base.passed), candidate=TestCounts(passed=self.candidate if ok else 0, failed=0 if ok else 1),
            test_count_delta=self.candidate - base.passed, suspicious=self.suspicious,
            reasons=[] if ok else ["test suite failed"], isolation=fake_attestation() if self.isolated else None, candidate_digest=digest,
            results=[ValidationResult(operation="run_test_suite", passed=ok)], static_analysis_passed=True)


class Approver(ApprovalHandler):
    def __init__(self, answer: bool = True):
        self.answer, self.requests = answer, []

    async def approve(self, tool_name, arguments, level) -> bool:
        self.requests.append((tool_name, arguments, level))
        return self.answer


def make_manager(tmp_path: Path, validator=None, web=None, project: Path | None = None, backend="host-test", **sandbox_kw):
    """backend="host-test" uses the UNSAFE test double (logic tests; pair with the trust_test_backend fixture)."""
    project = project or make_project(tmp_path / "project")
    root = tmp_path / "improvement"
    store = ReleaseStore(root)
    policy = make_policy(**sandbox_kw)
    sandbox = SandboxManager(root, policy, HostTestBackend(policy) if backend == "host-test" else backend)
    instance = validator(store) if callable(validator) else validator
    manager = ImprovementManager(ImprovementRepository(tmp_path / "t.db"), store, sandbox, web, validator=instance)
    if instance is not None and hasattr(instance, "bind"):
        instance.bind(sandbox)
    manager.ensure_current_release(project)
    return manager, project


def tree_hashes(root: Path) -> dict[str, str]:
    return {str(p.relative_to(root)): hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(root.rglob("*")) if p.is_file()}
