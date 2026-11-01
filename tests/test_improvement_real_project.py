"""End-to-end check against the REAL project inside a REAL container (slow: runs the whole test suite twice in the
isolated validation container). Skipped by default; run with JARVIS_RUN_SLOW=1 pytest tests/test_improvement_real_project.py.
Skipped (never passed) when no container runtime/image is available, and always skipped inside the validation container."""
from __future__ import annotations

import hashlib
import os
from pathlib import Path

import pytest

import app
from app.improvement.models import ImprovementState as S
from app.improvement.models import ChangeOperation as Op
from app.improvement.models import ValidationStatus
from app.improvement.proposals import ProposedChange
from app.versioning.manifest import iter_snapshot_files
from tests.improvement_helpers import make_manager

PROJECT_ROOT = Path(app.__file__).resolve().parent.parent
pytestmark = pytest.mark.skipif(
    os.environ.get("JARVIS_RUN_SLOW") != "1" or bool(os.environ.get("JARVIS_VALIDATION_SANDBOX")),
    reason="slow end-to-end test; set JARVIS_RUN_SLOW=1 (never runs inside the sandbox)")


async def test_documentation_change_validates_against_the_real_project(tmp_path, container_backend):
    live_before = {rel: hashlib.sha256(p.read_bytes()).hexdigest() for rel, p in iter_snapshot_files(PROJECT_ROOT)}
    from tests.test_container_real import backend_like
    manager, _ = make_manager(tmp_path, project=PROJECT_ROOT, backend=backend_like(container_backend, timeout_seconds=900, memory_limit_mb=3072, cpus=4, max_processes=512))
    version = manager.store.current_version()
    readme = (manager.store.release_source(version) / "README.md").read_text()
    run = manager.submit_request("Improve the README documentation")
    manager.evaluate(run.id, ["README.md"])
    manager.create_plan(run.id)
    built = manager.propose(run.id, "Document the improvement engine", "docs", [ProposedChange(
        path="README.md", operation=Op.MODIFY, new_content=readme + "\n<!-- validated candidate -->\n",
        original_hash=hashlib.sha256(readme.encode()).hexdigest(), reason="docs")])
    assert built.proposal.risk_level.value == "low" and built.proposal.mode.value == "safe_automatic"
    manager.create_sandbox(run.id)
    summary = await manager.validate(run.id)
    assert summary.status is ValidationStatus.PASSED, summary.reasons
    assert summary.baseline.passed > 800 and summary.test_count_delta == 0 and summary.static_analysis_passed is True
    assert summary.isolation.satisfies_requirements() and summary.isolation.network == "none"
    assert manager.get_run(run.id).state is S.VALIDATED
    live_after = {rel: hashlib.sha256(p.read_bytes()).hexdigest() for rel, p in iter_snapshot_files(PROJECT_ROOT)}
    assert live_after == live_before
