"""Backward-compatibility / regression tests for the VENDORED recon
engine itself (vendor/ai_bug_bounty_recon/) — proving the Phase 10
integration did not change its existing behavior, and that the two
pre-existing bugs fixed during integration (a broken main.py import, and
a broken path in the project's own test runner) stay fixed.

These run the vendored project's OWN standalone test suite and CLI
entry point as subprocesses, from its own directory, exactly as someone
using it independently of JARVIS-X would. No network access is used —
tests/test_pipeline.py mocks its own HTTP layer (see that file).
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

_ENGINE_DIR = Path(__file__).resolve().parents[1] / "vendor" / "ai_bug_bounty_recon"

pytestmark = pytest.mark.skipif(
    not _ENGINE_DIR.is_dir(), reason="vendored recon engine not present in this checkout"
)


def test_vendored_engine_own_test_suite_still_passes():
    """The project's own tests/test_pipeline.py — 175 tests as of the
    Phase 10 integration, covering recon_core/vuln_engine/alive_check/etc.
    directly. This is the actual backward-compatibility proof: Phase 10
    changed zero lines of pipeline logic, only two path/import bugs in
    non-pipeline files (main.py, tests/test_pipeline.py itself)."""
    proc = subprocess.run(
        [sys.executable, "tests/test_pipeline.py"],
        cwd=_ENGINE_DIR,
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert proc.returncode == 0, (
        f"vendored engine's own test suite failed (regression!):\n"
        f"stdout(tail)={proc.stdout[-2000:]}\nstderr(tail)={proc.stderr[-2000:]}"
    )


def test_cli_entry_point_imports_and_shows_help():
    """main.py previously failed at IMPORT TIME (ai_engine.payload_suggestions
    does not exist) — this would have crashed before argparse even ran.
    --help exercises exactly that import path without touching the network."""
    proc = subprocess.run(
        [sys.executable, "main.py", "--help"],
        cwd=_ENGINE_DIR,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert proc.returncode == 0, f"stdout={proc.stdout}\nstderr={proc.stderr}"
    assert "ModuleNotFoundError" not in proc.stderr
    assert "ImportError" not in proc.stderr


def test_dashboard_module_still_imports():
    """The Flask dashboard (dashboard/app.py) must remain independently
    runnable — Phase 10 does not touch or replace it (§12)."""
    proc = subprocess.run(
        [sys.executable, "-c", "import sys; sys.path.insert(0, '.'); import dashboard.app"],
        cwd=_ENGINE_DIR,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert proc.returncode == 0, f"stdout={proc.stdout}\nstderr={proc.stderr}"


def test_report_generator_filename_convention_unchanged():
    """adapter.py's report-path-confinement logic depends on the exact
    filename pattern generate_text_report produces — this pins that
    contract so a future change to the vendored module fails loudly here
    instead of silently breaking report confinement."""
    sys.path.insert(0, str(_ENGINE_DIR))
    try:
        from reports.report_generator import generate_text_report  # type: ignore
        import inspect
        src = inspect.getsource(generate_text_report)
        assert '"reports"' in src
        assert "_safe_domain(domain)" in src
    finally:
        sys.path.remove(str(_ENGINE_DIR))
