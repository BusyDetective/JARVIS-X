from __future__ import annotations

import pytest

from app.improvement.classification import (
    classify_changes, classify_path, decide_mode, detect_test_tampering, is_docs_path,
)
from app.improvement.models import AutomationMode as M
from app.improvement.models import ChangeOperation as Op
from app.improvement.models import RiskLevel as R


@pytest.mark.parametrize("path,op,risk", [
    ("README.md", Op.MODIFY, R.LOW), ("docs/guide.md", Op.ADD, R.LOW), ("CHANGELOG.md", Op.MODIFY, R.LOW),
    ("app/util/strings.py", Op.ADD, R.MEDIUM), ("app/ui/view.py", Op.MODIFY, R.MEDIUM), ("tests/test_new.py", Op.ADD, R.MEDIUM),
    (".env.example", Op.MODIFY, R.MEDIUM),
    ("app/providers/gemini.py", Op.MODIFY, R.HIGH), ("app/storage/database.py", Op.MODIFY, R.HIGH), ("app/tasks/manager.py", Op.MODIFY, R.HIGH),
    ("app/memory/manager.py", Op.MODIFY, R.HIGH), ("app/context/manager.py", Op.MODIFY, R.HIGH), ("app/web/fetch.py", Op.MODIFY, R.HIGH),
    ("app/github/client.py", Op.MODIFY, R.HIGH), ("app/core/runner.py", Op.MODIFY, R.HIGH), ("requirements.txt", Op.MODIFY, R.HIGH),
    ("requirements-dev.txt", Op.MODIFY, R.HIGH), ("tests/test_existing.py", Op.MODIFY, R.HIGH),
    ("Dockerfile", Op.ADD, R.HIGH), ("scripts/run.sh", Op.ADD, R.HIGH), ("weird.bin", Op.ADD, R.HIGH), ("app/data.json", Op.ADD, R.HIGH),
    ("app/security/permissions.py", Op.MODIFY, R.CRITICAL), ("app/security/approval.py", Op.MODIFY, R.CRITICAL),
    ("app/capabilities/manager.py", Op.MODIFY, R.CRITICAL), ("app/improvement/manager.py", Op.MODIFY, R.CRITICAL),
    ("app/sandbox/policy.py", Op.MODIFY, R.CRITICAL), ("app/versioning/manager.py", Op.MODIFY, R.CRITICAL),
    ("app/tools/registry.py", Op.MODIFY, R.CRITICAL), ("app/core/orchestrator.py", Op.MODIFY, R.CRITICAL),
    ("app/config/settings.py", Op.MODIFY, R.CRITICAL), ("app/util/auth_helpers.py", Op.ADD, R.CRITICAL),
    ("app/util/credentials.py", Op.ADD, R.CRITICAL), ("app/x/rollback_tools.py", Op.ADD, R.CRITICAL),
    ("pyproject.toml", Op.MODIFY, R.CRITICAL), ("pytest.ini", Op.ADD, R.CRITICAL), ("tests/conftest.py", Op.MODIFY, R.CRITICAL),
    ("conftest.py", Op.ADD, R.CRITICAL), ("setup.cfg", Op.MODIFY, R.CRITICAL), ("tox.ini", Op.MODIFY, R.CRITICAL), (".coveragerc", Op.ADD, R.CRITICAL),
    ("tests/test_old.py", Op.DELETE, R.CRITICAL),
    ("README.md", Op.DELETE, R.HIGH), ("app/util/strings.py", Op.DELETE, R.HIGH),
])
def test_path_classification(path, op, risk):
    assert classify_path(path, op)[0] is risk, (path, op)


def test_protected_areas_are_always_critical_even_for_docs_and_new_files():
    for path in ("app/security/NOTES.md", "app/sandbox/new_helper.py", "app/improvement/docs.txt", "app/capabilities/x.py"):
        for op in (Op.ADD, Op.MODIFY):
            assert classify_path(path, op)[0] is R.CRITICAL


def test_uncertain_paths_are_classified_higher_not_lower():
    assert classify_path("something/unknown.dat", Op.ADD)[0] is R.HIGH
    assert classify_path("app/new_subsystem/thing.cfg", Op.ADD)[0] is R.HIGH


def test_aggregate_risk_is_the_maximum_and_lists_reasons():
    a = classify_changes([("README.md", Op.MODIFY), ("app/util/x.py", Op.ADD), ("app/security/permissions.py", Op.MODIFY)])
    assert a.risk is R.CRITICAL and a.mode is M.APPROVAL_REQUIRED and len(a.reasons) == 3 and "protected_area" in a.flags
    assert classify_changes([]).risk is R.HIGH


def test_many_files_escalate_to_at_least_high():
    files = [(f"docs/page{i}.md", Op.MODIFY) for i in range(26)]
    a = classify_changes(files)
    assert a.risk is R.HIGH and a.mode is M.APPROVAL_REQUIRED
    assert classify_changes(files[:25]).risk is R.LOW


@pytest.mark.parametrize("files,mode", [
    ([("README.md", Op.MODIFY)], M.SAFE_AUTOMATIC),
    ([("docs/a.md", Op.ADD), ("docs/b.md", Op.MODIFY)], M.SAFE_AUTOMATIC),
    ([(f"docs/{i}.md", Op.ADD) for i in range(6)], M.APPROVAL_REQUIRED),  # too many for automatic
    ([("README.md", Op.DELETE)], M.APPROVAL_REQUIRED),
    ([("app/util/x.py", Op.ADD)], M.PROPOSE_ONLY),
    ([("app/util/x.py", Op.ADD), ("README.md", Op.MODIFY)], M.PROPOSE_ONLY),
    ([("app/providers/x.py", Op.MODIFY)], M.APPROVAL_REQUIRED),
    ([("requirements.txt", Op.MODIFY)], M.APPROVAL_REQUIRED),
    ([("app/security/x.py", Op.MODIFY)], M.APPROVAL_REQUIRED),
    ([("tests/test_a.py", Op.MODIFY)], M.APPROVAL_REQUIRED),
    ([("unknown.thing", Op.ADD)], M.APPROVAL_REQUIRED),
])
def test_automation_mode(files, mode):
    assert classify_changes(files).mode is mode


def test_decide_mode_flags_force_approval():
    assert decide_mode(R.LOW, {"dependency_change"}, [("README.md", Op.MODIFY)]) is M.APPROVAL_REQUIRED
    assert decide_mode(R.LOW, set(), []) is M.APPROVAL_REQUIRED


def test_test_tampering_detection():
    found = detect_test_tampering([
        ("tests/test_a.py", Op.DELETE), ("tests/test_b.py", Op.MODIFY), ("pytest.ini", Op.MODIFY),
        ("tests/conftest.py", Op.ADD), ("tests/test_new.py", Op.ADD), ("app/x.py", Op.MODIFY)])
    assert found == ["test deleted: tests/test_a.py", "existing test modified: tests/test_b.py",
                     "test configuration changed: pytest.ini", "test configuration changed: tests/conftest.py"]
    assert detect_test_tampering([("app/x.py", Op.MODIFY), ("tests/test_new.py", Op.ADD)]) == []


def test_docs_path_detection():
    assert is_docs_path("README.md") and is_docs_path("docs/a/b.rst") and is_docs_path("docs/n.txt")
    assert not is_docs_path("docs/script.py") and not is_docs_path("app/readme.md") and not is_docs_path("notes.md")
