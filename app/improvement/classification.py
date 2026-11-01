"""Deterministic, path-based change classification (conservative: when a path
is not clearly low risk it is classified higher, never lower).

LOW       documentation only
MEDIUM    isolated application logic, new tests
HIGH      provider/database/task/context/memory/networking/orchestration code,
          dependency files, modified tests, anything unrecognised, any deletion
CRITICAL  permissions, approval, sandbox, authentication, secrets, capability
          enforcement, the update engine itself, rollback, test configuration,
          and deleted tests
"""
from __future__ import annotations

import posixpath
from dataclasses import dataclass, field

from app.improvement.models import AutomationMode, ChangeOperation, RiskLevel, max_risk

CRITICAL_PREFIXES = (
    "app/security/", "app/capabilities/", "app/improvement/", "app/sandbox/", "app/versioning/",
    "app/tools/registry.py", "app/tools/base.py", "app/core/orchestrator.py", "app/config/",
)
CRITICAL_KEYWORDS = ("auth", "permission", "approval", "approve", "secret", "credential", "sandbox",
                     "rollback", "promotion", "promote", "capabilit", "password", "token", "update_engine")
HIGH_PREFIXES = (
    "app/providers/", "app/storage/", "app/tasks/", "app/memory/", "app/context/", "app/web/", "app/github/",
    "app/workspace/", "app/sessions/", "app/core/", "app/engineering/", "app/tools/",
)
TEST_CONFIG_NAMES = {"conftest.py", "pytest.ini", "tox.ini", "setup.cfg", ".coveragerc", "pyproject.toml", "noxfile.py"}
DEPENDENCY_FILES = {"requirements.txt", "requirements-dev.txt", "pipfile", "pipfile.lock", "poetry.lock",
                    "package.json", "package-lock.json", "constraints.txt"}
DOC_SUFFIXES = (".md", ".rst", ".txt")
DOC_TOP_LEVEL = {"readme.md", "changelog.md", "license", "license.md", "contributing.md"}
MAX_FILES_BEFORE_ESCALATION = 25


def is_docs_path(path: str) -> bool:
    low = path.lower()
    if low in DOC_TOP_LEVEL:
        return True
    return low.startswith("docs/") and low.endswith(DOC_SUFFIXES)


def is_test_path(path: str) -> bool:
    return path.startswith("tests/") or posixpath.basename(path).startswith("test_")


def is_test_config(path: str) -> bool:
    return posixpath.basename(path).lower() in TEST_CONFIG_NAMES


def is_protected_area(path: str) -> bool:
    return any(path == p or path.startswith(p) for p in CRITICAL_PREFIXES)


def classify_path(path: str, operation: ChangeOperation) -> tuple[RiskLevel, str, set[str]]:
    p = path.strip().lstrip("/")
    low = p.lower()
    base = posixpath.basename(low)
    flags: set[str] = set()
    if operation == ChangeOperation.DELETE:
        flags.add("delete_operation")
    if is_test_config(p):
        flags.update({"test_tampering", "test_config_change"})
        level, reason = RiskLevel.CRITICAL, "test/pytest configuration"
    elif is_protected_area(p):
        flags.add("protected_area")
        level, reason = RiskLevel.CRITICAL, "protected safety/update infrastructure"
    elif operation == ChangeOperation.DELETE and is_test_path(p):
        flags.update({"test_tampering", "test_deleted"})
        level, reason = RiskLevel.CRITICAL, "deleted test"
    elif is_docs_path(p):
        level, reason = RiskLevel.LOW, "documentation"
    elif any(k in low for k in CRITICAL_KEYWORDS):
        flags.add("security_keyword")
        level, reason = RiskLevel.CRITICAL, "path relates to security-sensitive functionality"
    elif base in DEPENDENCY_FILES:
        flags.add("dependency_change")
        level, reason = RiskLevel.HIGH, "dependency definition"
    elif is_test_path(p):
        if operation == ChangeOperation.MODIFY:
            flags.add("test_tampering")
            level, reason = RiskLevel.HIGH, "modified existing test"
        else:
            level, reason = RiskLevel.MEDIUM, "new test"
    elif any(p.startswith(pre) for pre in HIGH_PREFIXES):
        level, reason = RiskLevel.HIGH, "core subsystem"
    elif low == ".env.example":
        level, reason = RiskLevel.MEDIUM, "configuration template"
    elif p.startswith("app/") and low.endswith(".py"):
        level, reason = RiskLevel.MEDIUM, "application code"
    else:
        level, reason = RiskLevel.HIGH, "unrecognised path (classified conservatively)"
    if operation == ChangeOperation.DELETE and level.rank < RiskLevel.HIGH.rank:
        level, reason = RiskLevel.HIGH, f"deletion of {reason}"
    return level, reason, flags


@dataclass
class ChangeAssessment:
    risk: RiskLevel
    per_file: list[tuple[str, RiskLevel, str]]
    flags: set[str] = field(default_factory=set)
    mode: AutomationMode = AutomationMode.APPROVAL_REQUIRED
    reasons: list[str] = field(default_factory=list)

    @property
    def requires_approval(self) -> bool:
        return True  # every promotion needs an approval decision; see ApprovalPolicy for who may give it


def classify_changes(files: list[tuple[str, ChangeOperation]]) -> ChangeAssessment:
    per_file: list[tuple[str, RiskLevel, str]] = []
    flags: set[str] = set()
    for path, op in files:
        level, reason, f = classify_path(path, op)
        per_file.append((path, level, reason))
        flags |= f
    risk = max_risk([lvl for _, lvl, _ in per_file]) if per_file else RiskLevel.HIGH
    reasons = [f"{path}: {lvl.value} ({why})" for path, lvl, why in per_file]
    if len(files) > MAX_FILES_BEFORE_ESCALATION and risk.rank < RiskLevel.HIGH.rank:
        risk = RiskLevel.HIGH
        reasons.append(f"{len(files)} files changed (more than {MAX_FILES_BEFORE_ESCALATION})")
    return ChangeAssessment(risk=risk, per_file=per_file, flags=flags, mode=decide_mode(risk, flags, files), reasons=reasons)


def decide_mode(risk: RiskLevel, flags: set[str], files: list[tuple[str, ChangeOperation]]) -> AutomationMode:
    """SAFE_AUTOMATIC only for tiny documentation-only, non-deleting changes;
    APPROVAL_REQUIRED for HIGH/CRITICAL, deletions, dependencies, tampering and
    anything unrecognised; PROPOSE_ONLY for ordinary MEDIUM code changes."""
    if risk.rank >= RiskLevel.HIGH.rank or flags:
        return AutomationMode.APPROVAL_REQUIRED
    if (risk == RiskLevel.LOW and 0 < len(files) <= 5
            and all(is_docs_path(p) and op != ChangeOperation.DELETE for p, op in files)):
        return AutomationMode.SAFE_AUTOMATIC
    if risk == RiskLevel.MEDIUM:
        return AutomationMode.PROPOSE_ONLY
    return AutomationMode.APPROVAL_REQUIRED


def detect_test_tampering(files: list[tuple[str, ChangeOperation]]) -> list[str]:
    out: list[str] = []
    for path, op in files:
        _, _, flags = classify_path(path, op)
        if "test_config_change" in flags:
            out.append(f"test configuration changed: {path}")
        elif "test_deleted" in flags:
            out.append(f"test deleted: {path}")
        elif "test_tampering" in flags:
            out.append(f"existing test modified: {path}")
    return out
