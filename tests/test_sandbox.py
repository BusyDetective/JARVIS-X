"""Sandbox file operations (REAL filesystem tests), the fail-closed manager, and policy.
Container execution is covered in test_container_backend.py (MOCKED runtime) and
test_container_real.py (REAL containers, skipped when no runtime is available)."""
from __future__ import annotations

import asyncio
import inspect
import re
from pathlib import Path

import pytest

import app
from app.sandbox.errors import (
    IsolationFailure, IsolationUnavailableError, SandboxChangeError, SandboxError, SandboxPathError, SandboxPolicyViolation,
)
from app.sandbox.isolation import IsolationBackend
from app.sandbox.manager import SandboxManager
from app.sandbox.models import ChangeOperation, SandboxChange, SandboxOperation
from app.sandbox.policy import SandboxPolicy
from tests.improvement_helpers import make_policy, make_project, sha, tree_hashes

SID = "cand-abcdef123456"


@pytest.fixture
def env(tmp_path):
    project = make_project(tmp_path / "release", {
        ".env": "API_KEY=supersecret", "id_rsa": "KEY", "server.pem": "pem", ".git/config": "[core]",
        "data/app.db": "db", "logs/x.log": "log", "workspace/notes.txt": "n", "__pycache__/x.pyc": "pyc",
        "node_modules/pkg/index.js": "js", "app/__pycache__/m.pyc": "pyc"})
    (project / "link_to_outside").symlink_to(tmp_path)
    sm = SandboxManager(tmp_path / "sb", make_policy())
    return sm, project, tmp_path


def test_create_copies_only_snapshot_eligible_files(env):
    sm, project, _ = env
    paths = sm.create(SID, project)
    copied = set(tree_hashes(paths.source))
    assert {"app/util.py", "tests/test_util.py", "README.md", "requirements.txt"} <= copied
    for excluded in (".env", "id_rsa", "server.pem", ".git/config", "data/app.db", "logs/x.log", "workspace/notes.txt",
                     "__pycache__/x.pyc", "node_modules/pkg/index.js", "app/__pycache__/m.pyc"):
        assert excluded not in copied
    assert not (paths.source / "link_to_outside").exists()  # symlinks are never copied


def test_sandbox_ids_are_validated(env):
    sm, project, _ = env
    for bad in ("", "../x", "a/b", "CAND-ABCDEF123", "x", "cand-" + "a" * 80, "cand abc123"):
        with pytest.raises(SandboxPathError):
            sm.create(bad, project)
    sm.create(SID, project)
    with pytest.raises(SandboxError, match="already exists"):
        sm.create(SID, project)
    with pytest.raises(SandboxPathError, match="does not exist"):
        sm.paths("cand-doesnotexist1")


@pytest.mark.parametrize("bad", ["../x", "a/../../x", "/etc/passwd", "~/x", "C:/x", "a\\b", "a/%2e%2e/b", "a\x00b", "", ".", "..", "a/%2F"])
def test_resolve_rejects_escapes(env, bad):
    sm, project, _ = env
    sm.create(SID, project)
    with pytest.raises(SandboxPathError):
        sm.resolve(SID, bad)


def test_resolve_rejects_symlink_escape(env):
    sm, project, tmp_path = env
    paths = sm.create(SID, project)
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret.txt").write_text("outside")
    (paths.source / "evil_link").symlink_to(outside, target_is_directory=True)
    with pytest.raises(SandboxPathError, match="outside"):
        sm.resolve(SID, "evil_link/secret.txt")
    assert sm.resolve(SID, "app/util.py").is_file()


def test_candidate_and_current_are_separate_trees(env):
    sm, project, _ = env
    before = tree_hashes(project)
    paths = sm.create(SID, project)
    new = "def add(a, b):\n    return a + b + 0\n"
    sm.apply_changes(SID, [SandboxChange(path="app/util.py", operation=ChangeOperation.MODIFY, original_hash=sha("def add(a, b):\n    return a + b\n"),
                                         proposed_hash=sha(new), content=new.encode())])
    assert (paths.source / "app/util.py").read_text() == new
    assert tree_hashes(project) == before  # the source it was copied from is untouched


def test_apply_add_modify_delete_and_report(env):
    sm, project, _ = env
    paths = sm.create(SID, project)
    old = (paths.source / "app/util.py").read_text()
    changes = [
        SandboxChange(path="app/new.py", operation=ChangeOperation.ADD, proposed_hash=sha("x = 1\n"), content=b"x = 1\n"),
        SandboxChange(path="app/util.py", operation=ChangeOperation.MODIFY, original_hash=sha(old), proposed_hash=sha("y = 2\n"), content=b"y = 2\n"),
        SandboxChange(path="docs/guide.md", operation=ChangeOperation.DELETE, original_hash=sha("guide\n")),
    ]
    assert sm.apply_changes(SID, changes) == ["app/new.py", "app/util.py", "docs/guide.md"]
    assert (paths.source / "app/new.py").read_text() == "x = 1\n" and (paths.source / "app/util.py").read_text() == "y = 2\n"
    assert not (paths.source / "docs/guide.md").exists()
    assert sm.source_hashes(SID)["app/new.py"] == sha("x = 1\n")


def test_apply_rejects_stale_missing_duplicate_and_bad_content(env):
    sm, project, _ = env
    paths = sm.create(SID, project)
    good = sha("def add(a, b):\n    return a + b\n")
    cases = [
        SandboxChange(path="app/util.py", operation=ChangeOperation.MODIFY, original_hash=sha("stale"), proposed_hash=sha("x"), content=b"x"),
        SandboxChange(path="app/util.py", operation=ChangeOperation.MODIFY, original_hash=good, proposed_hash=sha("x"), content=b"tampered"),
        SandboxChange(path="app/util.py", operation=ChangeOperation.ADD, proposed_hash=sha("x"), content=b"x"),
        SandboxChange(path="app/ghost.py", operation=ChangeOperation.MODIFY, original_hash=good, proposed_hash=sha("x"), content=b"x"),
        SandboxChange(path="app/ghost.py", operation=ChangeOperation.DELETE, original_hash=good),
        SandboxChange(path="app/util.py", operation=ChangeOperation.DELETE, original_hash=None),
        SandboxChange(path="app/new.py", operation=ChangeOperation.ADD, proposed_hash=None, content=None),
    ]
    for case in cases:
        with pytest.raises(SandboxChangeError):
            sm.apply_changes(SID, [case])
    assert (paths.source / "app/util.py").read_text() == "def add(a, b):\n    return a + b\n"


@pytest.mark.parametrize("path", [".env", ".git/config", "data/app.db", "logs/a.log", "id_rsa", "../outside.py", "/etc/passwd",
                                  "app/__pycache__/x.py", "node_modules/a.js", "a\\b"])
def test_apply_rejects_protected_and_escaping_paths(env, path):
    sm, project, tmp_path = env
    sm.create(SID, project)
    with pytest.raises((SandboxChangeError, SandboxPathError)):
        sm.apply_changes(SID, [SandboxChange(path=path, operation=ChangeOperation.ADD, proposed_hash=sha("x"), content=b"x")])
    assert not (tmp_path / "outside.py").exists()


def test_apply_is_all_or_nothing(env):
    sm, project, _ = env
    paths = sm.create(SID, project)
    ok = SandboxChange(path="app/new.py", operation=ChangeOperation.ADD, proposed_hash=sha("x"), content=b"x")
    bad = SandboxChange(path="app/util.py", operation=ChangeOperation.MODIFY, original_hash=sha("stale"), proposed_hash=sha("y"), content=b"y")
    with pytest.raises(SandboxChangeError):
        sm.apply_changes(SID, [ok, bad])
    assert not (paths.source / "app/new.py").exists()
    dup = [ok, SandboxChange(path="app/new.py", operation=ChangeOperation.ADD, proposed_hash=sha("x"), content=b"x")]
    with pytest.raises(SandboxChangeError, match="more than once"):
        sm.apply_changes(SID, dup)


def test_destroy_and_workspace_view(env):
    sm, project, _ = env
    sm.create(SID, project)
    ws = sm.workspace(SID)
    assert ws.read_file("app/util.py").content.startswith("def add")
    sm.destroy(SID)
    assert not sm.exists(SID)


# --- fail closed: no backend, no execution ---------------------------------------------------------


def test_manager_without_a_backend_never_executes_and_fails_closed(env):
    sm, project, _ = env
    sm.create(SID, project)
    assert sm.backend is None
    for op in SandboxOperation:
        with pytest.raises(IsolationUnavailableError) as ei:
            asyncio.run(sm.run(SID, op))
        assert ei.value.reason is IsolationFailure.NO_BACKEND_CONFIGURED and "nothing was executed" in str(ei.value)
    with pytest.raises(IsolationUnavailableError):
        asyncio.run(sm.ensure_isolation())


def test_run_accepts_only_an_operation_enum_never_a_command(env):
    sm, project, _ = env
    sm.create(SID, project)
    assert list(inspect.signature(SandboxManager.run).parameters) == ["self", "sandbox_id", "operation"]
    for bad in ("pytest -q", ["ls", "-la"], "rm -rf /", None):
        with pytest.raises(SandboxPolicyViolation):
            asyncio.run(sm.run(SID, bad))  # type: ignore[arg-type]
    assert {o.value for o in SandboxOperation} == {"run_test_suite", "run_static_analysis"}
    restricted = SandboxManager(sm.root, make_policy(allowed_operations=frozenset({SandboxOperation.RUN_STATIC_ANALYSIS})))
    with pytest.raises(SandboxPolicyViolation):
        asyncio.run(restricted.run(SID, SandboxOperation.RUN_TEST_SUITE))


def test_backend_errors_propagate_and_nothing_falls_back(env):
    sm, project, _ = env
    sm.create(SID, project)
    calls = []

    class Broken(IsolationBackend):
        name = "broken"

        def describe(self):
            return "broken"

        async def preflight(self):
            calls.append("preflight")
            raise IsolationUnavailableError(IsolationFailure.RUNTIME_NOT_USABLE, "daemon down")

        async def run(self, paths, operation):
            calls.append("run")
            raise IsolationUnavailableError(IsolationFailure.STARTUP_FAILED, "cannot start")

    sm.backend = Broken()
    with pytest.raises(IsolationUnavailableError, match="cannot start"):
        asyncio.run(sm.run(SID, SandboxOperation.RUN_TEST_SUITE))
    with pytest.raises(IsolationUnavailableError, match="daemon down"):
        asyncio.run(sm.ensure_isolation())
    assert calls == ["run", "preflight"]


def test_there_is_no_host_execution_path_in_the_code_base():
    """Static guard: the container CLI wrapper is the ONLY place that starts processes, and the only
    IsolationBackend implementation in app/ is ContainerBackend."""
    base = Path(app.__file__).parent
    pattern = re.compile(r"\bsubprocess\b|create_subprocess|os\.system|os\.popen|\bpopen\b|os\.exec|os\.spawn|\bpty\b|preexec_fn|\bRLIMIT_")
    offenders = sorted(str(p.relative_to(base)) for p in base.rglob("*.py") if pattern.search(p.read_text()))
    assert offenders == ["sandbox/container.py"]
    backends = [str(p.relative_to(base)) for p in base.rglob("*.py") if re.search(r"class \w+\((?:\w+\.)?IsolationBackend\)", p.read_text())]
    assert backends == ["sandbox/container.py"]
    for p in (base / "sandbox" / "manager.py", base / "improvement" / "validation.py"):
        assert "sys.executable" not in p.read_text()


def test_isolation_report_does_not_overclaim(env):
    sm, _, _ = env
    report = sm.isolation_report()
    assert "NONE configured" in report["backend"] and "fails closed" in report["backend"]
    assert "no host execution" in report["execution"] and "NOT a perfect boundary" in report["residual_risk"]
    assert "kernel" in report["residual_risk"] and "forge" in report["residual_risk"]
    assert "--network none" in report["network"] and "container boundary" in report["network"]
    assert "read-only" in report["filesystem"] and "no home directory" in report["filesystem"]


def test_policy_value_validation_and_limits():
    for kw in (dict(timeout_seconds=0), dict(max_output_bytes=10), dict(memory_limit_mb=1), dict(max_processes=1), dict(network="open"),
               dict(cpus=0), dict(work_tmpfs_mb=1)):
        with pytest.raises(ValueError):
            SandboxPolicy(**kw)
    limits = SandboxPolicy(memory_limit_mb=512, cpus=1.5, max_processes=64).limits_summary()
    assert limits["memory_mb"] == 512 and limits["cpus"] == 1.5 and limits["pids"] == 64


def test_error_taxonomy_is_typed():
    err = IsolationUnavailableError(IsolationFailure.NO_CONTAINER_RUNTIME, "msg")
    assert isinstance(err, SandboxError) and err.reason is IsolationFailure.NO_CONTAINER_RUNTIME
    assert {f.value for f in IsolationFailure} >= {"no_backend_configured", "no_container_runtime", "runtime_not_usable",
                                                   "image_not_found", "restrictions_not_established", "startup_failed", "misconfigured"}
