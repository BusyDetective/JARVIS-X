"""ValidationRunner logic.

Most tests here use the UNSAFE host-side test double (HostTestBackend) so real pytest/pyflakes runs can exercise the
counting, baseline and regression LOGIC. That is not isolation: it is opted in with `trust_test_backend`. Real
container isolation is tested in test_container_real.py; the gate logic with mocked attestations further below."""
from __future__ import annotations

import uuid

import pytest

import app.sandbox.models as sandbox_models
from app.improvement.errors import PreconditionError
from app.improvement.models import ChangeFile, ChangeSet, ValidationStatus
from app.improvement.models import ChangeOperation as Op
from app.improvement.validation import (
    ISOLATION_REASON, ValidationRunner, counts_from_reported, parse_stdout_counts, tail_summary,
)
from app.sandbox.errors import IsolationFailure, IsolationUnavailableError
from app.sandbox.isolation import IsolationBackend
from app.sandbox.manager import SandboxManager
from app.sandbox.models import ChangeOperation, ExecutionResult, SandboxChange, SandboxOperation
from app.versioning.manager import ReleaseStore
from app.versioning.manifest import tree_digest
from app.versioning.models import TestBaseline
from tests.improvement_helpers import HostTestBackend, fake_attestation, make_policy, make_project, sha

pytestmark = pytest.mark.usefixtures("trust_test_backend")

SID = "cand-validate00001"
UTIL = "def add(a, b):\n    return a + b\n"


def make_world(tmp_path, backend=None, **policy_kw):
    project = make_project(tmp_path / "project")
    store = ReleaseStore(tmp_path / "store")
    version = store.bootstrap(project)
    policy = make_policy(**policy_kw)
    sandbox = SandboxManager(tmp_path / "store", policy, backend if backend is not None else HostTestBackend(policy))
    return store, sandbox, version, project


@pytest.fixture
def world(tmp_path):
    return make_world(tmp_path)


def candidate(world, changes):
    store, sb, version, _ = world
    sb.create(SID, store.release_source(version))
    sb.apply_changes(SID, changes)
    return ChangeSet(files=[ChangeFile(path=c.path, operation=Op(c.operation.value), original_hash=c.original_hash, proposed_hash=c.proposed_hash)
                            for c in changes])


def add(path, text):
    return SandboxChange(path=path, operation=ChangeOperation.ADD, proposed_hash=sha(text), content=text.encode())


def modify(path, old, new):
    return SandboxChange(path=path, operation=ChangeOperation.MODIFY, original_hash=sha(old), proposed_hash=sha(new), content=new.encode())


async def validate(world, changes):
    store, sb, version, _ = world
    cs = candidate(world, changes)
    return await ValidationRunner(sb, store).validate(uuid.uuid4(), SID, version, cs)


async def test_baseline_is_captured_before_and_recorded_once(world):
    store, sb, version, _ = world
    runner = ValidationRunner(sb, store)
    assert store.get_baseline(version) is None
    base = await runner.ensure_baseline(version)
    assert base.passed == 2 and store.get_baseline(version).passed == 2
    assert await runner.ensure_baseline(version) == base
    assert list(sb.candidates_dir.iterdir()) == []  # the temporary baseline sandbox is cleaned up


async def test_release_that_fails_its_own_tests_has_no_baseline(tmp_path):
    project = make_project(tmp_path / "p", {"tests/test_broken.py": "def test_broken():\n    assert False\n"})
    store = ReleaseStore(tmp_path / "s")
    v = store.bootstrap(project)
    policy = make_policy()
    with pytest.raises(PreconditionError, match="does not pass its own tests"):
        await ValidationRunner(SandboxManager(tmp_path / "s", policy, HostTestBackend(policy)), store).ensure_baseline(v)
    assert store.get_baseline(v) is None


async def test_passing_candidate_with_new_tests(world):
    new_tests = "from app.util import add\n\n\ndef test_a():\n    assert add(2, 2) == 4\n\n\ndef test_b():\n    assert add(-1, 1) == 0\n"
    s = await validate(world, [add("tests/test_more.py", new_tests)])
    assert s.status is ValidationStatus.PASSED and s.reasons == []
    assert s.baseline.passed == 2 and s.candidate.passed == 4 and s.test_count_delta == 2
    assert s.static_analysis_passed is True and [r.operation for r in s.results] == ["run_test_suite", "run_static_analysis"]
    assert all(r.passed for r in s.results) and s.suspicious == []
    assert s.isolation is not None and s.candidate_digest == tree_digest(world[1].paths(SID).source)


async def test_failing_tests_fail_validation(world):
    s = await validate(world, [modify("app/util.py", UTIL, "def add(a, b):\n    return a - b\n")])
    assert s.status is ValidationStatus.FAILED and any("test suite failed" in r for r in s.reasons)
    assert s.candidate.failed >= 1 and s.results[0].passed is False and s.results[0].summary


async def test_timeout_fails_validation(tmp_path):
    w = make_world(tmp_path, timeout_seconds=3)
    store, sb, version, _ = w
    # the baseline must be recorded with a generous timeout first, then the candidate runs under the short one
    long_policy = make_policy()
    await ValidationRunner(SandboxManager(tmp_path / "store", long_policy, HostTestBackend(long_policy)), store).ensure_baseline(version)
    cs = candidate(w, [add("tests/test_slow.py", "import time\n\n\ndef test_slow():\n    time.sleep(60)\n")])
    s = await ValidationRunner(sb, store).validate(uuid.uuid4(), SID, version, cs)
    assert s.status is ValidationStatus.FAILED and "test suite timed out" in s.reasons and s.results[0].timed_out is True


async def test_reduced_test_count_is_suspicious_and_fails(world):
    reduced = "from app.util import add\n\n\ndef test_add():\n    assert add(1, 2) == 3\n"
    old_tests = (world[3] / "tests" / "test_util.py").read_text()
    s = await validate(world, [modify("tests/test_util.py", old_tests, reduced)])
    assert s.status is ValidationStatus.FAILED and s.test_count_delta == -1
    assert "test count decreased: 2 -> 1" in s.suspicious and "fewer tests pass than in the baseline" in s.reasons
    assert any(x.startswith("existing test modified") for x in s.suspicious)


async def test_static_analysis_failure_fails_validation(world):
    s = await validate(world, [add("app/bad.py", "import os\n\n\ndef f():\n    return undefined_name\n")])
    assert s.status is ValidationStatus.FAILED and s.static_analysis_passed is False and "static analysis failed" in s.reasons
    assert s.results[0].passed is True and s.results[1].passed is False and "undefined name" in s.results[1].summary


async def test_test_configuration_changes_are_flagged(world):
    s = await validate(world, [add("conftest.py", "# harmless\n")])
    assert s.status is ValidationStatus.PASSED  # tests still pass...
    assert s.suspicious == ["test configuration changed: conftest.py"]  # ...but it is flagged for escalation/approval


async def test_secrets_in_output_are_redacted_and_summary_is_bounded(world):
    noisy = ("def test_leak():\n    print('password = hunter2hunter2')\n    print('token ghp_abcdefghijklmnopqrstuvwxyz0123')\n"
             "    for i in range(500):\n        print('line', i)\n    assert False\n")
    s = await validate(world, [add("tests/test_leak.py", noisy)])
    summary = s.results[0].summary
    assert "hunter2hunter2" not in summary and "ghp_abcdefghijklmnopqrstuvwxyz0123" not in summary
    assert len(summary) <= 1500 and len(summary.splitlines()) <= 25


# --- isolation requirements and exact-candidate binding (logic; stub backends) ---------------------------


class StubBackend(IsolationBackend):
    """Returns canned ExecutionResults. MOCK: exercises how the runner treats results, not any real isolation."""

    name = "stub"

    def __init__(self, results, attestation=None, mutate=None):
        self.results, self.attestation, self.mutate, self.runs = list(results), attestation or fake_attestation(), mutate, 0

    def describe(self):
        return "stub"

    async def preflight(self):
        return self.attestation

    async def run(self, paths, operation):
        self.runs += 1
        if self.mutate:
            self.mutate(paths, operation)
        res = self.results.pop(0) if self.results else self.default(operation)
        return res.model_copy(update={"isolation": self.attestation if res.isolation is None else res.isolation})

    @staticmethod
    def default(operation):
        if operation == SandboxOperation.RUN_TEST_SUITE:
            return ExecutionResult(operation=operation, exit_code=0, duration_seconds=0.1, stdout="2 passed in 0.1s",
                                   reported={"exit": 0, "counts": {"passed": 2, "failed": 0, "skipped": 0, "errors": 0}})
        return ExecutionResult(operation=operation, exit_code=0, duration_seconds=0.1)


def stub_world(tmp_path, backend):
    w = make_world(tmp_path, backend=backend)
    w[0].record_baseline(w[2], TestBaseline(passed=2))  # recorded up front so the stub's queue maps to the candidate's runs only
    cs = candidate(w, [add("app/extra.py", "x = 1\n")])
    return w, cs


async def run_stub(tmp_path, backend):
    w, cs = stub_world(tmp_path, backend)
    store, sb, version, _ = w
    return await ValidationRunner(sb, store).validate(uuid.uuid4(), SID, version, cs), w


async def test_validation_requires_the_isolation_attestation(tmp_path):
    for weak in (fake_attestation(network="host"), fake_attestation(user="0:0"), fake_attestation(read_only_rootfs=False),
                 fake_attestation(capabilities_dropped=False), fake_attestation(no_new_privileges=False), fake_attestation(canary_passed=False),
                 fake_attestation(host_mounts=["snapshot:ro", "home:rw"]), fake_attestation(writable_host_mounts=1)):
        s, _ = await run_stub(tmp_path / uuid.uuid4().hex[:6], StubBackend([], attestation=weak))
        assert s.status is ValidationStatus.FAILED and ISOLATION_REASON in s.reasons and s.isolation is None, weak


async def test_an_untrusted_backend_name_is_never_accepted(tmp_path, monkeypatch):
    monkeypatch.setattr(sandbox_models, "TRUSTED_BACKENDS", frozenset({"docker", "podman"}))  # production set
    s, _ = await run_stub(tmp_path, StubBackend([], attestation=fake_attestation(backend="test-double")))
    assert s.status is ValidationStatus.FAILED and ISOLATION_REASON in s.reasons
    ok, _ = await run_stub(tmp_path / "b", StubBackend([], attestation=fake_attestation(backend="podman")))
    assert ok.status is ValidationStatus.PASSED and ok.isolation.satisfies_requirements()


async def test_baseline_cannot_be_recorded_without_isolation(tmp_path):
    w = make_world(tmp_path, backend=StubBackend([], attestation=fake_attestation(network="host")))
    store, sb, version, _ = w
    with pytest.raises(PreconditionError, match=ISOLATION_REASON):
        await ValidationRunner(sb, store).ensure_baseline(version)
    assert store.get_baseline(version) is None


async def test_the_candidate_tree_changing_during_validation_fails(tmp_path):
    def tamper(paths, operation):
        if operation == SandboxOperation.RUN_TEST_SUITE:
            (paths.source / "app" / "sneaky.py").write_text("changed = True\n")

    s, _ = await run_stub(tmp_path, StubBackend([], mutate=tamper))
    assert s.status is ValidationStatus.FAILED and "the candidate tree changed while it was being validated" in s.reasons


async def test_resource_limit_kills_are_reported(tmp_path):
    killed = ExecutionResult(operation=SandboxOperation.RUN_TEST_SUITE, exit_code=137, duration_seconds=1.0, resource_limit_exit=True)
    s, _ = await run_stub(tmp_path, StubBackend([killed]))
    assert s.status is ValidationStatus.FAILED and "test suite was terminated by a resource limit (exit 137)" in s.reasons


async def test_unusable_results_fail(tmp_path):
    s, _ = await run_stub(tmp_path, StubBackend([ExecutionResult(operation=SandboxOperation.RUN_TEST_SUITE, exit_code=0, duration_seconds=0.1, stdout="garbage")]))
    assert s.status is ValidationStatus.FAILED and "test suite produced no usable result" in s.reasons


async def test_disagreeing_result_sources_are_flagged(tmp_path):
    odd = ExecutionResult(operation=SandboxOperation.RUN_TEST_SUITE, exit_code=0, duration_seconds=0.1, stdout="99 passed in 1s",
                          reported={"exit": 0, "counts": {"passed": 2, "failed": 0, "skipped": 0, "errors": 0}})
    s, _ = await run_stub(tmp_path, StubBackend([odd]))
    assert s.status is ValidationStatus.FAILED and "test result sources disagree (junit vs console summary)" in s.suspicious


async def test_static_analysis_tool_missing_in_the_image_is_reported(tmp_path):
    missing = ExecutionResult(operation=SandboxOperation.RUN_STATIC_ANALYSIS, exit_code=1, duration_seconds=0.1,
                              stdout="/usr/bin/python3: No module named pyflakes")
    s, _ = await run_stub(tmp_path, StubBackend([StubBackend.default(SandboxOperation.RUN_TEST_SUITE), missing]))
    assert s.status is ValidationStatus.FAILED and s.static_analysis_passed is None
    assert "static analysis tool is unavailable in the validation image" in s.reasons


async def test_no_isolation_backend_means_nothing_runs(tmp_path):
    store, sb, version, project = make_world(tmp_path)
    sb.backend = None
    runner = ValidationRunner(sb, store)
    with pytest.raises(IsolationUnavailableError) as ei:
        await runner.preflight()
    assert ei.value.reason is IsolationFailure.NO_BACKEND_CONFIGURED
    sb.create(SID, store.release_source(version))
    with pytest.raises(IsolationUnavailableError):
        await runner.validate(uuid.uuid4(), SID, version, ChangeSet(files=[ChangeFile(path="a.py", operation=Op.ADD, proposed_hash="a" * 64)]))
    assert store.get_baseline(version) is None


def test_output_parsing_helpers():
    assert parse_stdout_counts("....\n3 passed, 1 skipped in 0.5s\n").model_dump() == {"passed": 3, "failed": 0, "skipped": 1, "errors": 0}
    assert parse_stdout_counts("1 failed, 4 passed, 2 errors in 1s").model_dump() == {"passed": 4, "failed": 1, "skipped": 0, "errors": 2}
    assert parse_stdout_counts("nothing useful") is None
    assert counts_from_reported({"counts": {"passed": 6, "failed": 1, "skipped": 2, "errors": 1}}).model_dump() == {"passed": 6, "failed": 1, "skipped": 2, "errors": 1}
    for bad in (None, {}, {"counts": None}, {"counts": "x"}, {"counts": {"passed": "many"}}):
        assert counts_from_reported(bad) is None


def test_tail_summary_bounds_and_redacts():
    text = "\n".join(f"line {i}" for i in range(200)) + "\napi_key=abcdef123456\n"
    out = tail_summary(text)
    assert "abcdef123456" not in out and len(out.splitlines()) <= 25 and len(out) <= 1500
    assert tail_summary("") == ""
