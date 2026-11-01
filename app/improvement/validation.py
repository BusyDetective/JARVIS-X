from __future__ import annotations

import re
import uuid

from app.improvement.classification import detect_test_tampering
from app.improvement.errors import PreconditionError
from app.improvement.models import (
    ChangeSet,
    TestCounts,
    ValidationResult,
    ValidationStatus,
    ValidationSummary,
)
from app.sandbox.manager import SandboxManager
from app.sandbox.models import ExecutionResult, IsolationAttestation, SandboxOperation
from app.security.untrusted import redact_text
from app.versioning.manager import ReleaseStore
from app.versioning.manifest import tree_digest
from app.versioning.models import TestBaseline

MAX_SUMMARY_LINES = 25
MAX_SUMMARY_CHARS = 1500
ISOLATION_REASON = "validation did not run in the required isolation environment"
_COUNT_RE = {k: re.compile(rf"(\d+) {pat}") for k, pat in
             (("passed", "passed"), ("failed", "failed"), ("skipped", "skipped"), ("errors", "errors?"))}


def tail_summary(text: str) -> str:
    """Bounded, redacted tail of command output — never a full log."""
    lines = [ln.rstrip() for ln in text.strip().splitlines()][-MAX_SUMMARY_LINES:]
    out = "\n".join(lines)[-MAX_SUMMARY_CHARS:]
    return redact_text(out)[0]


def parse_stdout_counts(stdout: str) -> TestCounts | None:
    tail = "\n".join(stdout.strip().splitlines()[-3:])
    found = {k: int(m.group(1)) for k, rx in _COUNT_RE.items() if (m := rx.search(tail))}
    return TestCounts(**found) if found else None


def counts_from_reported(reported: dict | None) -> TestCounts | None:
    """Counts the in-container runner derived from pytest's junit report."""
    raw = (reported or {}).get("counts")
    if not isinstance(raw, dict):
        return None
    try:
        return TestCounts(**{k: int(raw.get(k, 0)) for k in ("passed", "failed", "skipped", "errors")})
    except (TypeError, ValueError):
        return None


class ValidationRunner:
    """Runs the two fixed validation operations (test suite, static analysis) through the
    sandbox's ISOLATION BACKEND and turns the outcome into a ValidationSummary. The model
    can only ask for "validate this candidate"; it never supplies a command.

    Fails closed: with no usable isolation backend nothing is executed and
    IsolationUnavailableError propagates. A summary can only be PASSED if every run
    carried an isolation attestation that meets the requirements, and the candidate tree
    was identical before and after the runs."""

    def __init__(self, sandbox: SandboxManager, store: ReleaseStore) -> None:
        self._sandbox = sandbox
        self._store = store

    async def preflight(self) -> IsolationAttestation:
        return await self._sandbox.ensure_isolation()

    async def _run_tests(self, sandbox_id: str) -> tuple[ValidationResult, TestCounts | None, list[str], ExecutionResult]:
        res = await self._sandbox.run(sandbox_id, SandboxOperation.RUN_TEST_SUITE)
        reported = counts_from_reported(res.reported)
        stdout = parse_stdout_counts(res.stdout)
        notes: list[str] = []
        counts = reported or stdout
        if reported and stdout and reported.passed != stdout.passed:
            notes.append("test result sources disagree (junit vs console summary)")
        passed = (res.exit_code == 0 and not res.timed_out and counts is not None
                  and counts.failed == 0 and counts.errors == 0 and counts.passed > 0)
        return self._result(res, passed), counts, notes, res

    @staticmethod
    def _result(res: ExecutionResult, passed: bool, unavailable: bool = False) -> ValidationResult:
        return ValidationResult(
            operation=res.operation.value, passed=passed, exit_code=res.exit_code, timed_out=res.timed_out,
            unavailable=unavailable, duration_seconds=res.duration_seconds, output_truncated=res.output_truncated,
            summary=tail_summary(res.stdout + ("\n" + res.stderr if res.stderr.strip() else "")))

    async def _run_static(self, sandbox_id: str) -> tuple[ValidationResult, ExecutionResult]:
        res = await self._sandbox.run(sandbox_id, SandboxOperation.RUN_STATIC_ANALYSIS)
        unavailable = res.exit_code not in (0, None) and "No module named" in (res.stdout + res.stderr) and "pyflakes" in (res.stdout + res.stderr)
        return self._result(res, passed=res.exit_code == 0 and not res.timed_out, unavailable=unavailable), res

    async def ensure_baseline(self, version: str) -> TestBaseline:
        """The baseline is the current release's own test result, captured in a pristine
        ISOLATED sandbox BEFORE any candidate is judged, and recorded once."""
        existing = self._store.get_baseline(version)
        if existing is not None:
            return existing
        sid = f"base-{uuid.uuid4().hex[:12]}"
        self._sandbox.create(sid, self._store.release_source(version))
        try:
            result, counts, _, raw = await self._run_tests(sid)
        finally:
            self._sandbox.destroy(sid)
        if raw.isolation is None or not raw.isolation.satisfies_requirements():
            raise PreconditionError(f"the baseline could not be recorded: {ISOLATION_REASON}")
        if not result.passed or counts is None:
            raise PreconditionError(f"the current release {version} does not pass its own tests; no baseline recorded")
        baseline = TestBaseline(passed=counts.passed, failed=counts.failed, skipped=counts.skipped,
                                duration_seconds=result.duration_seconds)
        self._store.record_baseline(version, baseline)
        return baseline

    async def validate(self, candidate_id: uuid.UUID, sandbox_id: str, base_version: str, change_set: ChangeSet) -> ValidationSummary:
        source = self._sandbox.paths(sandbox_id).source
        digest_before = tree_digest(source)
        baseline = await self.ensure_baseline(base_version)
        tamper = detect_test_tampering([(f.path, f.operation) for f in change_set.files])
        test_result, counts, notes, test_raw = await self._run_tests(sandbox_id)
        static_result, static_raw = await self._run_static(sandbox_id)
        cand = counts or TestCounts()
        reasons: list[str] = []
        attestation = test_raw.isolation
        for raw in (test_raw, static_raw):
            if raw.isolation is None or not raw.isolation.satisfies_requirements() or raw.isolation.image_id != (attestation.image_id if attestation else None):
                reasons.append(ISOLATION_REASON)
                attestation = None
                break
        if tree_digest(source) != digest_before:
            reasons.append("the candidate tree changed while it was being validated")
        if test_result.timed_out:
            reasons.append("test suite timed out")
        elif test_raw.resource_limit_exit:
            reasons.append("test suite was terminated by a resource limit (exit 137)")
        elif not test_result.passed:
            reasons.append(f"test suite failed (failed={cand.failed}, errors={cand.errors})" if counts else
                           "test suite produced no usable result")
        suspicious = [*tamper, *notes]
        if counts is not None and counts.passed < baseline.passed:
            suspicious.append(f"test count decreased: {baseline.passed} -> {counts.passed}")
            reasons.append("fewer tests pass than in the baseline")
        if static_result.unavailable:
            reasons.append("static analysis tool is unavailable in the validation image")
        elif static_raw.resource_limit_exit:
            reasons.append("static analysis was terminated by a resource limit (exit 137)")
        elif not static_result.passed:
            reasons.append("static analysis failed")
        if notes:
            reasons.extend(notes)
        status = ValidationStatus.FAILED if reasons else ValidationStatus.PASSED
        return ValidationSummary(
            candidate_id=candidate_id, status=status, baseline=TestCounts(passed=baseline.passed, failed=baseline.failed, skipped=baseline.skipped),
            candidate=cand, test_count_delta=cand.passed - baseline.passed, results=[test_result, static_result],
            static_analysis_passed=None if static_result.unavailable else static_result.passed,
            suspicious=suspicious, reasons=reasons, isolation=attestation, candidate_digest=digest_before,
            duration_seconds=round(test_result.duration_seconds + static_result.duration_seconds, 3))
