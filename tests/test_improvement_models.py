from __future__ import annotations

import itertools
import json
import uuid
from datetime import datetime

import pytest
from pydantic import ValidationError

from app.improvement.errors import InvalidTransitionError
from app.improvement.models import (
    ALLOWED_TRANSITIONS, TERMINAL_STATES, ChangeFile, ChangeOperation as Op, ChangeSet, ImprovementRequest, ImprovementRun,
    ImprovementState as S, RiskLevel, check_transition, max_risk,
)

H1, H2 = "a" * 64, "b" * 64


def test_all_lifecycle_states_exist():
    assert {s.value for s in S} == {"discovered", "evaluated", "planned", "proposed", "sandboxed", "validating", "validated",
                                    "rejected", "approved", "promoted", "failed", "rolled_back"}


def test_happy_path_transitions_are_allowed():
    path = [S.DISCOVERED, S.EVALUATED, S.PLANNED, S.PROPOSED, S.SANDBOXED, S.VALIDATING, S.VALIDATED, S.APPROVED, S.PROMOTED, S.ROLLED_BACK]
    for a, b in zip(path, path[1:]):
        check_transition(a, b)


def test_every_other_transition_is_rejected():
    for a, b in itertools.product(S, S):
        if b in ALLOWED_TRANSITIONS[a]:
            check_transition(a, b)
        else:
            with pytest.raises(InvalidTransitionError):
                check_transition(a, b)


def test_terminal_states_and_critical_skips():
    assert TERMINAL_STATES == {S.REJECTED, S.FAILED, S.ROLLED_BACK}
    for terminal in TERMINAL_STATES:
        assert all(t not in ALLOWED_TRANSITIONS[terminal] for t in S)
    for skip in [(S.PLANNED, S.PROMOTED), (S.PROPOSED, S.VALIDATED), (S.VALIDATING, S.APPROVED), (S.VALIDATED, S.PROMOTED),
                 (S.SANDBOXED, S.APPROVED), (S.DISCOVERED, S.PROMOTED), (S.PROMOTED, S.APPROVED), (S.FAILED, S.PROMOTED), (S.REJECTED, S.APPROVED)]:
        with pytest.raises(InvalidTransitionError):
            check_transition(*skip)


def test_risk_ordering():
    assert [r.rank for r in (RiskLevel.LOW, RiskLevel.MEDIUM, RiskLevel.HIGH, RiskLevel.CRITICAL)] == [0, 1, 2, 3]
    assert max_risk([RiskLevel.LOW, RiskLevel.HIGH, RiskLevel.MEDIUM]) is RiskLevel.HIGH and max_risk([]) is RiskLevel.LOW


def test_request_validation_and_normalization():
    r = ImprovementRequest(goal="  Improve   the web research subsystem  ", scope=[" app/web ", ""], constraints=["no new deps"])
    assert r.goal == "Improve the web research subsystem" and r.scope == ["app/web"] and r.requested_by == "user"
    assert isinstance(r.id, uuid.UUID) and r.created_at.tzinfo is not None
    for bad in (dict(goal="short"), dict(goal="x" * 1001), dict(goal="a valid goal here", requested_by=" "),
                dict(goal="a valid goal here", scope=["x" * 400]), dict(goal="a valid goal here", scope=["a"] * 21),
                dict(goal="a valid goal here", created_at=datetime(2026, 1, 1))):
        with pytest.raises(ValidationError):
            ImprovementRequest(**bad)


def test_change_file_shape_rules():
    ChangeFile(path="a.py", operation=Op.ADD, proposed_hash=H1)
    ChangeFile(path="a.py", operation=Op.MODIFY, original_hash=H1, proposed_hash=H2)
    ChangeFile(path="a.py", operation=Op.DELETE, original_hash=H1)
    for bad in (dict(operation=Op.ADD), dict(operation=Op.ADD, proposed_hash=H1, original_hash=H2), dict(operation=Op.MODIFY, original_hash=H1),
                dict(operation=Op.MODIFY, proposed_hash=H1), dict(operation=Op.DELETE), dict(operation=Op.DELETE, original_hash=H1, proposed_hash=H2),
                dict(operation=Op.ADD, proposed_hash="nothex"), dict(operation=Op.ADD, proposed_hash=H1.upper())):
        with pytest.raises(ValidationError):
            ChangeFile(path="a.py", **bad)
    with pytest.raises(ValidationError):
        ChangeFile(path="", operation=Op.ADD, proposed_hash=H1)


def test_change_set_rules():
    f = lambda p: ChangeFile(path=p, operation=Op.ADD, proposed_hash=H1)  # noqa: E731
    assert ChangeSet(files=[f("a.py"), f("b.py")]).paths == ["a.py", "b.py"]
    with pytest.raises(ValidationError):
        ChangeSet(files=[])
    with pytest.raises(ValidationError):
        ChangeSet(files=[f("a.py"), f("a.py")])
    with pytest.raises(ValidationError):
        ChangeSet(files=[f(f"f{i}.py") for i in range(51)])


def test_run_serialization_roundtrip_and_no_content_fields():
    req = ImprovementRequest(goal="a perfectly fine goal")
    run = ImprovementRun(id=req.id, state=S.DISCOVERED, request=req)
    data = json.loads(run.model_dump_json())
    assert data["state"] == "discovered" and ImprovementRun.model_validate(data) == run
    assert run.risk_level is None and run.created_at.tzinfo is not None
    assert "content" not in ChangeFile.model_fields and "new_content" not in ChangeFile.model_fields
