from __future__ import annotations

import json
from datetime import timedelta
from pathlib import Path

import pytest

from app.cybersecurity.errors import AuthorizationExpired, NoScopeConfigured, OperationLimitExceeded, ScopeViolation
from app.cybersecurity.models import AuthorizedScope, OperationType, utcnow
from app.cybersecurity.scope import ScopeStore


def _scope(**overrides):
    defaults = dict(
        id="s1",
        domains=("example.com",),
        operation_types=(OperationType.SUBDOMAIN_ENUM, OperationType.ALIVE_CHECK),
        expires_at=utcnow() + timedelta(days=1),
        source="unit test",
        max_targets=1,
    )
    defaults.update(overrides)
    return AuthorizedScope(**defaults)


def test_empty_store_fails_closed():
    store = ScopeStore([])
    with pytest.raises(NoScopeConfigured):
        store.find_for_domain("example.com", OperationType.SUBDOMAIN_ENUM)


def test_target_outside_scope_is_rejected():
    store = ScopeStore([_scope()])
    with pytest.raises(ScopeViolation):
        store.find_for_domain("not-example.com", OperationType.SUBDOMAIN_ENUM)


def test_operation_outside_scope_is_rejected():
    store = ScopeStore([_scope()])
    with pytest.raises(ScopeViolation):
        store.find_for_domain("example.com", OperationType.REPORT_GENERATION)


def test_expired_scope_raises_authorization_expired_not_scope_violation():
    store = ScopeStore([_scope(expires_at=utcnow() - timedelta(seconds=1))])
    with pytest.raises(AuthorizationExpired):
        store.find_for_domain("example.com", OperationType.SUBDOMAIN_ENUM)


def test_matching_unexpired_scope_is_returned():
    scope = _scope()
    store = ScopeStore([scope])
    assert store.find_for_domain("example.com", OperationType.SUBDOMAIN_ENUM).id == "s1"


def test_a_user_supplied_target_is_never_implicitly_in_scope():
    """No scope configured at all => nothing is ever authorized, no matter
    how innocuous-looking the domain is."""
    store = ScopeStore([])
    for domain in ("example.com", "google.com", "my-own-authorized-test.local"):
        with pytest.raises(NoScopeConfigured):
            store.find_for_domain(domain, OperationType.ALIVE_CHECK)


def test_record_usage_enforces_max_targets():
    scope = _scope(domains=("a.example.com", "b.example.com"), max_targets=1)
    store = ScopeStore([scope])
    store.record_usage(scope, "a.example.com")
    with pytest.raises(OperationLimitExceeded):
        store.record_usage(scope, "b.example.com")


def test_record_usage_is_idempotent_for_the_same_domain():
    scope = _scope(max_targets=1)
    store = ScopeStore([scope])
    store.record_usage(scope, "example.com")
    store.record_usage(scope, "example.com")  # must not consume quota twice


def test_from_file_fails_closed_on_missing_file(tmp_path: Path):
    with pytest.raises(NoScopeConfigured):
        ScopeStore.from_file(tmp_path / "does-not-exist.json")


def test_from_file_fails_closed_on_malformed_json(tmp_path: Path):
    f = tmp_path / "scope.json"
    f.write_text("{not valid json", encoding="utf-8")
    with pytest.raises(NoScopeConfigured):
        ScopeStore.from_file(f)


def test_from_file_loads_valid_entries(tmp_path: Path):
    f = tmp_path / "scope.json"
    f.write_text(
        json.dumps([{
            "id": "s1",
            "domains": ["example.com"],
            "operation_types": ["subdomain_enum"],
            "expires_at": (utcnow() + timedelta(days=1)).isoformat(),
            "source": "test",
        }]),
        encoding="utf-8",
    )
    store = ScopeStore.from_file(f)
    assert len(store) == 1
