from __future__ import annotations

from datetime import datetime, timedelta

import pytest
from pydantic import ValidationError

from app.cybersecurity.models import (
    AuthorizedScope,
    CyberLimits,
    CyberOperationRequest,
    OperationType,
    utcnow,
)


def _scope(**overrides):
    defaults = dict(
        id="s1",
        domains=("example.com",),
        operation_types=(OperationType.SUBDOMAIN_ENUM,),
        expires_at=utcnow() + timedelta(days=1),
        source="unit test",
    )
    defaults.update(overrides)
    return AuthorizedScope(**defaults)


def test_scope_normalizes_domain_case_and_scheme():
    s = _scope(domains=("HTTPS://Example.COM/path",))
    assert s.domains == ("example.com",)


def test_scope_requires_at_least_one_target():
    with pytest.raises(ValidationError):
        AuthorizedScope(
            id="s1", domains=(), ip_networks=(), operation_types=(OperationType.SUBDOMAIN_ENUM,),
            expires_at=utcnow() + timedelta(days=1), source="x",
        )


def test_scope_rejects_naive_datetime():
    with pytest.raises(ValidationError):
        AuthorizedScope(
            id="s1", domains=("example.com",), operation_types=(OperationType.SUBDOMAIN_ENUM,),
            expires_at=datetime.now(), source="x",  # naive — no tzinfo
        )


def test_scope_rejects_duplicate_operation_types():
    with pytest.raises(ValidationError):
        _scope(operation_types=(OperationType.SUBDOMAIN_ENUM, OperationType.SUBDOMAIN_ENUM))


def test_scope_rejects_malformed_ip_network():
    with pytest.raises(ValidationError):
        _scope(domains=(), ip_networks=("not-a-cidr",), allow_private_targets=True)


def test_scope_is_expired():
    expired = _scope(expires_at=utcnow() - timedelta(seconds=1))
    assert expired.is_expired() is True
    fresh = _scope(expires_at=utcnow() + timedelta(days=1))
    assert fresh.is_expired() is False


def test_operation_request_normalizes_target():
    req = CyberOperationRequest(operation=OperationType.ALIVE_CHECK, target="HTTPS://Example.COM/")
    assert req.target == "example.com"


def test_operation_request_rejects_malformed_target():
    with pytest.raises(ValidationError):
        CyberOperationRequest(operation=OperationType.ALIVE_CHECK, target="not a domain!!")


def test_limits_clamp_prefers_requested_within_ceiling():
    limits = CyberLimits()
    assert limits.clamp(10, 50) == 10


def test_limits_clamp_caps_at_ceiling_regardless_of_request():
    limits = CyberLimits()
    assert limits.clamp(10_000, 50) == 50


def test_limits_clamp_uses_ceiling_when_nothing_requested():
    limits = CyberLimits()
    assert limits.clamp(None, 50) == 50


def test_limits_are_frozen():
    limits = CyberLimits()
    with pytest.raises(ValidationError):
        limits.max_hosts = 999  # type: ignore[misc]
