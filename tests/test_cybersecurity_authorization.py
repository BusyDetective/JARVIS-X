from __future__ import annotations

from datetime import timedelta

import pytest

import app.cybersecurity.authorization as auth_mod
from app.cybersecurity.authorization import authorize, authorize_redirect
from app.cybersecurity.errors import InvalidTarget, UnsafeTarget
from app.cybersecurity.models import AuthorizedScope, CyberOperationRequest, OperationType, utcnow
from app.cybersecurity.scope import ScopeStore
from tests.web_helpers import PUBLIC_IP, FakeResolver

PRIVATE_IP = "10.0.0.5"
LOOPBACK_IP = "127.0.0.1"
METADATA_IP = "169.254.169.254"


def _scope(**overrides):
    defaults = dict(
        id="s1",
        domains=("example.com",),
        operation_types=(OperationType.SUBDOMAIN_ENUM, OperationType.ALIVE_CHECK, OperationType.ENDPOINT_DISCOVERY),
        expires_at=utcnow() + timedelta(days=1),
        source="unit test",
        max_targets=5,
    )
    defaults.update(overrides)
    return AuthorizedScope(**defaults)


@pytest.fixture
def fake_resolver(monkeypatch):
    """Swap SystemResolver for a FakeResolver everywhere authorization.py
    (directly, for the local-lab path) and urls.py (via UrlValidator, for
    the public path) construct one, so no real DNS lookups happen in
    unit tests."""
    import app.web.urls as urls_mod

    resolver = FakeResolver(default=[PUBLIC_IP])
    monkeypatch.setattr(auth_mod, "SystemResolver", lambda: resolver)
    monkeypatch.setattr(urls_mod, "SystemResolver", lambda: resolver)
    return resolver


async def test_public_target_in_scope_is_authorized(fake_resolver):
    scope = _scope()
    store = ScopeStore([scope])
    req = CyberOperationRequest(operation=OperationType.SUBDOMAIN_ENUM, target="example.com")
    result = await authorize(req, store)
    assert result.domain == "example.com"
    assert result.addresses == (PUBLIC_IP,)


async def test_public_scope_rejects_private_resolved_address(monkeypatch):
    import app.web.urls as urls_mod
    resolver = FakeResolver(default=[PRIVATE_IP])
    monkeypatch.setattr(urls_mod, "SystemResolver", lambda: resolver)

    scope = _scope()
    store = ScopeStore([scope])
    req = CyberOperationRequest(operation=OperationType.SUBDOMAIN_ENUM, target="example.com")
    with pytest.raises(UnsafeTarget):
        await authorize(req, store)


async def test_public_scope_rejects_metadata_address(monkeypatch):
    import app.web.urls as urls_mod
    resolver = FakeResolver(default=[METADATA_IP])
    monkeypatch.setattr(urls_mod, "SystemResolver", lambda: resolver)

    scope = _scope()
    store = ScopeStore([scope])
    req = CyberOperationRequest(operation=OperationType.ALIVE_CHECK, target="example.com")
    with pytest.raises(UnsafeTarget):
        await authorize(req, store)


async def test_local_lab_scope_allows_address_inside_its_own_ip_networks(fake_resolver):
    fake_resolver.default = [PRIVATE_IP]
    scope = _scope(
        domains=("lab.internal",),
        ip_networks=("10.0.0.0/24",),
        allow_private_targets=True,
    )
    store = ScopeStore([scope])
    req = CyberOperationRequest(operation=OperationType.SUBDOMAIN_ENUM, target="lab.internal")
    result = await authorize(req, store)
    assert result.addresses == (PRIVATE_IP,)


async def test_local_lab_scope_still_rejects_address_outside_its_own_ip_networks(fake_resolver):
    fake_resolver.default = [METADATA_IP]  # resolves somewhere NOT in the declared ip_networks
    scope = _scope(
        domains=("lab.internal",),
        ip_networks=("10.0.0.0/24",),
        allow_private_targets=True,
    )
    store = ScopeStore([scope])
    req = CyberOperationRequest(operation=OperationType.SUBDOMAIN_ENUM, target="lab.internal")
    with pytest.raises(UnsafeTarget):
        await authorize(req, store)


async def test_local_lab_scope_without_ip_networks_is_rejected(fake_resolver):
    scope = _scope(domains=("lab.internal",), ip_networks=(), allow_private_targets=True)
    store = ScopeStore([scope])
    req = CyberOperationRequest(operation=OperationType.SUBDOMAIN_ENUM, target="lab.internal")
    with pytest.raises(UnsafeTarget):
        await authorize(req, store)


async def test_malformed_resolution_raises_invalid_target(monkeypatch):
    class EmptyResolver:
        async def resolve(self, host, port):
            return []

    scope = _scope(domains=("lab.internal",), ip_networks=("10.0.0.0/24",), allow_private_targets=True)
    monkeypatch.setattr(auth_mod, "SystemResolver", lambda: EmptyResolver())
    store = ScopeStore([scope])
    req = CyberOperationRequest(operation=OperationType.SUBDOMAIN_ENUM, target="lab.internal")
    with pytest.raises(InvalidTarget):
        await authorize(req, store)


async def test_redirect_within_same_domain_is_allowed(fake_resolver):
    scope = _scope()
    store = ScopeStore([scope])
    req = CyberOperationRequest(operation=OperationType.ENDPOINT_DISCOVERY, target="example.com")
    authorized = await authorize(req, store)
    url = await authorize_redirect(authorized, "https://example.com/some/path")
    assert "example.com" in url


async def test_redirect_to_a_different_domain_is_rejected(fake_resolver):
    scope = _scope()
    store = ScopeStore([scope])
    req = CyberOperationRequest(operation=OperationType.ENDPOINT_DISCOVERY, target="example.com")
    authorized = await authorize(req, store)
    with pytest.raises(UnsafeTarget):
        await authorize_redirect(authorized, "https://attacker.example.net/steal")


async def test_redirect_to_metadata_address_on_same_domain_is_rejected(fake_resolver):
    """Even if the host NAME matches, the redirect target's resolved
    address still has to be safe — a domain can't escape scope by having
    DNS point itself at a metadata/private address either."""
    resolver = fake_resolver
    resolver.mapping["example.com"] = [PUBLIC_IP]

    scope = _scope()
    store = ScopeStore([scope])
    req = CyberOperationRequest(operation=OperationType.ENDPOINT_DISCOVERY, target="example.com")
    authorized = await authorize(req, store)

    resolver.mapping["example.com"] = [METADATA_IP]  # DNS changes between the first check and the redirect
    with pytest.raises(UnsafeTarget):
        await authorize_redirect(authorized, "https://example.com/moved")
