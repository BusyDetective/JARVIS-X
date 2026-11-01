"""Authorization + network-safety boundary for the cybersecurity specialist.

Every target reaches the vendored recon engine ONLY through `authorize()`
below. It never trusts a domain string by itself: a scope must explicitly
cover it, and the domain's resolved addresses must be safe to reach —
reusing the Phase 6 SSRF boundary (`app.web.urls.UrlValidator`) rather than
reimplementing address-safety checks. A local-lab scope
(`allow_private_targets=True`) is the only way to reach a private address,
and even then only within that scope's explicit `ip_networks`.
"""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass

from app.cybersecurity.errors import InvalidTarget, UnsafeTarget
from app.cybersecurity.models import AuthorizedScope, CyberOperationRequest
from app.cybersecurity.scope import ScopeStore
from app.web.errors import InvalidWebURL, UnsafeWebTarget, safe_url
from app.web.urls import SystemResolver, UrlValidator


@dataclass(frozen=True)
class AuthorizedTarget:
    domain: str
    scope: AuthorizedScope
    addresses: tuple[str, ...]


async def authorize(request: CyberOperationRequest, scope_store: ScopeStore) -> AuthorizedTarget:
    """Resolve + validate `request.target` for `request.operation`.
    Raises NoScopeConfigured / ScopeViolation / AuthorizationExpired
    (from scope.py) or InvalidTarget / UnsafeTarget (from this module)."""
    scope = scope_store.find_for_domain(request.target, request.operation)
    domain = request.target

    if scope.allow_private_targets:
        addresses = await _resolve_within_lab_scope(domain, scope)
    else:
        try:
            validated = await UrlValidator().validate(f"https://{domain}/")
        except InvalidWebURL as exc:
            raise InvalidTarget(str(exc)) from None
        except UnsafeWebTarget as exc:
            raise UnsafeTarget(str(exc)) from None
        addresses = validated.addresses

    # Network/DNS validation succeeded — this target now counts against
    # the scope's max_targets quota (idempotent for repeat calls).
    scope_store.record_usage(scope, domain)

    return AuthorizedTarget(domain=domain, scope=scope, addresses=addresses)


async def _resolve_within_lab_scope(domain: str, scope: AuthorizedScope) -> tuple[str, ...]:
    networks = [ipaddress.ip_network(n, strict=False) for n in scope.ip_networks]
    if not networks:
        raise UnsafeTarget("scope allows private targets but lists no ip_networks to constrain them")
    try:
        raw_addresses = await SystemResolver().resolve(domain, 443)
    except InvalidWebURL as exc:
        raise InvalidTarget(str(exc)) from None
    if not raw_addresses:
        raise InvalidTarget(f"could not resolve host {domain}")
    for addr in raw_addresses:
        ip = ipaddress.ip_address(addr.split("%", 1)[0])
        if not any(ip in net for net in networks):
            raise UnsafeTarget(
                f"host {domain} resolved to an address outside this scope's authorized ip_networks"
            )
    return tuple(raw_addresses)


async def authorize_redirect(authorized: AuthorizedTarget, candidate_url: str) -> str:
    """Called by the endpoint-discovery adapter before following any
    redirect or discovered link. A target cannot escape its authorized
    scope through a redirect, DNS change, or alternate host — the
    candidate must resolve to the SAME domain this request was authorized
    for, and pass the same address-safety check as the original target.
    Returns the normalized URL on success."""
    from urllib.parse import urlsplit

    parts = urlsplit(candidate_url)
    host = (parts.hostname or "").rstrip(".").lower()
    if host != authorized.domain:
        raise UnsafeTarget(
            f"redirect target {safe_url(candidate_url)} leaves the authorized domain {authorized.domain}"
        )

    if authorized.scope.allow_private_targets:
        await _resolve_within_lab_scope(host, authorized.scope)
        return candidate_url

    try:
        validated = await UrlValidator().validate(candidate_url)
    except InvalidWebURL as exc:
        raise InvalidTarget(str(exc)) from None
    except UnsafeWebTarget as exc:
        raise UnsafeTarget(str(exc)) from None
    return validated.url
