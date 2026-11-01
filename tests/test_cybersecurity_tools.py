from __future__ import annotations

from datetime import timedelta

import pytest

from app.cybersecurity import adapter
from app.cybersecurity.models import AuthorizedScope, CyberLimits, OperationType, utcnow
from app.cybersecurity.scope import ScopeStore
from app.cybersecurity.tools import (
    ALL_TOOL_CLASSES,
    AliveCheckTool,
    CyberReportTool,
    RiskScoringTool,
    SubdomainEnumTool,
)
from app.security.permissions import PermissionLevel


def _scope(**overrides):
    defaults = dict(
        id="s1",
        domains=("example.com",),
        operation_types=tuple(OperationType),
        expires_at=utcnow() + timedelta(days=1),
        source="unit test",
        max_targets=5,
    )
    defaults.update(overrides)
    return AuthorizedScope(**defaults)


@pytest.fixture(autouse=True)
def _reset_adapter_state():
    adapter._cache = None
    yield
    adapter._cache = None


def test_network_tools_default_to_dangerous_permission():
    for cls in (SubdomainEnumTool, AliveCheckTool):
        assert cls.permission_level == PermissionLevel.DANGEROUS


def test_readonly_tools_are_confirm_not_safe():
    """Even operations with no new network activity are never SAFE here —
    §6: never classify anything as safe merely because it's 'recon'."""
    for cls in (RiskScoringTool, CyberReportTool):
        assert cls.permission_level == PermissionLevel.CONFIRM
        assert cls.permission_level != PermissionLevel.SAFE


def test_no_tool_is_ever_safe_or_blocked_by_default():
    for cls in ALL_TOOL_CLASSES:
        assert cls.permission_level in (PermissionLevel.CONFIRM, PermissionLevel.DANGEROUS)


async def test_unauthorized_target_returns_structured_denial_not_an_exception():
    store = ScopeStore([])  # nothing configured — fail closed
    tool = SubdomainEnumTool(store, CyberLimits())
    args = tool.args_model(domain="example.com")
    result = await tool.execute(args)
    assert result["authorized"] is False
    assert "reason" in result


async def test_out_of_scope_domain_returns_scope_violation_reason():
    store = ScopeStore([_scope(domains=("only-this.com",))])
    tool = SubdomainEnumTool(store, CyberLimits())
    args = tool.args_model(domain="example.com")
    result = await tool.execute(args)
    assert result["authorized"] is False


async def test_successful_result_carries_untrusted_notice(monkeypatch):
    from types import SimpleNamespace

    async def _fake_authorize(request, scope_store):
        from app.cybersecurity.authorization import AuthorizedTarget
        scope = scope_store.find_for_domain(request.target, request.operation)
        return AuthorizedTarget(domain=request.target, scope=scope, addresses=("93.184.216.34",))

    monkeypatch.setattr(adapter, "authorize", _fake_authorize)
    engine = SimpleNamespace(get_subdomains=lambda domain: ["a.example.com"])
    monkeypatch.setattr(adapter._Engine, "get", classmethod(lambda cls: engine))

    store = ScopeStore([_scope()])
    tool = SubdomainEnumTool(store, CyberLimits())
    args = tool.args_model(domain="example.com")
    result = await tool.execute(args)

    assert "notice" in result
    assert "UNTRUSTED DATA" in result["notice"]
    assert "data" in result


async def test_secrets_in_discovered_content_are_redacted(monkeypatch):
    from types import SimpleNamespace

    async def _fake_authorize(request, scope_store):
        from app.cybersecurity.authorization import AuthorizedTarget
        scope = scope_store.find_for_domain(request.target, request.operation)
        return AuthorizedTarget(domain=request.target, scope=scope, addresses=("93.184.216.34",))

    monkeypatch.setattr(adapter, "authorize", _fake_authorize)
    # A page title containing something that LOOKS like a leaked AWS key —
    # the kind of thing a real scan could legitimately encounter.
    engine = SimpleNamespace(
        get_subdomains=lambda domain: ["a.example.com"],
        check_alive=lambda subs: [
            {"url": "https://a.example.com", "status": 200, "title": "AKIAABCDEFGHIJKLMNOP leaked here"}
        ],
    )
    monkeypatch.setattr(adapter._Engine, "get", classmethod(lambda cls: engine))

    store = ScopeStore([_scope()])
    tool = AliveCheckTool(store, CyberLimits())
    args = tool.args_model(domain="example.com")
    result = await tool.execute(args)

    serialized = str(result)
    assert "AKIAABCDEFGHIJKLMNOP" not in serialized
    assert "REDACTED" in serialized


async def test_unexpected_exception_does_not_leak_internal_detail(monkeypatch):
    async def _boom(request, scope_store):
        raise RuntimeError("leaking /etc/passwd contents here")

    monkeypatch.setattr(adapter, "authorize", _boom)
    store = ScopeStore([_scope()])
    tool = SubdomainEnumTool(store, CyberLimits())
    args = tool.args_model(domain="example.com")
    result = await tool.execute(args)

    assert result["authorized"] is False
    assert "/etc/passwd" not in str(result)
    assert "unexpectedly" in result["reason"]


async def test_output_is_bounded_by_max_tool_output_chars(monkeypatch):
    from types import SimpleNamespace

    async def _fake_authorize(request, scope_store):
        from app.cybersecurity.authorization import AuthorizedTarget
        scope = scope_store.find_for_domain(request.target, request.operation)
        return AuthorizedTarget(domain=request.target, scope=scope, addresses=("93.184.216.34",))

    monkeypatch.setattr(adapter, "authorize", _fake_authorize)
    engine = SimpleNamespace(get_subdomains=lambda domain: [f"h{i}.example.com" for i in range(200)])
    monkeypatch.setattr(adapter._Engine, "get", classmethod(lambda cls: engine))

    store = ScopeStore([_scope()])
    tiny_limits = CyberLimits(max_subdomains=200, max_findings_per_result=200, max_tool_output_chars=1000)
    tool = SubdomainEnumTool(store, tiny_limits)
    args = tool.args_model(domain="example.com")
    result = await tool.execute(args)

    assert result.get("truncated_output") is True
