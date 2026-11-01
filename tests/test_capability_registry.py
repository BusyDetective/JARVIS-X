from __future__ import annotations

import pytest

from app.capabilities.models import Capability, CapabilityCategory
from app.capabilities.registry import (
    CapabilityNotFoundError,
    CapabilityRegistry,
    DuplicateCapabilityError,
)


def cap(cid, **kw):
    return Capability(id=cid, name=cid.title(), **kw)


def test_register_get_list_sorted():
    r = CapabilityRegistry()
    for cid in ("zeta", "alpha", "mid"):
        r.register(cap(cid))
    assert [c.id for c in r.list()] == ["alpha", "mid", "zeta"]
    assert r.get("mid").id == "mid" and r.get("nope") is None
    assert r.has("alpha") and not r.has("nope")


def test_duplicate_id_is_rejected_not_overwritten():
    r = CapabilityRegistry()
    r.register(cap("a", description="first"))
    with pytest.raises(DuplicateCapabilityError):
        r.register(cap("a", description="second"))
    assert r.get("a").description == "first"


def test_tool_can_belong_to_only_one_capability():
    r = CapabilityRegistry()
    r.register(cap("a", tool_names=("t",)))
    with pytest.raises(DuplicateCapabilityError):
        r.register(cap("b", tool_names=("t",)))
    assert not r.has("b")


def test_unregister():
    r = CapabilityRegistry()
    r.register(cap("a"))
    assert r.unregister("a").id == "a" and r.list() == []
    with pytest.raises(CapabilityNotFoundError):
        r.unregister("a")


def test_enable_disable_and_filter():
    r = CapabilityRegistry()
    r.register(cap("a"))
    r.register(cap("b", enabled=False))
    assert r.is_enabled("a") and not r.is_enabled("b") and not r.is_enabled("missing")
    assert [c.id for c in r.list(enabled_only=True)] == ["a"]
    r.disable("a")
    r.enable("b")
    assert [c.id for c in r.list(enabled_only=True)] == ["b"]
    with pytest.raises(CapabilityNotFoundError):
        r.enable("missing")
    with pytest.raises(CapabilityNotFoundError):
        r.disable("missing")


def test_find_by_category_and_tool():
    r = CapabilityRegistry()
    r.register(cap("a", category=CapabilityCategory.CORE, tool_names=("t1", "t2")))
    r.register(cap("b", category=CapabilityCategory.SYSTEM, tool_names=("t3",)))
    r.register(cap("c", category=CapabilityCategory.CORE))
    assert [c.id for c in r.find_by_category(CapabilityCategory.CORE)] == ["a", "c"]
    assert r.find_by_category(CapabilityCategory.INTEGRATION) == []
    assert r.find_by_tool("t2").id == "a" and r.find_by_tool("t3").id == "b"
    assert r.find_by_tool("nope") is None


def test_registries_are_isolated():
    a, b = CapabilityRegistry(), CapabilityRegistry()
    a.register(cap("x"))
    assert b.list() == []
