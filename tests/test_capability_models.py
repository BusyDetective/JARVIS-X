from __future__ import annotations

import json

import pytest
from pydantic import ValidationError

from app.capabilities.models import (
    Capability,
    CapabilityCategory,
    CapabilitySource,
    max_permission,
)
from app.security.permissions import PermissionLevel


def test_valid_capability_defaults():
    c = Capability(id="core", name="Core")
    assert c.version == "1.0.0" and c.enabled is True
    assert c.category is CapabilityCategory.OTHER and c.source is CapabilitySource.LOCAL
    assert c.max_permission is PermissionLevel.SAFE
    assert c.tool_names == () and c.depends_on == () and c.metadata == {}


def test_enums():
    assert {c.value for c in CapabilityCategory} == {
        "core", "information", "productivity", "development", "system", "integration", "other",
    }
    assert {s.value for s in CapabilitySource} == {"builtin", "local", "plugin", "future_external"}
    assert Capability(id="a", name="A", category="system", source="builtin").category is CapabilityCategory.SYSTEM
    with pytest.raises(ValidationError):
        Capability(id="a", name="A", category="browser")
    with pytest.raises(ValidationError):
        Capability(id="a", name="A", source="marketplace")


@pytest.mark.parametrize("version", ["1", "1.0", "v1.0.0", "1.0.0.0", "", "latest"])
def test_invalid_versions(version):
    with pytest.raises(ValidationError):
        Capability(id="a", name="A", version=version)


@pytest.mark.parametrize("version", ["0.1.0", "10.20.30", "1.0.0-beta.1"])
def test_valid_versions(version):
    assert Capability(id="a", name="A", version=version).version == version


@pytest.mark.parametrize("cid", ["", "Core", "1abc", "has space", "a-b", "a/b"])
def test_invalid_ids(cid):
    with pytest.raises(ValidationError):
        Capability(id=cid, name="A")


def test_invalid_metadata_fields():
    with pytest.raises(ValidationError):
        Capability(id="a", name="  ")
    with pytest.raises(ValidationError):
        Capability(id="a", name="A", tool_names=("x", "x"))
    with pytest.raises(ValidationError):
        Capability(id="a", name="A", tool_names=(" ",))
    with pytest.raises(ValidationError):
        Capability(id="a", name="A", depends_on=("a",))
    with pytest.raises(ValidationError):
        Capability(id="a", name="A", depends_on=("b", "b"))
    with pytest.raises(ValidationError):
        Capability(id="a", name="A", depends_on=("Bad Id",))
    with pytest.raises(ValidationError):
        Capability(id="a", name="A", max_permission="root")


def test_frozen_and_enabled_state_via_copy():
    c = Capability(id="a", name="A")
    with pytest.raises(ValidationError):
        c.enabled = False
    assert c.model_copy(update={"enabled": False}).enabled is False and c.enabled is True


def test_serialization_roundtrip():
    c = Capability(
        id="a", name="A", category=CapabilityCategory.CORE, source=CapabilitySource.BUILTIN,
        tool_names=("t1",), depends_on=("b",), metadata={"k": [1]}, max_permission=PermissionLevel.CONFIRM,
    )
    data = json.loads(c.model_dump_json())
    assert data["category"] == "core" and data["max_permission"] == "confirm"
    assert Capability.model_validate(data) == c


def test_max_permission_ordering():
    L = PermissionLevel
    assert max_permission([]) is L.SAFE
    assert max_permission([L.SAFE, L.DANGEROUS, L.CONFIRM]) is L.DANGEROUS
    assert max_permission([L.DANGEROUS, L.BLOCKED]) is L.BLOCKED
