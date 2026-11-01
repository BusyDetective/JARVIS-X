from __future__ import annotations

from app.capabilities.models import Capability, CapabilityCategory


class CapabilityError(Exception):
    """Base class for capability framework errors."""


class DuplicateCapabilityError(CapabilityError):
    pass


class CapabilityNotFoundError(CapabilityError, LookupError):
    pass


class CapabilityRegistry:
    """In-memory catalog of Capability declarations (descriptive only).

    It groups and describes tools but never executes or looks them up —
    ToolRegistry remains the sole authority for tool lookup/execution.
    Dependency and permission policy lives in CapabilityManager; this class
    enforces only structural uniqueness. Nothing is ever silently
    overwritten. All listings are sorted by id (deterministic).
    """

    def __init__(self) -> None:
        self._caps: dict[str, Capability] = {}

    def register(self, capability: Capability) -> None:
        if capability.id in self._caps:
            raise DuplicateCapabilityError(f"Capability '{capability.id}' is already registered")
        for tool_name in capability.tool_names:
            owner = self.find_by_tool(tool_name)
            if owner is not None:
                raise DuplicateCapabilityError(
                    f"Tool '{tool_name}' already belongs to capability '{owner.id}'"
                )
        self._caps[capability.id] = capability

    def unregister(self, capability_id: str) -> Capability:
        cap = self._require(capability_id)
        del self._caps[capability_id]
        return cap

    def get(self, capability_id: str) -> Capability | None:
        return self._caps.get(capability_id)

    def has(self, capability_id: str) -> bool:
        return capability_id in self._caps

    def list(self, enabled_only: bool = False) -> list[Capability]:
        caps = sorted(self._caps.values(), key=lambda c: c.id)
        return [c for c in caps if c.enabled] if enabled_only else caps

    def enable(self, capability_id: str) -> Capability:
        return self._set_enabled(capability_id, True)

    def disable(self, capability_id: str) -> Capability:
        return self._set_enabled(capability_id, False)

    def is_enabled(self, capability_id: str) -> bool:
        cap = self._caps.get(capability_id)
        return cap is not None and cap.enabled

    def find_by_category(self, category: CapabilityCategory) -> list[Capability]:
        return [c for c in self.list() if c.category == category]

    def find_by_tool(self, tool_name: str) -> Capability | None:
        for cap in self.list():
            if tool_name in cap.tool_names:
                return cap
        return None

    def _require(self, capability_id: str) -> Capability:
        cap = self._caps.get(capability_id)
        if cap is None:
            raise CapabilityNotFoundError(f"Capability '{capability_id}' is not registered")
        return cap

    def _set_enabled(self, capability_id: str, enabled: bool) -> Capability:
        cap = self._require(capability_id)
        updated = cap.model_copy(update={"enabled": enabled})
        self._caps[capability_id] = updated
        return updated
