from __future__ import annotations

from app.providers.schemas import ToolSchema
from app.tools.base import Tool


class ToolRegistry:
    """Holds the tools available for a given orchestrator run.

    The orchestrator never imports a concrete Tool implementation
    directly — it only ever asks a registry for one by name, or for the
    full set of schemas to offer the model. This keeps the orchestrator
    decoupled from whatever tools happen to exist, and lets callers build
    a registry scoped to exactly the tools a given run should have access
    to (e.g. a restricted set for an untrusted context).

    ENABLED STATE: a registered tool can be disabled (by the
    CapabilityManager, when its capability is disabled). A disabled tool is
    unavailable, not merely hidden: `get()` returns None for it (the
    orchestrator already reports that as "not available" and never
    executes it) and `schemas()`/`list_tools()` omit it. Because the
    orchestrator resolves the tool through `get()` at execution time, a
    tool disabled mid-run cannot execute either. Tools are enabled by
    default, so registries that never touch this behave exactly as before.
    """

    def __init__(self) -> None:
        self._tools: dict[str, Tool] = {}
        self._disabled: set[str] = set()

    def register(self, tool: Tool) -> None:
        if tool.name in self._tools:
            raise ValueError(f"Tool '{tool.name}' is already registered")
        self._tools[tool.name] = tool

    def unregister(self, name: str) -> None:
        if name not in self._tools:
            raise KeyError(f"Tool '{name}' is not registered")
        del self._tools[name]
        self._disabled.discard(name)

    def get(self, name: str, include_disabled: bool = False) -> Tool | None:
        if name in self._disabled and not include_disabled:
            return None
        return self._tools.get(name)

    def has(self, name: str) -> bool:
        """True if registered, regardless of enabled state."""
        return name in self._tools

    def set_enabled(self, name: str, enabled: bool) -> None:
        if name not in self._tools:
            raise KeyError(f"Tool '{name}' is not registered")
        if enabled:
            self._disabled.discard(name)
        else:
            self._disabled.add(name)

    def is_enabled(self, name: str) -> bool:
        return name in self._tools and name not in self._disabled

    def list_tools(self, include_disabled: bool = False) -> list[Tool]:
        return [
            t for t in self._tools.values() if include_disabled or t.name not in self._disabled
        ]

    def schemas(self) -> list[ToolSchema]:
        """Normalized ToolSchemas for every ENABLED tool, ready to pass to
        `AIProvider.generate_with_tools` / `ModelRouter.generate_with_tools`."""
        return [tool.to_tool_schema() for tool in self.list_tools()]
