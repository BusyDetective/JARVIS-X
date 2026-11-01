from __future__ import annotations

import logging
from typing import Sequence

from app.capabilities.models import (
    PERMISSION_RANK,
    Capability,
    CapabilityInfo,
    CapabilitySnapshot,
    CapabilitySource,
    DependencyStatus,
    ToolInfo,
    UsabilityReport,
    is_valid_version,
    max_permission,
)
from app.capabilities.registry import (
    CapabilityError,
    CapabilityNotFoundError,
    CapabilityRegistry,
    DuplicateCapabilityError,
)
from app.config.settings import settings
from app.providers.schemas import ToolSchema
from app.security.permissions import PermissionLevel, requires_approval
from app.tools.base import Tool
from app.tools.registry import ToolRegistry

logger = logging.getLogger(__name__)

# Only these can be installed in Phase 5. PLUGIN / FUTURE_EXTERNAL exist in
# the enum for later; nothing external may register itself.
INSTALLABLE_SOURCES = frozenset({CapabilitySource.BUILTIN, CapabilitySource.LOCAL})


class CapabilityValidationError(CapabilityError):
    pass


class CapabilityDependencyError(CapabilityError):
    pass


class CapabilitySourceError(CapabilityError):
    pass


class CapabilitiesDisabledError(CapabilityError):
    pass


def find_dependency_cycles(graph: dict[str, tuple[str, ...]]) -> list[list[str]]:
    """Cycles in a {id: depends_on} graph (Tarjan SCC). Edges to ids not in
    the graph are ignored. Each cycle is a sorted list of ids; the result
    is sorted — fully deterministic."""
    index: dict[str, int] = {}
    low: dict[str, int] = {}
    on_stack: set[str] = set()
    stack: list[str] = []
    cycles: list[list[str]] = []
    counter = 0

    def visit(node: str) -> None:
        nonlocal counter
        index[node] = low[node] = counter
        counter += 1
        stack.append(node)
        on_stack.add(node)
        for dep in sorted(graph[node]):
            if dep not in graph:
                continue
            if dep not in index:
                visit(dep)
                low[node] = min(low[node], low[dep])
            elif dep in on_stack:
                low[node] = min(low[node], index[dep])
        if low[node] == index[node]:
            component: list[str] = []
            while True:
                member = stack.pop()
                on_stack.discard(member)
                component.append(member)
                if member == node:
                    break
            if len(component) > 1 or node in graph[node]:
                cycles.append(sorted(component))

    for node in sorted(graph):
        if node not in index:
            visit(node)
    return sorted(cycles)


class CapabilityManager:
    """Control plane above CapabilityRegistry and ToolRegistry.

    SECURITY BOUNDARY: this class only decides which tools are *available*
    (by enabling/disabling them in the ToolRegistry). It never touches
    permission levels: the orchestrator still reads `tool.permission_level`
    and runs the approval flow for every call. A capability's declared
    `max_permission` is reported next to the tools' effective maximum —
    never applied. Installing means registering code that already exists
    in the running project; there is no download, discovery or plugin
    loading, and only BUILTIN/LOCAL sources are accepted.

    State is in memory only (nothing persisted in Phase 5).
    """

    def __init__(
        self,
        tool_registry: ToolRegistry,
        registry: CapabilityRegistry | None = None,
        enabled: bool | None = None,
    ) -> None:
        self.tool_registry = tool_registry
        self.registry = registry if registry is not None else CapabilityRegistry()
        self.enabled = settings.capabilities_enabled if enabled is None else enabled

    # --- Install / remove --------------------------------------------------

    def install(self, capability: Capability, tools: Sequence[Tool] = ()) -> Capability:
        """Register an already-present capability and its tools atomically.

        The capability's `tool_names` must exactly match the supplied
        tools. If `capability.enabled` is True its dependencies must
        already be installed and enabled (install dependencies first, or
        install with enabled=False and `enable()` later). Dependency cycles
        are rejected. Nothing is changed unless every check passes.
        """
        if not self.enabled:
            raise CapabilitiesDisabledError("the capability framework is disabled by configuration")
        if capability.source not in INSTALLABLE_SOURCES:
            raise CapabilitySourceError(
                f"capabilities with source '{capability.source.value}' cannot be installed yet"
            )
        self._validate_tools(capability, tools)

        graph = {c.id: c.depends_on for c in self.registry.list()}
        if capability.id in graph:
            raise DuplicateCapabilityError(f"Capability '{capability.id}' is already registered")
        graph[capability.id] = capability.depends_on
        cycles = [c for c in find_dependency_cycles(graph) if capability.id in c]
        if cycles:
            raise CapabilityDependencyError(
                f"dependency cycle detected: {' <-> '.join(cycles[0])}"
            )
        if capability.enabled:
            status = self._status_for(capability.depends_on)
            if not status.satisfied:
                raise CapabilityDependencyError(self._describe_unsatisfied(capability.id, status))

        for tool in tools:
            if PERMISSION_RANK.get(tool.permission_level) is None:
                raise CapabilityValidationError(f"tool '{tool.name}' has an invalid permission level")
        effective = max_permission([t.permission_level for t in tools])
        if PERMISSION_RANK[capability.max_permission] < PERMISSION_RANK[effective]:
            logger.warning(
                "capability %s declares max_permission=%s but its tools require %s; "
                "tool-level permissions remain authoritative",
                capability.id, capability.max_permission.value, effective.value,
            )

        self.registry.register(capability)  # raises on duplicate id / tool ownership
        registered: list[str] = []
        try:
            for tool in tools:
                self.tool_registry.register(tool)
                registered.append(tool.name)
        except Exception:
            for name in registered:
                self.tool_registry.unregister(name)
            self.registry.unregister(capability.id)
            raise
        for name in registered:
            self.tool_registry.set_enabled(name, capability.enabled)
        return capability

    def unregister(self, capability_id: str) -> None:
        cap = self._require(capability_id)
        dependents = self.dependents_of(capability_id)
        if dependents:
            raise CapabilityDependencyError(
                f"cannot unregister '{capability_id}': required by {', '.join(dependents)}"
            )
        for name in cap.tool_names:
            if self.tool_registry.has(name):
                self.tool_registry.unregister(name)
        self.registry.unregister(capability_id)

    # --- Enable / disable --------------------------------------------------

    def enable(self, capability_id: str) -> Capability:
        cap = self._require(capability_id)
        status = self._status_for(cap.depends_on)
        if not status.satisfied:
            raise CapabilityDependencyError(self._describe_unsatisfied(capability_id, status))
        updated = self.registry.enable(capability_id)
        self._sync_tools(updated)
        return updated

    def disable(self, capability_id: str, cascade: bool = False) -> Capability:
        """Disables the capability and makes its tools unavailable. If
        enabled capabilities depend on it, raises unless `cascade=True`,
        which disables those dependents (transitively) first."""
        self._require(capability_id)
        dependents = self._enabled_dependents(capability_id)
        if dependents and not cascade:
            raise CapabilityDependencyError(
                f"cannot disable '{capability_id}': enabled capabilities depend on it: "
                f"{', '.join(dependents)} (use cascade=True)"
            )
        for dep_id in dependents:
            self._sync_tools(self.registry.disable(dep_id))
        updated = self.registry.disable(capability_id)
        self._sync_tools(updated)
        return updated

    # --- Queries -------------------------------------------------------------

    def get_capability(self, capability_id: str) -> Capability | None:
        return self.registry.get(capability_id)

    def is_enabled(self, capability_id: str) -> bool:
        return self.registry.is_enabled(capability_id)

    def resolve_tools(self, capability_id: str, include_disabled: bool = False) -> list[Tool]:
        """Capability -> its Tool objects (declaration order)."""
        cap = self._require(capability_id)
        tools = [self.tool_registry.get(n, include_disabled=include_disabled) for n in cap.tool_names]
        return [t for t in tools if t is not None]

    def dependencies_of(self, capability_id: str) -> DependencyStatus:
        return self._status_for(self._require(capability_id).depends_on)

    def dependents_of(self, capability_id: str) -> list[str]:
        """Ids of installed capabilities that directly depend on this one."""
        return [c.id for c in self.registry.list() if capability_id in c.depends_on]

    def detect_cycles(self) -> list[list[str]]:
        return find_dependency_cycles({c.id: c.depends_on for c in self.registry.list()})

    def check_usable(
        self, capability_id: str, max_allowed_permission: PermissionLevel | None = None
    ) -> UsabilityReport:
        """Can this capability be used in the current execution context?
        `max_allowed_permission` is the most restrictive level the context
        tolerates (e.g. SAFE for an unattended run). Advisory: execution is
        still governed by the permission/approval system."""
        cap = self.registry.get(capability_id)
        if cap is None:
            return UsabilityReport(usable=False, reasons=[f"capability '{capability_id}' is not installed"])
        reasons: list[str] = []
        if not cap.enabled:
            reasons.append("capability is disabled")
        status = self._status_for(cap.depends_on)
        reasons += [f"dependency '{d}' is not installed" for d in status.missing]
        reasons += [f"dependency '{d}' is disabled" for d in status.disabled]
        levels: list[PermissionLevel] = []
        for name in cap.tool_names:
            tool = self.tool_registry.get(name, include_disabled=True)
            if tool is None:
                reasons.append(f"tool '{name}' is not registered")
                continue
            levels.append(tool.permission_level)
            if not self.tool_registry.is_enabled(name):
                reasons.append(f"tool '{name}' is disabled")
            if tool.permission_level == PermissionLevel.BLOCKED:
                reasons.append(f"tool '{name}' is BLOCKED")
        if max_allowed_permission is not None:
            ceiling = PERMISSION_RANK[max_allowed_permission]
            for name in cap.tool_names:
                tool = self.tool_registry.get(name, include_disabled=True)
                if tool is not None and PERMISSION_RANK[tool.permission_level] > ceiling:
                    reasons.append(
                        f"tool '{name}' requires {tool.permission_level.value}, above the allowed "
                        f"{max_allowed_permission.value}"
                    )
        return UsabilityReport(usable=not reasons, reasons=reasons)

    # --- Discovery / snapshot ------------------------------------------------

    def list_available_capabilities(self, include_disabled: bool = False) -> list[CapabilityInfo]:
        return [
            self._capability_info(c) for c in self.registry.list(enabled_only=not include_disabled)
        ]

    def list_available_tools(self, include_disabled: bool = False) -> list[ToolInfo]:
        """Every tool in the ToolRegistry (capability-provided or directly
        registered), sorted by name; disabled ones only on request."""
        tools = sorted(self.tool_registry.list_tools(include_disabled=include_disabled), key=lambda t: t.name)
        return [self._tool_info(t) for t in tools]

    def model_tool_schemas(self) -> list[ToolSchema]:
        """The model-facing view: ENABLED tools only, name-sorted, in the
        normalized ToolSchema the providers already translate. (The
        orchestrator itself keeps using `ToolRegistry.schemas()`, which
        applies the same enabled filter.)"""
        return [t.to_tool_schema() for t in sorted(self.tool_registry.list_tools(), key=lambda t: t.name)]

    def snapshot(self) -> CapabilitySnapshot:
        return CapabilitySnapshot(capabilities=self.list_available_capabilities(include_disabled=True))

    # --- Bootstrap -------------------------------------------------------------

    def register_builtin_capabilities(self) -> list[str]:
        """Installs the built-in capabilities in dependency order and
        returns the ids newly installed. Idempotent: ids already installed
        as BUILTIN are skipped; an id held by a non-builtin capability, or
        a tool-name collision, raises BEFORE anything is installed. A no-op
        returning [] when the framework is disabled by configuration."""
        from app.capabilities.builtin import builtin_packages

        if not self.enabled:
            return []
        pending: list[tuple[Capability, list[Tool]]] = []
        for capability, tools in builtin_packages():
            existing = self.registry.get(capability.id)
            if existing is not None:
                if existing.source != CapabilitySource.BUILTIN:
                    raise DuplicateCapabilityError(
                        f"Capability '{capability.id}' is already registered with source "
                        f"'{existing.source.value}'"
                    )
                continue
            for tool in tools:
                if self.tool_registry.has(tool.name):
                    raise CapabilityValidationError(
                        f"tool '{tool.name}' is already registered outside capability '{capability.id}'"
                    )
            pending.append((capability, tools))
        for capability, tools in pending:
            self.install(capability, tools)
        return [c.id for c, _ in pending]

    # --- Internals ---------------------------------------------------------------

    def _require(self, capability_id: str) -> Capability:
        cap = self.registry.get(capability_id)
        if cap is None:
            raise CapabilityNotFoundError(f"Capability '{capability_id}' is not registered")
        return cap

    def _sync_tools(self, capability: Capability) -> None:
        for name in capability.tool_names:
            if self.tool_registry.has(name):
                self.tool_registry.set_enabled(name, capability.enabled)

    def _status_for(self, deps: Sequence[str]) -> DependencyStatus:
        missing = sorted(d for d in deps if not self.registry.has(d))
        disabled = sorted(d for d in deps if self.registry.has(d) and not self.registry.is_enabled(d))
        return DependencyStatus(satisfied=not missing and not disabled, missing=missing, disabled=disabled)

    @staticmethod
    def _describe_unsatisfied(capability_id: str, status: DependencyStatus) -> str:
        parts = []
        if status.missing:
            parts.append(f"missing: {', '.join(status.missing)}")
        if status.disabled:
            parts.append(f"disabled: {', '.join(status.disabled)}")
        return f"capability '{capability_id}' has unsatisfied dependencies ({'; '.join(parts)})"

    def _enabled_dependents(self, capability_id: str) -> list[str]:
        """Transitive, enabled dependents, sorted."""
        found: set[str] = set()
        frontier = [capability_id]
        while frontier:
            current = frontier.pop()
            for dep_id in self.dependents_of(current):
                if dep_id not in found and self.registry.is_enabled(dep_id):
                    found.add(dep_id)
                    frontier.append(dep_id)
        return sorted(found)

    def _validate_tools(self, capability: Capability, tools: Sequence[Tool]) -> None:
        names = [t.name for t in tools]
        if len(set(names)) != len(names):
            raise CapabilityValidationError("duplicate tool in capability package")
        if set(names) != set(capability.tool_names):
            raise CapabilityValidationError(
                f"capability '{capability.id}' declares tools {sorted(capability.tool_names)} "
                f"but was given {sorted(names)}"
            )
        for tool in tools:
            if not is_valid_version(tool.version):
                raise CapabilityValidationError(f"tool '{tool.name}' has an invalid version")
            if self.tool_registry.has(tool.name):
                raise CapabilityValidationError(f"tool '{tool.name}' is already registered")

    def _tool_info(self, tool: Tool) -> ToolInfo:
        owner = self.registry.find_by_tool(tool.name)
        schema = tool.to_tool_schema()
        return ToolInfo(
            name=tool.name,
            description=tool.description,
            version=tool.version,
            permission_level=tool.permission_level,
            requires_approval=requires_approval(tool.permission_level),
            timeout_seconds=tool.timeout_seconds,
            input_schema=schema.parameters,
            capability_id=owner.id if owner else None,
            category=owner.category if owner else None,
            enabled=self.tool_registry.is_enabled(tool.name),
        )

    def _capability_info(self, cap: Capability) -> CapabilityInfo:
        tools = [
            self._tool_info(t)
            for n in sorted(cap.tool_names)
            if (t := self.tool_registry.get(n, include_disabled=True)) is not None
        ]
        effective = max_permission([t.permission_level for t in tools])
        return CapabilityInfo(
            id=cap.id,
            name=cap.name,
            description=cap.description,
            version=cap.version,
            category=cap.category,
            source=cap.source,
            enabled=cap.enabled,
            declared_max_permission=cap.max_permission,
            effective_max_permission=effective,
            permission_mismatch=PERMISSION_RANK[cap.max_permission] < PERMISSION_RANK[effective],
            tools=tools,
            depends_on=sorted(cap.depends_on),
            dependency_status=self._status_for(cap.depends_on),
            metadata=dict(cap.metadata),
        )
