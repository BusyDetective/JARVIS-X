from __future__ import annotations

import logging

from app.capabilities.manager import CapabilityManager
from app.capabilities.models import Capability, CapabilityCategory, CapabilitySource
from app.config.settings import settings
from app.cybersecurity.errors import NoScopeConfigured
from app.cybersecurity.models import CyberLimits
from app.cybersecurity.scope import ScopeStore
from app.cybersecurity.tools import ALL_TOOL_CLASSES
from app.security.permissions import PermissionLevel
from app.tools.base import Tool

logger = logging.getLogger(__name__)

CYBERSECURITY_CAPABILITY_ID = "cybersecurity_specialist"


def build_cybersecurity_manager() -> tuple[ScopeStore, CyberLimits]:
    """Wires the scope store (fail-closed if CYBERSECURITY_SCOPE_FILE is
    unset or unreadable — see scope.py) and the resource limits. Unlike
    build_web_research_manager(), an empty/missing scope configuration is
    NOT an error here: the capability still installs (so its tools are
    visible and their descriptions explain how to configure a scope), it
    simply authorizes nothing until a scope file is present. This matches
    §5's "fail closed, never invent a permissive default" without making
    the capability impossible to even inspect."""
    limits = CyberLimits.from_settings()
    try:
        scope_store = ScopeStore.from_settings()
    except NoScopeConfigured as exc:
        logger.warning("cybersecurity_specialist: %s — every operation will be denied until configured", exc)
        scope_store = ScopeStore([])
    return scope_store, limits


def cybersecurity_package(scope_store: ScopeStore, limits: CyberLimits) -> tuple[Capability, list[Tool]]:
    tools = [cls(scope_store, limits) for cls in ALL_TOOL_CLASSES]
    capability = Capability(
        id=CYBERSECURITY_CAPABILITY_ID,
        name="Cybersecurity specialist",
        description=(
            "Bounded, authorization-scoped reconnaissance (subdomain enumeration, alive-host checks, "
            "endpoint discovery, technology fingerprinting, exposure risk summary, report generation) "
            "against explicitly authorized targets only. No exploitation, vulnerability scanning, or "
            "credential testing. Disabled and unauthorized by default."
        ),
        version="1.0.0",
        category=CapabilityCategory.INFORMATION,
        source=CapabilitySource.BUILTIN,
        max_permission=PermissionLevel.DANGEROUS,
        tool_names=tuple(cls.name for cls in ALL_TOOL_CLASSES),
        # Approval is enforced solely through each tool's permission_level
        # (DANGEROUS/CONFIRM) via the existing ApprovalHandler — there is
        # deliberately no separate "require approval" toggle here that
        # could be read as a way to bypass it.
        metadata={"authorized_scopes": len(scope_store)},
    )
    return capability, tools


def register_cybersecurity_capability(
    capabilities: CapabilityManager, scope_store: ScopeStore, limits: CyberLimits
) -> bool:
    """Installs cybersecurity_specialist through the CapabilityManager.
    Returns True if newly installed; False if CYBERSECURITY_ENABLED is
    false (the default) or it is already installed."""
    if not settings.cybersecurity_enabled:
        return False
    if capabilities.registry.has(CYBERSECURITY_CAPABILITY_ID):
        return False
    capability, tools = cybersecurity_package(scope_store, limits)
    capabilities.install(capability, tools)
    return True
