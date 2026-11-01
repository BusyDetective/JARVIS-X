from __future__ import annotations

import logging

from app.capabilities.manager import CapabilityManager
from app.capabilities.models import Capability, CapabilityCategory, CapabilitySource
from app.config.settings import settings
from app.security.permissions import PermissionLevel
from app.tools.base import Tool
from app.web.fetch import HttpxWebFetcher
from app.web.limits import WebLimits
from app.web.research import WebResearchManager
from app.web.search import build_search_provider
from app.web.tools import WebResearchTool, WebSearchTool
from app.web.urls import UrlValidator

logger = logging.getLogger(__name__)

WEB_CAPABILITY_ID = "web_research"


def build_web_research_manager(limits: WebLimits | None = None) -> WebResearchManager:
    """Wires the configured search provider and the HTTP fetcher.
    Raises WebConfigurationError if search is not configured (no API key /
    unknown provider) — it never returns a manager that cannot work."""
    limits = limits or WebLimits.from_settings()
    provider = build_search_provider(timeout_seconds=limits.request_timeout_seconds)
    return WebResearchManager(provider, HttpxWebFetcher(limits, UrlValidator()), limits)


def web_research_package(manager: WebResearchManager) -> tuple[Capability, list[Tool]]:
    capability = Capability(
        id=WEB_CAPABILITY_ID,
        name="Web research",
        description="Search the public web and read pages (bounded, SSRF-protected, read-only).",
        version="1.0.0",
        category=CapabilityCategory.INFORMATION,
        source=CapabilitySource.BUILTIN,
        max_permission=PermissionLevel.SAFE,
        tool_names=("web_search", "web_research"),
        metadata={"search_provider": manager.search_provider.name},
    )
    return capability, [WebSearchTool(manager), WebResearchTool(manager)]


def register_web_research_capability(
    capabilities: CapabilityManager, manager: WebResearchManager
) -> bool:
    """Installs the web_research capability through the CapabilityManager
    (so enable/disable gating applies). Returns True if newly installed;
    False if WEB_RESEARCH_ENABLED is false or it is already installed."""
    if not settings.web_research_enabled:
        return False
    if capabilities.registry.has(WEB_CAPABILITY_ID):
        return False
    capability, tools = web_research_package(manager)
    capabilities.install(capability, tools)
    return True
