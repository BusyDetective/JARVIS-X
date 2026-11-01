from __future__ import annotations

import importlib.util
import logging

from app.browser.errors import BrowserUnavailableError
from app.browser.manager import BrowserManager
from app.browser.models import BrowserLimits
from app.browser.tools import build_browser_tools
from app.capabilities.manager import CapabilityManager
from app.capabilities.models import Capability, CapabilityCategory, CapabilitySource
from app.config.settings import settings
from app.security.permissions import PermissionLevel
from app.tools.base import Tool

logger = logging.getLogger(__name__)

BROWSER_CAPABILITY_ID = "browser"


def build_browser_manager(limits: BrowserLimits | None = None) -> BrowserManager:
    """Raises BrowserUnavailableError if the optional dependency is missing; never starts a browser."""
    if importlib.util.find_spec("playwright") is None:
        raise BrowserUnavailableError(
            "Playwright is not installed. Install the optional dependency: pip install -r requirements-browser.txt")
    return BrowserManager(limits or BrowserLimits.from_settings())


def browser_package(manager: BrowserManager, enabled_check=None) -> tuple[Capability, list[Tool]]:
    tools = build_browser_tools(manager, enabled_check)
    capability = Capability(
        id=BROWSER_CAPABILITY_ID,
        name="Browser",
        description=("Controlled, temporary browser for observing public web pages (read, screenshot, follow links, "
                     "fill permitted text fields). State-changing actions are denied by policy."),
        version="1.0.0",
        category=CapabilityCategory.INFORMATION,
        source=CapabilitySource.BUILTIN,
        max_permission=PermissionLevel.CONFIRM,
        tool_names=tuple(t.name for t in tools),
        metadata={"javascript_enabled": str(manager.limits.javascript_enabled).lower()},
    )
    return capability, tools


def register_browser_capability(capabilities: CapabilityManager, manager: BrowserManager) -> bool:
    """Install through the CapabilityManager (so enable/disable gating applies). False if BROWSER_ENABLED is
    false or already installed."""
    if not settings.browser_enabled:
        return False
    if capabilities.registry.has(BROWSER_CAPABILITY_ID):
        return False
    capability, tools = browser_package(
        manager, lambda: capabilities.enabled and capabilities.is_enabled(BROWSER_CAPABILITY_ID))
    capabilities.install(capability, tools)
    return True
