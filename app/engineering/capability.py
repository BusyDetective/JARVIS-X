from __future__ import annotations

import logging

from app.capabilities.manager import CapabilityManager
from app.capabilities.models import Capability, CapabilityCategory, CapabilitySource
from app.config.settings import settings
from app.engineering.tools import engineering_tools
from app.github.client import GitHubClient, GitHubLimits, HttpxGitHubClient
from app.github.tools import github_tools
from app.security.permissions import PermissionLevel
from app.tools.base import Tool
from app.workspace.manager import WorkspaceLimits, WorkspaceManager
from app.workspace.tools import workspace_tools

logger = logging.getLogger(__name__)

SOFTWARE_ENGINEERING_CAPABILITY_ID = "software_engineering"


def build_github_client(limits: GitHubLimits | None = None) -> HttpxGitHubClient:
    """From settings. Works without a token (unauthenticated, lower rate limits)."""
    limits = limits or GitHubLimits.from_settings()
    return HttpxGitHubClient(settings.github_token, limits)


def build_workspace_manager(limits: WorkspaceLimits | None = None) -> WorkspaceManager:
    from app.security.workspace import get_workspace_root

    return WorkspaceManager(get_workspace_root(), limits or WorkspaceLimits.from_settings())


def software_engineering_package(
    github: GitHubClient | None, workspace: WorkspaceManager | None
) -> tuple[Capability, list[Tool]]:
    """Assembles the tools allowed by the individual feature switches
    (github_enabled / workspace_enabled / engineering_enabled). All tools are
    read-only and SAFE; the capability cannot raise or lower that."""
    tools: list[Tool] = []
    if github is not None and settings.github_enabled:
        tools += github_tools(github)
    if workspace is not None and settings.workspace_enabled:
        tools += workspace_tools(workspace)
        if settings.engineering_enabled:
            tools += engineering_tools(workspace)
    capability = Capability(
        id=SOFTWARE_ENGINEERING_CAPABILITY_ID,
        name="Software engineering",
        description="Read-only GitHub inspection, confined workspace reading/search, and deterministic "
                    "engineering helpers (project inspection, diff proposals, plans). Nothing is written or executed.",
        version="1.0.0",
        category=CapabilityCategory.DEVELOPMENT,
        source=CapabilitySource.BUILTIN,
        max_permission=PermissionLevel.SAFE,
        tool_names=tuple(t.name for t in tools),
        metadata={"read_only": True},
    )
    return capability, tools


def register_software_engineering_capability(
    capabilities: CapabilityManager, github: GitHubClient | None = None, workspace: WorkspaceManager | None = None
) -> bool:
    """Installs `software_engineering` through the CapabilityManager (so the
    Phase 5 enable/disable gating applies). Returns False — and registers
    nothing — if SOFTWARE_ENGINEERING_ENABLED is false, it is already
    installed, or no tool is enabled by the feature switches."""
    if not settings.software_engineering_enabled:
        return False
    if capabilities.registry.has(SOFTWARE_ENGINEERING_CAPABILITY_ID):
        return False
    capability, tools = software_engineering_package(github, workspace)
    if not tools:
        return False
    capabilities.install(capability, tools)
    return True
