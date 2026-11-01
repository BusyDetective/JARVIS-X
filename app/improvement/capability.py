from __future__ import annotations

import logging
from pathlib import Path

from app.capabilities.manager import CapabilityManager
from app.capabilities.models import Capability, CapabilityCategory, CapabilitySource
from app.config.settings import settings
from app.engineering.capability import SOFTWARE_ENGINEERING_CAPABILITY_ID
from app.improvement.manager import ImprovementManager
from app.improvement.repository import ImprovementRepository
from app.improvement.tools import improvement_tools
from app.sandbox.container import ContainerBackend
from app.sandbox.manager import SandboxManager
from app.sandbox.policy import SandboxPolicy
from app.security.permissions import PermissionLevel
from app.tools.base import Tool
from app.versioning.manager import ReleaseStore
from app.web.research import WebResearchManager

logger = logging.getLogger(__name__)
SELF_IMPROVEMENT_CAPABILITY_ID = "self_improvement"


def build_improvement_manager(
    web: WebResearchManager | None = None, db_path: Path | str | None = None, root: Path | str | None = None,
) -> ImprovementManager:
    """Wire the engine from settings (container isolation backend, no host execution). Creates directories under the improvement
    root only; does not bootstrap a release and does not touch the project tree."""
    base = Path(root) if root is not None else settings.self_improvement_root
    store = ReleaseStore(base)
    policy = SandboxPolicy.from_settings()
    # Candidate code can only run in a container. A bad configuration raises IsolationUnavailableError
    # here; a missing runtime/image is detected (fail closed) at validation time. No host fallback exists.
    backend = ContainerBackend(policy, cli=settings.improvement_isolation_backend, image=settings.improvement_container_image,
                               oci_runtime=settings.improvement_container_oci_runtime, scratch_dir=base / "scratch")
    sandbox = SandboxManager(base, policy, backend)
    manager = ImprovementManager(ImprovementRepository(db_path), store, sandbox, web,
                                 max_diff_chars=settings.engineering_max_diff_chars)
    manager.startup_recovery()
    return manager


def self_improvement_package(manager: ImprovementManager) -> tuple[Capability, list[Tool]]:
    tools = improvement_tools(manager)
    capability = Capability(
        id=SELF_IMPROVEMENT_CAPABILITY_ID, name="Self-improvement",
        description="Controlled improvement pipeline: research, evaluate, plan, propose (sandbox only), validate, rollback. "
                    "No tool can approve or promote; promotion needs a passing validation and a human approval.",
        version="1.0.0", category=CapabilityCategory.DEVELOPMENT, source=CapabilitySource.BUILTIN,
        max_permission=PermissionLevel.CONFIRM, tool_names=tuple(t.name for t in tools),
        depends_on=(SOFTWARE_ENGINEERING_CAPABILITY_ID,), metadata={"default_enabled": False})
    return capability, tools


def register_self_improvement_capability(capabilities: CapabilityManager, manager: ImprovementManager) -> bool:
    """Installs `self_improvement` through the CapabilityManager. Returns False
    and registers nothing unless SELF_IMPROVEMENT_ENABLED is true (default: false).
    Requires the `software_engineering` capability (enforced by the dependency system)."""
    if not settings.self_improvement_enabled:
        return False
    if capabilities.registry.has(SELF_IMPROVEMENT_CAPABILITY_ID):
        return False
    capability, tools = self_improvement_package(manager)
    capabilities.install(capability, tools)
    return True
