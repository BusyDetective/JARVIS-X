from __future__ import annotations

import re

from pydantic import BaseModel

from app.improvement.models import ImprovementRequest
from app.versioning.models import SystemManifest

_REQ_RE = re.compile(r"^([A-Za-z0-9_.\-]+)\s*(.*)$")


class DependencyCandidate(BaseModel):
    name: str
    specifier: str
    group: str  # "runtime" | "dev"


class ImprovementDiscovery:
    """Turns explicit requests into structured ImprovementRequests and lists
    local metadata a later research step can look at. It performs no network
    access, watches nothing and implements nothing."""

    def create_request(self, goal: str, scope: list[str] | None = None, constraints: list[str] | None = None,
                       requested_by: str = "user") -> ImprovementRequest:
        return ImprovementRequest(goal=goal, scope=scope or [], constraints=constraints or [], requested_by=requested_by)

    def dependency_candidates(self, manifest: SystemManifest) -> list[DependencyCandidate]:
        """Declared dependencies of the current release (names and specifiers
        only), as starting points for research. Nothing is installed or upgraded."""
        out: list[DependencyCandidate] = []
        for group, lines in sorted(manifest.dependencies.items()):
            for line in lines:
                m = _REQ_RE.match(line)
                if m:
                    out.append(DependencyCandidate(name=m.group(1), specifier=m.group(2).strip(), group=group))
        return out
