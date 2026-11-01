from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from ipaddress import ip_network
from typing import Any

from pydantic import BaseModel, Field, field_validator, model_validator

import re

_DOMAIN_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _require_utc(v: datetime) -> datetime:
    if v.tzinfo is None:
        raise ValueError("datetime fields must be timezone-aware (UTC), not naive")
    return v


def _normalize_domain(v: str) -> str:
    v = v.strip().lower().rstrip(".")
    if v.startswith(("http://", "https://")):
        v = v.split("://", 1)[1]
    v = v.split("/")[0]
    if not _DOMAIN_RE.match(v):
        raise ValueError(f"not a valid domain: {v!r}")
    return v


class OperationType(str, Enum):
    """The ONLY operations the cybersecurity specialist can perform in
    this phase. Deliberately excludes anything exploitation-adjacent
    (vulnerability scanning, payload validation, exploit generation,
    directory/credential brute-forcing) — those stages of the underlying
    recon engine are never invoked by this package. See adapter.py."""

    SUBDOMAIN_ENUM = "subdomain_enum"
    ALIVE_CHECK = "alive_check"
    ENDPOINT_DISCOVERY = "endpoint_discovery"
    TECH_FINGERPRINT = "tech_fingerprint"
    RISK_SCORING = "risk_scoring"
    REPORT_GENERATION = "report_generation"


# Operations that only read/compute over results an earlier operation in
# the SAME approved scope already produced — they never touch the network
# themselves. Used by scope checks: these still require a scope entry
# covering the target, but never widen what the network boundary allows.
NETWORK_OPERATIONS = frozenset(
    {
        OperationType.SUBDOMAIN_ENUM,
        OperationType.ALIVE_CHECK,
        OperationType.ENDPOINT_DISCOVERY,
        OperationType.TECH_FINGERPRINT,
    }
)


class AuthorizedScope(BaseModel):
    """A single authorization grant. Explicit allow-list entry — nothing
    is in scope unless it matches one of these. Loaded from configuration
    (see scope.py); never inferred from a user-supplied target."""

    model_config = {"frozen": True}

    id: str = Field(min_length=1, max_length=100)
    domains: tuple[str, ...] = Field(default_factory=tuple, description="Approved domains (exact match, no wildcards).")
    ip_networks: tuple[str, ...] = Field(
        default_factory=tuple,
        description="Approved IP/CIDR ranges. Only meaningful together with allow_private_targets for local labs.",
    )
    operation_types: tuple[OperationType, ...] = Field(min_length=1)
    expires_at: datetime
    source: str = Field(min_length=1, max_length=300, description="Program name, ticket, or other authorization reference.")
    max_targets: int = Field(default=1, ge=1, le=50)
    allow_private_targets: bool = Field(
        default=False,
        description="Explicit local-lab opt-in. When false (default), private/loopback/link-local/metadata "
        "addresses are rejected even if listed in ip_networks.",
    )

    @field_validator("domains")
    @classmethod
    def _domains_ok(cls, v: tuple[str, ...]) -> tuple[str, ...]:
        return tuple(_normalize_domain(d) for d in v)

    @field_validator("ip_networks")
    @classmethod
    def _networks_ok(cls, v: tuple[str, ...]) -> tuple[str, ...]:
        for n in v:
            ip_network(n, strict=False)  # raises ValueError on malformed input
        return v

    @field_validator("expires_at")
    @classmethod
    def _expires_utc(cls, v: datetime) -> datetime:
        return _require_utc(v)

    @field_validator("operation_types")
    @classmethod
    def _ops_unique(cls, v: tuple[OperationType, ...]) -> tuple[OperationType, ...]:
        if len(set(v)) != len(v):
            raise ValueError("operation_types must be unique")
        return v

    @model_validator(mode="after")
    def _has_targets(self) -> "AuthorizedScope":
        if not self.domains and not self.ip_networks:
            raise ValueError("scope must list at least one domain or ip_network")
        return self

    def is_expired(self, now: datetime | None = None) -> bool:
        return (now or utcnow()) >= self.expires_at


class CyberLimits(BaseModel):
    """Server-side bounds, enforced independently of anything a model
    requests: `max_results` on CyberOperationRequest is only ever clamped
    DOWN to these. Mirrors app.web.limits.WebLimits."""

    model_config = {"frozen": True}

    max_subdomains: int = Field(default=50, ge=1, le=500)
    max_hosts: int = Field(default=15, ge=1, le=100)
    max_endpoints: int = Field(default=100, ge=1, le=1000)
    max_findings_per_result: int = Field(default=200, ge=1, le=2000)
    request_timeout_seconds: float = Field(default=20.0, gt=0, le=120)
    operation_timeout_seconds: float = Field(default=180.0, gt=0, le=900)
    max_concurrency: int = Field(default=10, ge=1, le=50)
    max_tool_output_chars: int = Field(default=24_000, ge=1_000, le=500_000)
    cache_ttl_seconds: float = Field(default=3600.0, gt=0, le=86_400)
    cache_max_domains: int = Field(default=50, ge=1, le=1000)

    @classmethod
    def from_settings(cls) -> "CyberLimits":
        from app.config.settings import settings

        return cls(
            max_subdomains=settings.cybersecurity_max_subdomains,
            max_hosts=settings.cybersecurity_max_hosts,
            max_endpoints=settings.cybersecurity_max_endpoints,
            max_findings_per_result=settings.cybersecurity_max_findings,
            request_timeout_seconds=settings.cybersecurity_request_timeout,
            operation_timeout_seconds=settings.cybersecurity_operation_timeout,
            max_concurrency=settings.cybersecurity_max_concurrency,
            max_tool_output_chars=settings.cybersecurity_max_tool_output_chars,
            cache_ttl_seconds=settings.cybersecurity_cache_ttl_seconds,
            cache_max_domains=settings.cybersecurity_cache_max_domains,
        )

    def clamp(self, requested: int | None, ceiling: int) -> int:
        if requested is None:
            return ceiling
        return max(1, min(int(requested), ceiling))


class CyberOperationRequest(BaseModel):
    """Model-facing request. Everything here is untrusted input and is
    re-validated by scope.py/authorization.py before any network call —
    this model only enforces shape, not authorization."""

    operation: OperationType
    target: str = Field(min_length=1, max_length=253)
    max_results: int | None = Field(default=None, ge=1, description="Advisory only; server limits always win.")

    @field_validator("target")
    @classmethod
    def _target_ok(cls, v: str) -> str:
        return _normalize_domain(v)


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class CyberFinding(BaseModel):
    """One normalized item of output (a discovered subdomain, a live
    host, an endpoint, a technology, a risk note). NOT a confirmed
    vulnerability — this phase performs no exploitation or validation, so
    `severity`/`confidence` describe informational risk signal only."""

    type: str = Field(min_length=1, max_length=64)
    target: str = Field(max_length=300)
    detail: str = Field(default="", max_length=2000)
    severity: Severity = Severity.INFO
    confidence: int | None = Field(default=None, ge=0, le=100)
    evidence_ref: str | None = Field(default=None, max_length=300)


class CyberOperationResult(BaseModel):
    """Bounded, typed, model-facing output. No raw internal objects, no
    complete HTTP responses, no headers/bodies — only what adapter.py
    explicitly extracts into CyberFinding items."""

    operation: OperationType
    target: str
    scope_id: str
    started_at: datetime
    completed_at: datetime
    findings: list[CyberFinding] = Field(default_factory=list)
    counts: dict[str, int] = Field(default_factory=dict)
    warnings: list[str] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)
    truncated: bool = False
    limits_applied: dict[str, Any] = Field(default_factory=dict)

    @field_validator("started_at", "completed_at")
    @classmethod
    def _ts_utc(cls, v: datetime) -> datetime:
        return _require_utc(v)


class CyberReportMetadata(BaseModel):
    """Returned to the model in place of a raw file path: enough to find
    and describe the report without handing back a filesystem path the
    model could try to repurpose."""

    report_id: str
    domain: str
    format: str
    finding_count: int
    generated_at: datetime
    relative_path: str = Field(description="Path relative to the configured report output directory.")

    @field_validator("generated_at")
    @classmethod
    def _gen_utc(cls, v: datetime) -> datetime:
        return _require_utc(v)
