from __future__ import annotations

from urllib.parse import urlsplit


def safe_target(value: str) -> str:
    """host[:port]/path only — credentials, query strings and fragments
    (which may carry tokens) are dropped. Used in every error message,
    log line and report field so raw exception text, headers, or secrets
    from the scanned target never leak into a message the model or a
    report might surface."""
    try:
        parts = urlsplit(value if "//" in value else f"//{value}")
        host = parts.hostname or value
        out = host
        if parts.port:
            out += f":{parts.port}"
        if parts.path:
            out += parts.path
        return out[:200]
    except ValueError:
        return "<invalid target>"


class CyberError(Exception):
    """Base for the cybersecurity subsystem. Messages are SAFE BY
    CONSTRUCTION: built from fixed text and safe_target() values only —
    never from raw exception text, response bodies, headers or
    environment values — because they can reach the model and reports."""


class ScopeViolation(CyberError):
    """Target (or a resolved address / redirect target) is not covered by
    an active AuthorizedScope entry for the requested operation."""


class AuthorizationExpired(CyberError):
    """A matching scope entry exists but has passed its expiration time."""


class NoScopeConfigured(CyberError):
    """No authorization-scope configuration is present at all. Distinct
    from ScopeViolation so a misconfigured deployment is diagnosable
    without implying any target was actually checked and rejected."""


class InvalidTarget(CyberError):
    """Target is malformed, not a supported scheme, or otherwise cannot
    be parsed/resolved."""


class UnsafeTarget(CyberError):
    """Target (or something it resolves/redirects to) is a private,
    loopback, link-local, metadata, or otherwise disallowed address."""


class EngineUnavailable(CyberError):
    """The vendored recon engine could not be imported or a required
    external dependency (binary, package) is missing."""


class OperationLimitExceeded(CyberError):
    """A server-enforced bound (targets, hosts, endpoints, requests,
    runtime, output size) was hit."""


class ReportPathError(CyberError):
    """Requested report output path escapes the configured report
    directory, or no report directory is configured."""


class NoPriorResults(CyberError):
    """risk_scoring / report_generation operate ONLY on results an
    earlier bounded operation (subdomain_enum / alive_check /
    endpoint_discovery) already produced for this domain in this
    session. Raised when nothing is cached — these operations never
    silently trigger a new scan of their own."""
