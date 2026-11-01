"""Adapter: the ONLY module that imports and calls the vendored recon
engine (vendor/ai_bug_bounty_recon/).

Every call goes through `authorize()` first. Every engine call runs off
the event loop with a hard per-call timeout. Only plain, non-closure,
module-level engine functions are called — NEVER `run_recon()` — which is
what keeps the excluded stages (Smart Tests, Detection Engine, Vuln
Engine, exploit generation/validation, directory brute-forcing,
screenshots/browser automation) out of reach entirely: this module simply
never imports or calls them. See the Phase 10 integration report for the
full rationale.

Engine output is normalized into CyberFinding/CyberOperationResult before
it leaves this module — raw engine dicts, HTTP responses, and exceptions
never reach a Tool's return value directly.
"""
from __future__ import annotations

import asyncio
import logging
import shutil
import sys
import threading
import time
import uuid
from pathlib import Path
from typing import Any, Callable, TypeVar
from urllib.parse import urlsplit

from app.cybersecurity.authorization import AuthorizedTarget, authorize
from app.cybersecurity.errors import (
    CyberError,
    EngineUnavailable,
    NoPriorResults,
    OperationLimitExceeded,
    ReportPathError,
)
from app.cybersecurity.errors import safe_target
from app.cybersecurity.models import (
    CyberFinding,
    CyberLimits,
    CyberOperationRequest,
    CyberOperationResult,
    CyberReportMetadata,
    OperationType,
    utcnow,
)
from app.cybersecurity.scope import ScopeStore

logger = logging.getLogger(__name__)

_T = TypeVar("_T")

# vendor/ai_bug_bounty_recon relative to the repo root (two levels above
# app/cybersecurity/). Appended, never inserted at index 0, so it can
# never shadow a same-named package already on sys.path.
_ENGINE_DIR = Path(__file__).resolve().parents[2] / "vendor" / "ai_bug_bounty_recon"


class _Engine:
    """Lazily-imported handle to the specific engine functions this
    adapter calls. Import failures (missing playwright, missing recon
    source tree, etc.) surface once, clearly, as EngineUnavailable,
    instead of breaking JARVIS-X's own startup import chain."""

    _instance: "_Engine | None" = None

    def __init__(self) -> None:
        if str(_ENGINE_DIR) not in sys.path:
            if not _ENGINE_DIR.is_dir():
                raise EngineUnavailable(f"vendored recon engine not found at {_ENGINE_DIR.name}/")
            sys.path.append(str(_ENGINE_DIR))
        try:
            from core.recon_core import (  # type: ignore
                basic_crawler,
                fetch_wayback_urls,
                filter_important_urls,
                get_subdomains,
            )
            from core.alive_check import check_alive  # type: ignore
            from core.tech_fingerprint import detect_technologies  # type: ignore
            from core.classifier import classify_endpoint  # type: ignore
            from ai_engine.risk_scoring import calculate_risk  # type: ignore
            from reports.report_generator import generate_report  # type: ignore
        except ImportError as exc:
            raise EngineUnavailable(
                f"vendored recon engine dependencies are not importable: {type(exc).__name__}"
            ) from None

        self.get_subdomains = get_subdomains
        self.check_alive = check_alive
        self.fetch_wayback_urls = fetch_wayback_urls
        self.basic_crawler = basic_crawler
        self.filter_important_urls = filter_important_urls
        self.classify_endpoint = classify_endpoint
        self.detect_technologies = detect_technologies
        self.calculate_risk = calculate_risk
        self.generate_report = generate_report

    @classmethod
    def get(cls) -> "_Engine":
        if cls._instance is None:
            _install_redirect_guard()
            cls._instance = cls()
        return cls._instance


def _threaded_call(fn: Callable[..., _T], args: tuple, kwargs: dict, guard_domain: str | None) -> _T:
    """Runs INSIDE the worker thread asyncio.to_thread spawns. Setting the
    guard domain here (not in the calling coroutine) is required —
    threading.local state does not propagate across threads."""
    if guard_domain is not None:
        _guard_state.domain = guard_domain
    try:
        return fn(*args, **kwargs)
    except PermissionError as exc:
        # Translate the guard's generic PermissionError into our own
        # vocabulary at the boundary, without importing UnsafeTarget into
        # the monkeypatch itself.
        from app.cybersecurity.errors import UnsafeTarget

        raise UnsafeTarget(str(exc)) from None
    finally:
        if guard_domain is not None:
            _guard_state.domain = None


async def _run_bounded(
    fn: Callable[..., _T], *args: Any, timeout: float, guard_domain: str | None = None, **kwargs: Any
) -> _T:
    """Run a blocking engine call off the event loop with a hard timeout.
    A timeout here does not guarantee the underlying OS-level socket
    stops immediately (the engine's own per-request timeouts are the
    first line of defense) but it does guarantee THIS call returns
    control to the caller rather than hanging the operation forever.
    `guard_domain`, when given, activates the redirect/scope guard above
    for the duration of this call — pass it for every call that makes its
    own HTTP requests (check_alive, basic_crawler, detect_technologies);
    leave it None for pure computation (classify_endpoint,
    filter_important_urls, calculate_risk)."""
    try:
        return await asyncio.wait_for(
            asyncio.to_thread(_threaded_call, fn, args, kwargs, guard_domain), timeout=timeout
        )
    except asyncio.TimeoutError:
        raise OperationLimitExceeded(f"operation timed out after {timeout:.0f}s") from None


def _same_domain_or_sub(url: str, domain: str) -> bool:
    host = (urlsplit(url).hostname or "").lower().rstrip(".")
    return host == domain or host.endswith(f".{domain}")


# ─────────────────────────────────────────────────────────────────────────
# Redirect / out-of-scope-request guard for the vendored engine's own HTTP
# calls.
#
# check_alive, basic_crawler, and detect_technologies each issue their own
# `requests` calls internally with allow_redirects=True and no scope check
# of their own (confirmed by reading the source — see the integration
# report's "Network safety" section). authorize() only validates the
# domain we HAND to these functions; it cannot see what a remote server's
# 3xx response later points at. Per the Phase 10 brief ("if the existing
# engine cannot enforce a required boundary, introduce a narrow adapter"),
# this patches the one chokepoint all three paths share — every `requests`
# call funnels through `Session.send()`, including each hop of a redirect
# chain and bare `requests.get()` calls (which open a Session internally)
# — so a redirect or request that leaves the authorized domain is refused
# before it reaches the network, not merely filtered out of the results
# afterward.
#
# Scoped via threading.local rather than a global flag: _run_bounded runs
# each engine call in its own dedicated thread (via asyncio.to_thread), so
# setting the allowed domain only on that thread means concurrent calls
# for different domains can never see each other's guard state, and any
# unrelated code using `requests` elsewhere in the process (there is none
# in JARVIS-X itself — it uses httpx) is unaffected because its thread
# never has the guard domain set.
# ─────────────────────────────────────────────────────────────────────────

_guard_state = threading.local()
_guard_installed = False
_guard_lock = threading.Lock()


def _install_redirect_guard() -> None:
    global _guard_installed
    if _guard_installed:
        return
    with _guard_lock:
        if _guard_installed:
            return
        import requests

        _original_send = requests.Session.send

        def _guarded_send(self, request, **kwargs):  # noqa: ANN001
            domain = getattr(_guard_state, "domain", None)
            if domain is not None and not _same_domain_or_sub(request.url, domain):
                logger.warning(
                    "cybersecurity adapter: blocked out-of-scope request to %s (authorized domain: %s)",
                    safe_target(request.url), domain,
                )
                raise PermissionError(
                    f"refusing to request {safe_target(request.url)}: outside the authorized domain {domain}"
                )
            return _original_send(self, request, **kwargs)

        requests.Session.send = _guarded_send
        _guard_installed = True


# ─────────────────────────────────────────────────────────────────────────
# In-memory, per-process result cache.
#
# risk_scoring and report_generation operate ONLY on results an earlier
# bounded operation already produced for this domain — they never trigger
# a new scan themselves. This cache is what makes that possible without
# requiring the model to ferry large result lists back through tool
# arguments. It is deliberately NOT persisted (never written to SQLite or
# any long-term store — see §14 of the integration report): bounded size,
# bounded TTL, gone on restart.
# ─────────────────────────────────────────────────────────────────────────


class _ScanCache:
    def __init__(self, limits: CyberLimits) -> None:
        self._limits = limits
        self._data: dict[str, dict[str, Any]] = {}

    def _evict_if_needed(self) -> None:
        if len(self._data) <= self._limits.cache_max_domains:
            return
        oldest = min(self._data.items(), key=lambda kv: kv[1]["updated_at"])[0]
        del self._data[oldest]

    def _fresh(self, domain: str) -> dict[str, Any] | None:
        entry = self._data.get(domain)
        if entry is None:
            return None
        if time.monotonic() - entry["updated_at"] > self._limits.cache_ttl_seconds:
            return None
        return entry

    def get(self, domain: str) -> dict[str, Any] | None:
        return self._fresh(domain)

    def update(self, domain: str, **fields: Any) -> None:
        entry = self._data.setdefault(domain, {"updated_at": 0.0})
        entry.update(fields)
        entry["updated_at"] = time.monotonic()
        self._evict_if_needed()


_cache: _ScanCache | None = None


def _get_cache(limits: CyberLimits) -> _ScanCache:
    global _cache
    if _cache is None:
        _cache = _ScanCache(limits)
    return _cache


# ─────────────────────────────────────────────────────────────────────────
# Internal discovery helpers (shared by multiple operations; each caches
# its result against the authorized domain).
# ─────────────────────────────────────────────────────────────────────────


async def _subdomains_for(authorized: AuthorizedTarget, limits: CyberLimits, cache: _ScanCache) -> list[str]:
    cached = cache.get(authorized.domain)
    if cached and "subdomains" in cached:
        return cached["subdomains"]
    engine = _Engine.get()
    subs = await _run_bounded(engine.get_subdomains, authorized.domain, timeout=limits.operation_timeout_seconds)
    subs = subs or [authorized.domain]
    subs = sorted(set(subs))[: limits.max_subdomains]
    cache.update(authorized.domain, subdomains=subs)
    return subs


async def _live_hosts_for(authorized: AuthorizedTarget, limits: CyberLimits, cache: _ScanCache) -> list[dict]:
    cached = cache.get(authorized.domain)
    if cached and "live_hosts" in cached:
        return cached["live_hosts"]
    subs = await _subdomains_for(authorized, limits, cache)
    engine = _Engine.get()
    hosts = await _run_bounded(
        engine.check_alive, subs, timeout=limits.operation_timeout_seconds, guard_domain=authorized.domain
    )
    hosts = hosts or []
    hosts = [h for h in hosts if _same_domain_or_sub(h.get("url", ""), authorized.domain)]
    hosts = hosts[: limits.max_hosts]
    cache.update(authorized.domain, live_hosts=hosts)
    return hosts


def _result(operation: OperationType, authorized: AuthorizedTarget, started_at, limits: CyberLimits) -> CyberOperationResult:
    return CyberOperationResult(
        operation=operation,
        target=authorized.domain,
        scope_id=authorized.scope.id,
        started_at=started_at,
        completed_at=utcnow(),
        limits_applied=limits.model_dump(),
    )


def _cap_findings(result: CyberOperationResult, findings: list[CyberFinding], limits: CyberLimits) -> None:
    if len(findings) > limits.max_findings_per_result:
        result.findings = findings[: limits.max_findings_per_result]
        result.truncated = True
    else:
        result.findings = findings


# ─────────────────────────────────────────────────────────────────────────
# Public operations — one per OperationType. Each is self-contained: it
# takes only a domain, authorizes it, and performs exactly the bounded
# work described in the Phase 10 integration report.
# ─────────────────────────────────────────────────────────────────────────


async def run_subdomain_enum(domain: str, scope_store: ScopeStore, limits: CyberLimits) -> CyberOperationResult:
    started_at = utcnow()
    request = CyberOperationRequest(operation=OperationType.SUBDOMAIN_ENUM, target=domain)
    authorized = await authorize(request, scope_store)
    cache = _get_cache(limits)

    result = _result(OperationType.SUBDOMAIN_ENUM, authorized, started_at, limits)
    try:
        subs = await _subdomains_for(authorized, limits, cache)
    except CyberError as exc:
        result.errors.append(str(exc))
        result.counts["subdomains"] = 0
        return result
    except Exception as exc:  # noqa: BLE001 — never leak raw engine internals
        logger.error("subdomain_enum failed for %s: %s", safe_target(authorized.domain), type(exc).__name__)
        result.errors.append("subdomain enumeration failed unexpectedly")
        return result

    _cap_findings(result, [CyberFinding(type="subdomain", target=s) for s in subs], limits)
    result.counts["subdomains"] = len(subs)
    return result


async def run_alive_check(domain: str, scope_store: ScopeStore, limits: CyberLimits) -> CyberOperationResult:
    started_at = utcnow()
    request = CyberOperationRequest(operation=OperationType.ALIVE_CHECK, target=domain)
    authorized = await authorize(request, scope_store)
    cache = _get_cache(limits)

    result = _result(OperationType.ALIVE_CHECK, authorized, started_at, limits)
    try:
        hosts = await _live_hosts_for(authorized, limits, cache)
    except CyberError as exc:
        result.errors.append(str(exc))
        return result
    except Exception as exc:  # noqa: BLE001
        logger.error("alive_check failed for %s: %s", safe_target(authorized.domain), type(exc).__name__)
        result.errors.append("alive check failed unexpectedly")
        return result

    findings = [
        CyberFinding(
            type="alive_host",
            target=h.get("url", ""),
            detail=f"status={h.get('status', '?')} title={h.get('title', '')}"[:200],
        )
        for h in hosts
    ]
    _cap_findings(result, findings, limits)
    result.counts["live_hosts"] = len(hosts)
    return result


async def run_endpoint_discovery(domain: str, scope_store: ScopeStore, limits: CyberLimits) -> CyberOperationResult:
    started_at = utcnow()
    request = CyberOperationRequest(operation=OperationType.ENDPOINT_DISCOVERY, target=domain)
    authorized = await authorize(request, scope_store)
    cache = _get_cache(limits)

    result = _result(OperationType.ENDPOINT_DISCOVERY, authorized, started_at, limits)
    engine = _Engine.get()
    try:
        hosts = await _live_hosts_for(authorized, limits, cache)

        wayback = await _run_bounded(
            engine.fetch_wayback_urls, authorized.domain, timeout=limits.request_timeout_seconds
        )
        crawler_urls, _forms = await _run_bounded(
            engine.basic_crawler, hosts, timeout=limits.operation_timeout_seconds, guard_domain=authorized.domain
        )
        pool = list(dict.fromkeys((wayback or []) + (crawler_urls or [])))
        # Scope containment: a crawled/archived URL must still resolve to
        # the authorized domain or one of its subdomains. Nothing here is
        # fetched again — basic_crawler already made its one request per
        # live host — this only filters which discovered URLs are
        # reported back, same boundary as authorize_redirect() enforces
        # for an actual follow-on fetch.
        pool = [u for u in pool if _same_domain_or_sub(u, authorized.domain)]
        important = await _run_bounded(
            engine.filter_important_urls, pool, timeout=limits.request_timeout_seconds
        )
        important = (important or [])[: limits.max_endpoints]
    except CyberError as exc:
        result.errors.append(str(exc))
        return result
    except Exception as exc:  # noqa: BLE001
        logger.error("endpoint_discovery failed for %s: %s", safe_target(authorized.domain), type(exc).__name__)
        result.errors.append("endpoint discovery failed unexpectedly")
        return result

    endpoints = []
    for url in important:
        try:
            tags = engine.classify_endpoint(url)
        except Exception:  # noqa: BLE001 — classification is best-effort
            tags = []
        endpoints.append({"url": url, "tags": tags})

    cache.update(authorized.domain, endpoints=endpoints)
    findings = [
        CyberFinding(type="endpoint", target=e["url"], detail=", ".join(e["tags"])[:200])
        for e in endpoints
    ]
    _cap_findings(result, findings, limits)
    result.counts["endpoints"] = len(endpoints)
    return result


async def run_tech_fingerprint(domain: str, scope_store: ScopeStore, limits: CyberLimits) -> CyberOperationResult:
    started_at = utcnow()
    request = CyberOperationRequest(operation=OperationType.TECH_FINGERPRINT, target=domain)
    authorized = await authorize(request, scope_store)
    cache = _get_cache(limits)

    result = _result(OperationType.TECH_FINGERPRINT, authorized, started_at, limits)
    engine = _Engine.get()
    try:
        hosts = await _live_hosts_for(authorized, limits, cache)
        technologies: dict[str, list[str]] = {}
        for host in hosts[: limits.max_hosts]:
            url = host.get("url", "")
            if not url:
                continue
            try:
                techs = await _run_bounded(
                    engine.detect_technologies,
                    url,
                    timeout=limits.request_timeout_seconds,
                    guard_domain=authorized.domain,
                )
            except OperationLimitExceeded:
                continue  # one slow host does not fail the whole operation
            technologies[url] = techs or []
    except CyberError as exc:
        result.errors.append(str(exc))
        return result
    except Exception as exc:  # noqa: BLE001
        logger.error("tech_fingerprint failed for %s: %s", safe_target(authorized.domain), type(exc).__name__)
        result.errors.append("technology fingerprinting failed unexpectedly")
        return result

    cache.update(authorized.domain, technologies=technologies)
    findings = [
        CyberFinding(type="technology", target=url, detail=", ".join(techs)[:200])
        for url, techs in technologies.items()
        if techs
    ]
    _cap_findings(result, findings, limits)
    result.counts["hosts_fingerprinted"] = len(technologies)
    return result


async def run_risk_scoring(domain: str, scope_store: ScopeStore, limits: CyberLimits) -> CyberOperationResult:
    started_at = utcnow()
    request = CyberOperationRequest(operation=OperationType.RISK_SCORING, target=domain)
    authorized = await authorize(request, scope_store)
    cache = _get_cache(limits)

    cached = cache.get(authorized.domain)
    if not cached or "endpoints" not in cached or "live_hosts" not in cached:
        raise NoPriorResults(
            "no cached endpoint_discovery/alive_check results for this domain — run those operations first"
        )

    result = _result(OperationType.RISK_SCORING, authorized, started_at, limits)
    engine = _Engine.get()
    try:
        # No vulnerability-detection stage runs in this phase, so findings
        # is always empty; risk_scoring here reflects EXPOSURE SURFACE
        # (subdomain/endpoint/host counts) only, never a CVSS-scored
        # vulnerability. This is stated explicitly in the tool description.
        risk = await _run_bounded(
            engine.calculate_risk,
            cached["endpoints"],
            cached["live_hosts"],
            [],
            timeout=limits.request_timeout_seconds,
        )
    except CyberError as exc:
        result.errors.append(str(exc))
        return result
    except Exception as exc:  # noqa: BLE001
        logger.error("risk_scoring failed for %s: %s", safe_target(authorized.domain), type(exc).__name__)
        result.errors.append("risk scoring failed unexpectedly")
        return result

    cache.update(authorized.domain, risk=risk)
    summary = risk.get("summary", {}) if isinstance(risk, dict) else {}
    findings = [
        CyberFinding(
            type="risk_summary",
            target=authorized.domain,
            detail=(
                f"overall_risk_level={summary.get('overall_risk_level', 'UNKNOWN')} "
                f"security_score={summary.get('security_score', 'N/A')}"
            ),
        )
    ]
    _cap_findings(result, findings, limits)
    result.counts = {
        "endpoints_scored": len(cached.get("endpoints", [])),
        "hosts_considered": len(cached.get("live_hosts", [])),
    }
    return result


_report_lock = asyncio.Lock()


async def run_report_generation(domain: str, scope_store: ScopeStore, limits: CyberLimits) -> CyberReportMetadata:
    from app.config.settings import settings

    request = CyberOperationRequest(operation=OperationType.REPORT_GENERATION, target=domain)
    authorized = await authorize(request, scope_store)
    cache = _get_cache(limits)

    cached = cache.get(authorized.domain)
    if not cached or "endpoints" not in cached or "live_hosts" not in cached:
        raise NoPriorResults(
            "no cached endpoint_discovery/alive_check results for this domain — run those operations first"
        )

    if not settings.cybersecurity_report_dir:
        raise ReportPathError("no report output directory is configured (CYBERSECURITY_REPORT_DIR)")
    report_root = Path(settings.cybersecurity_report_dir).resolve()
    report_root.mkdir(parents=True, exist_ok=True)

    engine = _Engine.get()
    risk = cached.get("risk") or {"critical": [], "high": [], "medium": [], "low": [], "summary": {}}

    # The vendored generator writes to a hardcoded "reports/<domain>_report.txt"
    # path RELATIVE TO THE PROCESS CWD — it accepts no output_dir parameter
    # (see the integration report's "Reporting" section for why this is not
    # patched in place). A lock serializes concurrent report calls so two
    # requests for the same domain can't interleave writes to that shared
    # path; the file is moved into the confined, configured directory
    # immediately afterward, still under the lock, before anything else can
    # touch it.
    async with _report_lock:
        produced_path_str = await _run_bounded(
            engine.generate_report,
            authorized.domain,
            cached["live_hosts"],
            cached["endpoints"],
            [],
            risk,
            timeout=limits.request_timeout_seconds,
        )
        produced_path = Path(produced_path_str).resolve()
        report_id = uuid.uuid4().hex[:12]
        destination = report_root / f"{report_id}_{produced_path.name}"
        destination = destination.resolve()
        if report_root not in destination.parents and destination != report_root:
            # Defense in depth: this should be unreachable given the fixed
            # filename pattern above, but a report is never allowed to land
            # outside the configured directory regardless.
            raise ReportPathError("computed report path escapes the configured report directory")
        shutil.move(str(produced_path), str(destination))

    return CyberReportMetadata(
        report_id=report_id,
        domain=authorized.domain,
        format="text",
        finding_count=len(cached["endpoints"]),
        generated_at=utcnow(),
        relative_path=destination.relative_to(report_root).as_posix(),
    )
