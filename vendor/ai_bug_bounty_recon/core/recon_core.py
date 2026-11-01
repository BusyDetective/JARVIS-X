"""
recon_core.py — Orchestration layer for the AI Bug Bounty Recon &
Vulnerability Assessment Platform.

v3 architectural refactor:
- ScanContext dataclass introduced as the single mutable state carrier.
  Every stage reads from and writes to ctx; large argument lists eliminated.
- _run_stage() wrapper measures per-stage elapsed time, logs structured
  Stage / Elapsed / Items / Errors / Warnings lines, and stores failures in
  ctx.metadata["stage_errors"] so one bad stage never kills the scan.
- Parsed-URL cache (_parsed_url) eliminates repeated urlparse() calls.
- Technology fingerprints, browser results, and baseline responses reused
  across stages via ScanContext fields.
- detection_engine integration promoted to its own named stage with full
  EndpointContext construction per endpoint.
- run_recon() return dict unchanged (backwards compatible).
"""

import subprocess
from core.alive_check import check_alive
import os
import time
import requests
from bs4 import BeautifulSoup
from concurrent.futures import ThreadPoolExecutor, as_completed
import re
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
from ai_engine.risk_scoring import calculate_risk
from core.intelligence import analyze_all
from core.vuln_engine import (
    run_vuln_scan,
    VulnEngine        as _VulnEngine,
    ScanConfig        as _ScanConfig,
    extract_scan_stats as _extract_scan_stats,
    filter_real_findings as _filter_real_findings,
)
from core.classifier import classify_endpoint
from ai_engine.exploit_generator import generate_exploit
from ai_engine.auto_validator import validate_all
from ai_engine.prioritizer import prioritize_all
from ai_engine.real_validator import validate_open_redirect, validate_xss, validate_sqli
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, urlunparse
from core.screenshot import capture_screenshot
from core.tech_fingerprint import detect_technologies
from core.dir_fuzzer import fuzz_directories
from core.js_intelligence import analyze_js_files
from ai_engine.cvss import calculate_cvss
from core.browser_recon import browser_recon
from ai_engine.attack_mapper import map_attack_surface
from core.attack_surface_mapper import generate_attack_surface
from ai_engine.finding_grouper import group_findings
import html
import logging
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)

# ── Optional DetectionEngine integration ──────────────────────────────────────
try:
    from ai_engine.detection_engine import (
        DETECTION_ENGINE,
        EndpointContext,
        AuthState,
    )
    _DE_AVAILABLE = True
except ImportError:
    _DE_AVAILABLE = False

# ── Canonical finding identity helpers from VulnEngine ────────────────────────
# Reuse the same normalisation logic so recon_core never has a divergent copy.
try:
    from core.vuln_engine import (
        _normalise_url as _norm_url,
        _is_endpoint_level as _ep_level,
        ENDPOINT_LEVEL_CLASSES as _EP_CLASSES,
    )
    _DEDUP_HELPERS_AVAILABLE = True
except ImportError:
    # Fallback implementations if vuln_engine import fails (e.g. unit-test stubs)
    def _norm_url(url: str) -> str:
        try:
            from urllib.parse import urlparse as _up
            p = _up(url)
            return f"{p.scheme}://{p.netloc}{p.path}".rstrip("/")
        except Exception:
            return url

    _EP_CLASSES = frozenset({
        "MISSING_CSP", "MISSING_HSTS", "MISSING_REFERRER_POLICY",
        "MISSING_X_FRAME_OPTIONS", "MISSING_X_CONTENT_TYPE_OPTIONS",
        "MISSING_PERMISSIONS_POLICY", "MISSING_CACHE_CONTROL",
        "MISSING_COEP", "MISSING_COOP",
        "SERVER_HEADER_DISCLOSURE", "X_POWERED_BY_DISCLOSURE",
        "TECHNOLOGY_DISCLOSURE",
        "CORS", "CORS_MISCONFIGURATION",
        "CLICKJACKING",
        "HOST_HEADER_INJECTION",
        "DEBUG", "SUBDOMAIN_TAKEOVER",
        "MISCONFIGURATION",
        "INFORMATION DISCLOSURE", "INFORMATION_DISCLOSURE",
    })

    def _ep_level(vuln_class: str) -> bool:
        return vuln_class.upper().strip() in _EP_CLASSES

    _DEDUP_HELPERS_AVAILABLE = False

# ── Map Smart Test finding type strings → canonical vuln class tokens ─────────
# Used to classify smart findings into endpoint-level vs parameter-level for
# the canonical dedup key.  Keep in sync with ENDPOINT_LEVEL_CLASSES in
# vuln_engine.py.  Values must be strings that _ep_level() will recognise.
_SMART_TYPE_TO_VULN_CLASS: dict = {
    "missing content-security-policy":     "MISSING_CSP",
    "missing x-frame-options":             "MISSING_X_FRAME_OPTIONS",
    "missing x-content-type-options":      "MISSING_X_CONTENT_TYPE_OPTIONS",
    "missing strict-transport-security":   "MISSING_HSTS",
    "missing referrer-policy":             "MISSING_REFERRER_POLICY",
    "cors misconfiguration":               "CORS_MISCONFIGURATION",
    "information disclosure":              "INFORMATION_DISCLOSURE",
    "technology disclosure":               "TECHNOLOGY_DISCLOSURE",
    "cookie missing httponly":             "MISSING_HTTPONLY",
    "cookie missing secure":               "MISSING_SECURE_FLAG",
    "reflected xss":                       "XSS",
    "open redirect":                       "OPEN_REDIRECT",
}

# Smart finding types that are attack-surface intelligence (not confirmed vulns)
# These become CANDIDATES for VulnEngine/AI validation, not immediate findings.
_SMART_CANDIDATE_TYPES: frozenset = frozenset({
    "admin panel detected",
    "login endpoint",
    "registration endpoint",
    "health check endpoint",
    "graphql endpoint",
    "api documentation exposed",
    "potential idor",
    "potential idor (uuid)",
    "potential lfi",
    "potential ssrf",
    "potential rce",
    # intelligence.py outputs that should not auto-confirm
    "auth token endpoint",
    "oauth callback endpoint",
    "password reset endpoint",
    "email verification endpoint",
    "mfa endpoint",
    "login endpoint",
    "logout endpoint",
    "user data api endpoint",
    "data export api endpoint",
    "delete operation api endpoint",
    "file upload api endpoint",
    "internal api endpoint",
    "private api endpoint",
    "admin api endpoint",
    "graphql endpoint",
    "s3 bucket url",
    "gcs bucket url",
    "azure blob storage url",
    "data export endpoint",
    "report download endpoint",
    "financial document endpoint",
    "payment endpoint",
})


# ===============================================
# PLAN-DRIVEN DETECTION ENGINE ADAPTER
# ===============================================

class _PlanDrivenDE:
    """
    Adapts pre-built per-endpoint DetectionRule lists (from
    _stage_detection_engine) into the get_vuln_classes() / get_payloads()
    interface that VulnEngine._get_vuln_classes() and VulnEngine._get_payloads()
    call.

    ARCHITECTURAL NOTE — global aggregation is intentional:
    ────────────────────────────────────────────────────────
    VulnEngine.scan() calls self._de.get_payloads(vuln_class) with NO url
    argument.  The call happens inside _test_vuln_class(), which receives the
    url, but the payload-fetch is dispatched through self._de with only the
    vuln_class token.  There is no endpoint-specific hook in the current API.

    Consequence: per-endpoint recommended_payloads must be collapsed to a
    per-class union before being handed to VulnEngine.  This means an endpoint
    that was NOT flagged for XSS by the DetectionEngine may still receive XSS
    payloads if any other endpoint in the scan was flagged.  This is
    inefficient but not incorrect:
      - The payloads are generic attack strings, not endpoint-specific secrets.
      - FindingRegistry + execution cache prevent false confirmations.
      - stop_on_confirmation and per-class budgets contain the extra work.

    The correct fix requires a one-line change to VulnEngine._test_vuln_class:

        # Pass url so the adapter can filter to endpoint-specific payloads
        raw_payloads = self._get_payloads(vuln_class, url=url)

    and a corresponding signature extension in get_payloads(vuln_class, url=None).
    That change touches vuln_engine.py, which is outside the current scope.
    When it is made, replace this class's get_payloads() with:

        def get_payloads(self, vuln_class, url=None):
            norm = _norm_url(url) if url else None
            ep_plans = self._plans.get(norm, {}) if norm else {}
            payloads = ep_plans.get(vuln_class.upper(), [])
            if not payloads:
                payloads = self._class_payloads.get(vuln_class.upper(), [])
            return payloads

    VulnEngine dispatch note:
        _execute_payload() tries adapters in priority order:
            1. test_endpoint(url, payload, param)            — does NOT receive vuln_class
            2. test_payload(vuln_class, url, param, payload) — DOES receive vuln_class
            3. scan_parameter(url, param, payload)           — does NOT receive vuln_class
        _PlanDrivenDE intentionally implements ONLY test_payload so that
        VulnEngine uses branch 2 and passes the class directly.
        test_endpoint must NOT be added here — it would shadow test_payload
        and reintroduce the class-inference problem.
    """

    def __init__(self, plans: dict) -> None:
        """
        plans: {url_str: list[DetectionRule]}
        Builds a global per-class payload union for the current VulnEngine API.
        Also stores the full per-endpoint plan index for future endpoint-aware
        get_payloads() when VulnEngine gains the url argument.
        """
        # Global union: {VULN_CLASS_UPPER -> [payload, ...]}  (insertion-ordered, deduped)
        self._class_payloads: dict = {}
        # Per-endpoint index: {norm_url -> {VULN_CLASS_UPPER -> [payload, ...]}}
        # Populated now; used only once VulnEngine passes url to get_payloads().
        self._plans: dict = {}
        # Per-endpoint request metadata: {norm_url -> {method, body_params, content_type}}
        # Populated by populate_meta() after scan_targets are built.
        self._endpoint_meta: dict = {}

        for raw_url, rule_list in plans.items():
            norm = _norm_url(raw_url)
            ep_entry = self._plans.setdefault(norm, {})
            for rule in rule_list:
                group = rule.payload_group.upper()
                # Per-endpoint index
                ep_payloads = ep_entry.setdefault(group, [])
                for p in rule.recommended_payloads:
                    if p not in ep_payloads:
                        ep_payloads.append(p)
                # Global union
                global_list = self._class_payloads.setdefault(group, [])
                for p in rule.recommended_payloads:
                    if p not in global_list:
                        global_list.append(p)

    def populate_meta(self, endpoint_dicts: list) -> None:
        """
        Populate _endpoint_meta from the endpoint dicts passed to VulnEngine.

        Called by _run_vuln_with_stats() after endpoint_dicts are finalised
        so that test_payload() can look up the correct HTTP method and body
        parameter names for each endpoint without changing VulnEngine's API.

        endpoint_dicts: [{"url": str, "method": str, "body_params": list, ...}]
        """
        for ep in endpoint_dicts:
            raw_url = ep.get("url", "")
            if not raw_url:
                continue
            norm = _norm_url(raw_url)
            self._endpoint_meta[norm] = {
                "method":       ep.get("method", "GET"),
                "body_params":  ep.get("body_params", []),
                "content_type": ep.get("content_type", ""),
            }

    def get_vuln_classes(self) -> list:
        """Return every vuln class for which at least one endpoint has payloads."""
        return list(self._class_payloads.keys())

    def get_payloads(self, vuln_class: str) -> list:
        """
        Return payloads for vuln_class.  Currently uses the global union
        because VulnEngine does not pass the url.  Falls back to
        DETECTION_ENGINE.select_payloads() for classes that appeared in plans
        but had no recommended_payloads populated.
        """
        group = vuln_class.upper().strip()
        payloads = self._class_payloads.get(group, [])
        if payloads:
            return payloads
        # Fallback: ask DETECTION_ENGINE directly (covers vuln_id vs group mismatch)
        if _DE_AVAILABLE and hasattr(DETECTION_ENGINE, "select_payloads"):
            try:
                return DETECTION_ENGINE.select_payloads(vuln_class)
            except Exception:
                pass
        return []

    def endpoint_payloads(self, url: str, vuln_class: str) -> list:
        """
        Endpoint-specific payload lookup — not yet called by VulnEngine.
        Exposed here so tests can verify per-endpoint correctness today
        and VulnEngine can call it once it gains the url argument.
        """
        norm = _norm_url(url)
        return self._plans.get(norm, {}).get(vuln_class.upper(), [])

    # ── HTTP execution telemetry (readable by tests) ──────────────────────
    # These are instance counters updated by test_payload().
    # They are separate from VulnEngine's payloads_attempted, which is a
    # budget-slot counter incremented BEFORE _execute_payload() is called.
    http_requests_attempted: int = 0   # actual HTTP calls made
    http_request_failures:   int = 0   # network/timeout errors
    http_signals_detected:   int = 0   # responses with confidence > 0

    def test_payload(
        self,
        vuln_class: str,
        url: str,
        param: str,
        payload: str,
    ) -> dict:
        """
        Execute one payload against the target and return a result dict
        compatible with VulnEngine._test_vuln_class().

        VulnEngine dispatches here via _execute_payload() when test_endpoint()
        is absent and test_payload() is present (second-priority branch).
        The signature matches exactly what VulnEngine passes:

            de.test_payload(vuln_class, url, param, payload)

        Return contract:
            confidence=0  → request succeeded, no vulnerability signal
            confidence>0  → signal detected; VulnEngine will register a finding
            None/missing  → treated same as confidence=0 by VulnEngine

        vuln_class is used DIRECTLY — never inferred from payload content.
        This means an identical payload string produces different HTTP request
        construction and different response analysis depending on the class:

            payload="https://evil.com", vuln_class="SSRF"
                → fetch-probe construction, body/connection analysis

            payload="https://evil.com", vuln_class="OPEN_REDIRECT"
                → param-substitution construction, Location header analysis
        """
        # Extract payload string (VulnEngine may pass a dict or a raw string)
        if isinstance(payload, dict):
            payload_str = payload.get("payload", "")
        else:
            payload_str = str(payload)

        if not payload_str:
            return {"confidence": 0, "status_code": None}

        # ── Look up per-endpoint request metadata populated by populate_meta() ─
        norm = _norm_url(url)
        ep_meta     = self._endpoint_meta.get(norm, {})
        ep_method   = ep_meta.get("method",       "GET").upper()
        ep_body     = ep_meta.get("body_params",   [])
        ep_ctype    = ep_meta.get("content_type",  "").lower()

        # ── Decide request style ───────────────────────────────────────────────
        # CORS/SSRF/OPEN_REDIRECT have their own special-case construction inside
        # _build_test_request() and always use GET — preserve that entirely.
        # For everything else: use the discovered HTTP method.
        use_post = (
            ep_method == "POST"
            and ep_body                           # at least one body param known
            and vuln_class not in ("CORS", "SSRF", "OPEN_REDIRECT")
            and not (payload_str.lower().startswith("origin:"))
        )

        self.http_requests_attempted += 1

        if use_post:
            # ── POST request: inject payload into body ─────────────────────
            # The URL is not modified (no query-param injection for POST body).
            # Other body parameters receive a safe generic placeholder so the
            # server sees a well-formed request and does not reject it early.
            r = _make_post_request(
                url=url,
                tested_param=param,
                payload=payload_str,
                body_params=ep_body,
                content_type=ep_ctype,
                request_headers=dict(HEADERS),
            )
        else:
            # ── GET request (existing path, fully preserved) ───────────────
            test_url, request_headers, allow_redirects = _build_test_request(
                url, param, payload_str, vuln_class
            )
            try:
                r = session.get(
                    test_url,
                    headers=request_headers,
                    timeout=8,
                    verify=False,
                    allow_redirects=allow_redirects,
                )
            except Exception:
                self.http_request_failures += 1
                return {"confidence": 0, "status_code": None}

        if r is None:
            self.http_request_failures += 1
            return {"confidence": 0, "status_code": None}

        # ── Analyse the response for vulnerability signals ─────────────────
        # vuln_class is passed directly so _analyse_response applies the
        # correct class-specific detection logic without any heuristic.
        result = _analyse_response(r, payload_str, param, vuln_class)

        if result.get("confidence", 0) > 0:
            self.http_signals_detected += 1

        return result


def _make_post_request(
    url: str,
    tested_param: str,
    payload: str,
    body_params: list,
    content_type: str,
    request_headers: dict,
):
    """
    Make a POST request, injecting the payload into `tested_param` and
    filling other discovered body parameters with safe placeholder values.

    Rules:
    - Only body parameters discovered during recon (body_params) are sent.
      No parameter names are invented.
    - The tested parameter receives the raw payload string.
    - All other body parameters receive the safe placeholder "x" so the
      server sees a structurally valid request and does not reject it before
      reaching the vulnerable code path.
    - For application/json (or json-like enctype), uses session.post(..., json=body).
    - For application/x-www-form-urlencoded (default), uses session.post(..., data=body).
    - CORS/SSRF/OPEN_REDIRECT are never routed here (handled by caller).
    - Returns None on network/timeout exception (caller increments failure counter).

    Content-type decision:
        "json" anywhere in content_type  → JSON body
        anything else (including "")     → form-encoded body (safest default)
    """
    SAFE_PLACEHOLDER = "x"

    # Build the body: all known params populated, tested param gets payload
    body = {}
    for bp in body_params:
        body[bp] = payload if bp == tested_param else SAFE_PLACEHOLDER

    # If param is not in body_params (e.g. a path/query param being tested
    # on a POST endpoint), include it anyway so the payload reaches the server
    if tested_param and tested_param not in body:
        body[tested_param] = payload

    # Select encoding
    use_json = "json" in content_type

    try:
        if use_json:
            hdrs = {**request_headers, "Content-Type": "application/json"}
            return session.post(
                url,
                json=body,
                headers=hdrs,
                timeout=8,
                verify=False,
                allow_redirects=False,
            )
        else:
            hdrs = {**request_headers, "Content-Type": "application/x-www-form-urlencoded"}
            return session.post(
                url,
                data=body,
                headers=hdrs,
                timeout=8,
                verify=False,
                allow_redirects=False,
            )
    except Exception:
        return None


def _build_test_request(
    url: str, param: str, payload: str, vuln_class: str
) -> tuple:
    """
    Build (test_url, headers, allow_redirects) for a payload injection.

    Injection rules:
    - Named param in existing query string → replace its value
    - Named param not in query string     → append as new param
    - Empty param                          → use URL unchanged (header checks)
    - CORS/SSRF                            → inject via Origin/custom header
    - OPEN_REDIRECT                        → do not follow redirects

    Returns a (url_str, headers_dict, allow_redirects_bool) triple.
    """
    from urllib.parse import urlparse as _up, parse_qs as _pqs, urlencode as _ue, urlunparse as _uu
    import requests as _req

    headers = dict(HEADERS)
    allow_redirects = True

    # CORS: inject via Origin header, not URL param
    if vuln_class in ("CORS",) or payload.lower().startswith("origin:"):
        origin_val = payload.split(":", 1)[-1].strip() if ":" in payload else payload
        headers["Origin"] = origin_val
        return url, headers, False

    # OPEN_REDIRECT: never follow so we can inspect Location header
    if vuln_class == "OPEN_REDIRECT":
        allow_redirects = False

    # SSRF with no param: test as-is (bare URL already embeds the target)
    if not param and vuln_class == "SSRF":
        return url, headers, False

    if not param:
        # No param specified — append payload as generic probe param
        sep = "&" if "?" in url else "?"
        return f"{url}{sep}_p={_req.utils.quote(payload)}", headers, allow_redirects

    # Named param injection
    parsed = _up(url)
    qs = _pqs(parsed.query, keep_blank_values=True)

    if param in qs:
        # Replace existing value
        qs[param] = [payload]
        test_url = _uu(parsed._replace(query=_ue(qs, doseq=True)))
    else:
        # Append new param
        sep = "&" if parsed.query else ""
        test_url = _uu(parsed._replace(
            query=f"{parsed.query}{sep}{_req.utils.quote(param)}={_req.utils.quote(payload)}"
        ))

    return test_url, headers, allow_redirects


def _analyse_response(
    r,
    payload: str,
    param: str,
    vuln_class: str,
) -> dict:
    """
    Analyse an HTTP response for vulnerability signals.

    Returns a result dict with confidence=0 if no signal is found.
    Mirrors the detection logic already present in smart_test_endpoint()
    — no new parallel validation system is created.

    Signal thresholds:
        60  — Likely   (soft signal, pattern match)
        75  — Probable (strong signal, contextual match)
        85  — Confirmed (definitive signal, e.g. payload executed)

    confidence=0 is returned for:
        - generic HTTP 200 with no payload reflection or error signal
        - timeouts and connection errors (handled by caller)
        - any case where the evidence is ambiguous
    """
    status = r.status_code
    body   = r.text          # original case for payload matching
    body_l = body.lower()
    ctype  = r.headers.get("Content-Type", "")

    # ── XSS: payload must be reflected in HTML context ─────────────────────
    if vuln_class == "XSS":
        p = payload if isinstance(payload, str) else ""
        # Require the exact payload string in the body AND an HTML content type.
        # A generic 200 with no reflection is confidence=0.
        if p and p in body and "text/html" in ctype:
            # Additionally require that it appears in a tag-like context,
            # not just in a JSON error message or escaped attribute.
            p_lower = p.lower()
            if any(sig in p_lower for sig in ["<script", "onerror=", "onload=",
                                               "javascript:", "alert(", "svg"]):
                return {
                    "confidence":       75,
                    "severity":         "High",
                    "cvss":             6.1,
                    "evidence":         f"Payload reflected in HTML: {p[:80]}",
                    "reason":           "Reflected XSS — payload present in HTML response",
                    "validation_state": "Likely",
                    "status_code":      status,
                    "xss_type":         "reflected",
                }
        return {"confidence": 0, "status_code": status}

    # ── SQLI: error-based or time-based signals ────────────────────────────
    if vuln_class == "SQLI":
        sql_errors = [
            "sql syntax", "mysql_fetch", "ora-", "pg_query",
            "sqlite3", "unclosed quotation mark",
            "you have an error in your sql syntax",
            "warning: mysql", "supplied argument is not a valid mysql",
            "microsoft ole db provider for sql server",
            "odbc sql server driver", "postgresql error",
            "syntax error at or near", "unterminated quoted string",
            # SQLite / Sequelize ORM (Juice Shop and Node.js apps)
            "sqlite_error",            # "SQLITE_ERROR: near ..." → lowercased
            "sequelizedatabaseerror",  # "SequelizeDatabaseError: ..." → lowercased
        ]
        for sig in sql_errors:
            if sig in body_l:
                return {
                    "confidence":       75,
                    "severity":         "High",
                    "cvss":             8.8,
                    "evidence":         f"SQL error pattern: '{sig}'",
                    "reason":           "SQL injection — database error disclosed",
                    "validation_state": "Likely",
                    "status_code":      status,
                    "sqli_type":        "error-based",
                }
        # Blind time-based: if the caller injected SLEEP/WAITFOR, a 5s+ response
        # is a strong signal.  We can't measure elapsed time here (the caller
        # already awaited), so we only report time-based if we have elapsed-time
        # context — which we don't in this adapter.  Skip to avoid false positives.
        return {"confidence": 0, "status_code": status}

    # ── OPEN_REDIRECT: Location header points to injected target ───────────
    if vuln_class == "OPEN_REDIRECT":
        if status in (301, 302, 303, 307, 308):
            location = r.headers.get("Location", "")
            # Require the payload domain/path to appear in Location
            p_lower = payload.lower()
            loc_lower = location.lower()
            if (p_lower in loc_lower or
                    any(x in loc_lower for x in ["evil.com", "attacker.com", "example.com"])):
                return {
                    "confidence":       80,
                    "severity":         "High",
                    "cvss":             6.1,
                    "evidence":         f"Location: {location}",
                    "reason":           "Open redirect — Location header follows payload",
                    "validation_state": "Likely",
                    "status_code":      status,
                    "oauth_redirect":   False,
                }
        return {"confidence": 0, "status_code": status}

    # ── SSRF: internal content or error signatures ─────────────────────────
    if vuln_class == "SSRF":
        ssrf_signals = [
            "ami-id", "instance-id", "iam/security-credentials",
            "root:x:0:0", "/bin/bash", "localhost",
            "internal server", "connection refused",
        ]
        for sig in ssrf_signals:
            if sig in body_l:
                return {
                    "confidence":       70,
                    "severity":         "Critical",
                    "cvss":             9.1,
                    "evidence":         f"SSRF signal: '{sig}' in response",
                    "reason":           "Potential SSRF — internal content in response",
                    "validation_state": "Likely",
                    "status_code":      status,
                    "ssrf_egress":      True,
                }
        return {"confidence": 0, "status_code": status}

    # ── LFI: file content signatures ──────────────────────────────────────
    if vuln_class == "LFI":
        lfi_signals = [
            "root:x:0:0", "daemon:x:", "/bin/bash", "/usr/sbin",
            "[boot loader]", "[operating systems]",
            "for 16-bit app support",
        ]
        for sig in lfi_signals:
            if sig in body_l:
                return {
                    "confidence":       80,
                    "severity":         "Critical",
                    "cvss":             9.8,
                    "evidence":         f"LFI signal: '{sig}' in response",
                    "reason":           "Local file inclusion — system file content in response",
                    "validation_state": "Confirmed",
                    "status_code":      status,
                    "lfi_rce_evidence": True,
                }
        return {"confidence": 0, "status_code": status}

    # ── CORS: origin reflected or wildcard ────────────────────────────────
    if vuln_class == "CORS":
        acao = r.headers.get("Access-Control-Allow-Origin", "")
        acac = r.headers.get("Access-Control-Allow-Credentials", "")
        if acao in ("*",) or (acao and "evil" in acao.lower()):
            creds = acac.lower() == "true"
            return {
                "confidence":       80,
                "severity":         "High" if creds else "Medium",
                "cvss":             7.9 if creds else 5.4,
                "evidence":         f"ACAO: {acao}, Credentials: {acac}",
                "reason":           "CORS misconfiguration — origin reflected or wildcard",
                "validation_state": "Confirmed",
                "status_code":      status,
                "cors_credentials": creds,
            }
        return {"confidence": 0, "status_code": status}

    # ── SSTI: template execution evidence ─────────────────────────────────
    if vuln_class == "SSTI":
        # Payloads like {{7*7}} should produce "49" in the response
        if "{{7*7}}" in payload and "49" in body:
            return {
                "confidence":       85,
                "severity":         "Critical",
                "cvss":             9.8,
                "evidence":         "Template expression {{7*7}} evaluated to 49",
                "reason":           "SSTI — template injection confirmed",
                "validation_state": "Confirmed",
                "status_code":      status,
            }
        return {"confidence": 0, "status_code": status}

    # ── GENERIC / unrecognised class: no signal ────────────────────────────
    return {"confidence": 0, "status_code": status}


# ===============================================
# SCAN CONTEXT
# ===============================================

@dataclass
class ScanContext:
    """
    Single mutable state carrier passed through every recon stage.

    Every stage reads inputs from ctx and writes outputs back to ctx,
    eliminating large argument lists and allowing any stage to access
    results produced by any earlier stage.
    """
    # Target
    domain: str = ""

    # Stage outputs
    subdomains: list = field(default_factory=list)
    live_hosts: list = field(default_factory=list)
    ports: dict = field(default_factory=dict)
    technologies: dict = field(default_factory=dict)
    browser_recon: list = field(default_factory=list)
    screenshots: list = field(default_factory=list)
    directories: dict = field(default_factory=dict)
    js_files: list = field(default_factory=list)
    js_intelligence: list = field(default_factory=list)
    secrets: list = field(default_factory=list)
    wayback_urls: list = field(default_factory=list)
    important_urls: list = field(default_factory=list)
    form_endpoints: list = field(default_factory=list)  # [{url,method,body_params,content_type}]
    endpoints: list = field(default_factory=list)
    parameters: list = field(default_factory=list)
    analysis: list = field(default_factory=list)
    findings: list = field(default_factory=list)
    risk: dict = field(default_factory=dict)
    priorities: list = field(default_factory=list)
    attack_surface: dict = field(default_factory=dict)
    attack_surface_map: dict = field(default_factory=dict)
    validated_exploits: list = field(default_factory=list)

    # Scan metadata
    metadata: dict = field(default_factory=lambda: {
        "stage_errors": {},      # stage_name -> error string
        "stage_warnings": {},    # stage_name -> [warning strings]
        "stage_items": {},       # stage_name -> item count processed
    })
    timings: dict = field(default_factory=dict)      # stage_name -> elapsed seconds
    statistics: dict = field(default_factory=dict)   # populated at end of run_recon

    # Caches shared across stages
    _parsed_url_cache: dict = field(default_factory=dict, repr=False)

    def parsed_url(self, url: str):
        """Return a cached ParseResult for url (avoids repeated urlparse calls)."""
        if url not in self._parsed_url_cache:
            self._parsed_url_cache[url] = urlparse(url)
        return self._parsed_url_cache[url]

    def tech_for(self, url: str) -> list:
        """Return technology list for a URL, falling back to host-level lookup."""
        if url in self.technologies:
            return self.technologies[url]
        parsed = self.parsed_url(url)
        host_url = f"{parsed.scheme}://{parsed.netloc}"
        return self.technologies.get(host_url, [])

    def add_warning(self, stage: str, msg: str) -> None:
        self.metadata["stage_warnings"].setdefault(stage, []).append(msg)

    def to_result_dict(self) -> dict:
        """
        Return the same dictionary format that run_recon() has always returned.
        Backwards compatible — every existing key is preserved.
        """
        return {
            "domain": self.domain,
            "subdomains": self.subdomains,
            "live_hosts": self.live_hosts,
            "ports": self.ports,
            "technologies": self.technologies,
            "browser_recon": self.browser_recon,
            "screenshots": self.screenshots,
            "directories": self.directories,
            "js_files": self.js_files,
            "js_intelligence": self.js_intelligence,
            "secrets": self.secrets,
            "wayback_urls": self.wayback_urls,
            "important_urls": self.important_urls,
            "form_endpoints": self.form_endpoints,
            "endpoints": self.endpoints,
            "parameters": self.parameters,
            "analysis": self.analysis,
            "findings": self.findings,
            "verified": self.findings,          # legacy alias
            "risk": self.risk,
            "priorities": self.priorities,
            "attack_surface": self.attack_surface,
            "attack_surface_map": self.attack_surface_map,
            "exploits": self.metadata.get("exploits", []),
            "validated_exploits": self.validated_exploits,
            # v3 additions (additive — do not break existing consumers)
            "timings": self.timings,
            "statistics": self.statistics,
            "stage_errors": self.metadata.get("stage_errors", {}),
        }


# ===============================================
# STAGE RUNNER
# ===============================================

def _run_stage(ctx: ScanContext, stage_name: str, fn, *args, **kwargs) -> Any:
    """
    Execute one recon stage with timing, structured logging, and error isolation.

    - Measures wall-clock elapsed time and stores it in ctx.timings.
    - Prints Stage / Elapsed / Items / Errors / Warnings summary lines.
    - If fn raises, stores the error in ctx.metadata["stage_errors"] and
      returns None so the scan continues.

    Args:
        ctx:        ScanContext instance (mutated in place by fn).
        stage_name: Human-readable stage label (used in logs and timings key).
        fn:         Callable to execute. Receives *args, **kwargs.
        *args:      Positional arguments forwarded to fn.
        **kwargs:   Keyword arguments forwarded to fn.

    Returns:
        Whatever fn returns, or None on failure.
    """
    sep = "─" * 54
    print(f"\n{sep}")
    print(f"[STAGE] {stage_name}")
    print(sep)

    t_start = time.perf_counter()
    result = None
    error = None

    try:
        result = fn(*args, **kwargs)
    except Exception as exc:
        error = str(exc)
        ctx.metadata["stage_errors"][stage_name] = error
        logger.error("[STAGE] %s FAILED: %s", stage_name, exc, exc_info=True)

    elapsed = round(time.perf_counter() - t_start, 2)
    ctx.timings[stage_name] = elapsed

    # Determine item count: int result, len of list/dict, or 0
    items = 0
    if result is not None:
        if isinstance(result, int):
            items = result
        elif hasattr(result, "__len__"):
            items = len(result)

    warnings = ctx.metadata["stage_warnings"].get(stage_name, [])
    ctx.metadata["stage_items"][stage_name] = items

    status = "FAILED" if error else "OK"
    print(f"[STAGE] {stage_name:<35} status={status:<6}  "
          f"elapsed={elapsed:>6.2f}s  items={items}  "
          f"warnings={len(warnings)}  errors={1 if error else 0}")

    if error:
        print(f"  [!] Error: {error}")
    for w in warnings:
        print(f"  [W] {w}")

    return result

HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/120.0.0.0 Safari/537.36"
    )
}

session = requests.Session()
session.headers.update(HEADERS)
session.verify = False

# Static asset extensions to skip when processing URLs
SKIP_EXTENSIONS = {
    ".js", ".css", ".png", ".jpg", ".jpeg", ".gif",
    ".svg", ".woff", ".woff2", ".ttf", ".ico", ".pdf",
    ".zip", ".mp4", ".mp3", ".webp", ".map"
}

# Parameters that are noise and not worth testing
NOISE_PARAMS = {
    "utm_source", "utm_medium", "utm_campaign", "utm_content",
    "utm_term", "fbclid", "gclid", "lang", "theme", "locale",
    "_ga", "ref", "source", "v", "ver", "cb", "t"
}


# ===============================================
# SUBDOMAIN ENUMERATION
# ===============================================

def get_subdomains(domain):
    """Enumerate subdomains using multiple sources."""

    print(f"[+] Enumerating subdomains for {domain}...")

    subdomains = set()

    # ------------------------------------------------
    # Source 1 - Sublist3r
    # ------------------------------------------------
    try:

        result = subprocess.run(
            ["sublist3r", "-d", domain],
            capture_output=True,
            text=True,
            timeout=120
        )

        for line in result.stdout.splitlines():

            clean = re.sub(
                r"\x1b\[[0-9;]*m",
                "",
                line
            ).strip()

            if (
                clean
                and "." in clean
                and " " not in clean
                and not clean.startswith("[")
            ):
                subdomains.add(clean.lower())

        print(f"[+] Sublist3r: {len(subdomains)}")

    except subprocess.TimeoutExpired:
        print("[-] Sublist3r timeout")

    except FileNotFoundError:
        print("[-] Sublist3r not installed")

    except Exception as e:
        print(f"[-] Sublist3r error: {e}")

    # ------------------------------------------------
    # Source 2 - crt.sh
    # ------------------------------------------------
    try:

        url = (
            f"https://crt.sh/"
            f"?q=%.{domain}&output=json"
        )

        response = session.get(
            url,
            headers=HEADERS,
            timeout=20
        )

        if response.ok:

            for item in response.json():

                for name in item.get("name_value", "").split("\n"):

                    name = name.replace("*.", "").strip().lower()

                    if name.endswith(domain):
                        subdomains.add(name)

            print(f"[+] crt.sh total: {len(subdomains)}")

    except Exception as e:
        print(f"[-] crt.sh failed: {e}")

    # ------------------------------------------------
    # Final cleanup
    # ------------------------------------------------

    cleaned = sorted(
        s
        for s in subdomains
        if s.endswith(domain)
    )

    print(f"[+] Total unique subdomains: {len(cleaned)}")

    return cleaned


# ===============================================
# PORT SCANNING
# ===============================================

def scan_ports(live_hosts):
    """Fast Nmap scan using parallel workers."""

    print("[+] Scanning ports with Nmap...")

    results = {}

    if not live_hosts:
        return results

    def scan_host(host):

        try:

            domain = urlparse(host["url"]).netloc

            print(f"[+] Scanning {domain}")

            result = subprocess.run(
                [
                    "nmap",
                    "-Pn",          # Skip host discovery
                    "-F",           # Top 100 ports
                    "-T4",          # Faster timing
                    "--open",
                    domain
                ],
                capture_output=True,
                text=True,
                timeout=60
            )

            ports = []

            for line in result.stdout.splitlines():

                if "/tcp" not in line:
                    continue

                if "open" not in line:
                    continue

                parts = line.split()

                if len(parts) >= 3:

                    ports.append({
                        "port": parts[0],
                        "state": parts[1],
                        "service": parts[2]
                    })

            return domain, ports

        except subprocess.TimeoutExpired:

            print(f"[-] Nmap timeout: {host['url']}")
            return None

        except Exception as e:

            print(f"[-] Port scan error: {host['url']} -> {e}")
            return None

    with ThreadPoolExecutor(max_workers=8) as executor:

        futures = [
            executor.submit(scan_host, host)
            for host in live_hosts[:5]
        ]

        for future in as_completed(futures):

            result = future.result()

            if result:
                domain, ports = result
                results[domain] = ports

    print(f"[+] Port scans complete: {len(results)} hosts")

    return results


# ===============================================
# JS FILE EXTRACTION
# ===============================================

def extract_js_files(live_hosts):
    """Extract external JavaScript files from live hosts."""

    print("[+] Extracting JavaScript files...")

    js_files = set()

    def scan_host(host):

        url = host["url"]

        try:

            response = session.get(
                url,
                headers=HEADERS,
                timeout=8,
                verify=False,
                allow_redirects=True
            )

            content_type = response.headers.get(
                "Content-Type",
                ""
            ).lower()

            if "text/html" not in content_type:
                return set()

            soup = BeautifulSoup(response.text, "html.parser")

            discovered = set()

            for script in soup.find_all("script"):

                src = script.get("src")

                if not src:
                    continue

                full_url = urljoin(url, src)

                if full_url.lower().endswith(".js") or ".js?" in full_url.lower():
                    discovered.add(full_url)

            return discovered

        except Exception:
            return set()

    with ThreadPoolExecutor(max_workers=15) as executor:

        results = executor.map(scan_host, live_hosts[:20])

        for found in results:
            js_files.update(found)

    js_files = sorted(js_files)

    print(f"[+] Found {len(js_files)} JS files")

    return js_files


# ===============================================
# SECRET FINDER
# ===============================================

def find_secrets(js_files):
    """Scan JavaScript files for exposed secrets."""

    print("[+] Scanning JS files for secrets...")

    patterns = {

        "AWS Access Key": r"AKIA[0-9A-Z]{16}",

        "Google API Key": r"AIza[0-9A-Za-z\-_]{35}",

        "GitHub Token": r"gh[pousr]_[A-Za-z0-9]{36,255}",

        "Slack Token": r"xox[baprs]-[A-Za-z0-9\-]{10,}",

        "Stripe Live Key": r"sk_live_[0-9A-Za-z]{20,}",

        "Stripe Publishable": r"pk_live_[0-9A-Za-z]{20,}",

        "Firebase URL": r"https://[A-Za-z0-9\-.]+\.firebaseio\.com",

        "Bearer Token": r"Bearer\s+[A-Za-z0-9\-._~+/]+=*",

        "JWT": r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+",

        "API Key": r"(?i)(api[_-]?key|apikey)['\"\s:=]+([A-Za-z0-9_\-]{16,})",

        "Access Token": r"(?i)(access[_-]?token|token)['\"\s:=]+([A-Za-z0-9_\-.]{16,})",

        "Client Secret": r"(?i)(client[_-]?secret|secret)['\"\s:=]+([A-Za-z0-9_\-]{16,})",
    }


    def scan_js(js_url):

        findings = []

        try:

            response = session.get(
                js_url,
                headers=HEADERS,
                timeout=8,
                verify=False
            )

            if response.status_code != 200:
                return []

            content = response.text

            for secret_type, pattern in patterns.items():

                matches = re.findall(pattern, content)

                if not matches:
                    continue

                for match in matches:

                    if isinstance(match, tuple):
                        value = match[-1]
                    else:
                        value = match

                    findings.append({
                        "url": js_url,
                        "type": secret_type,
                        "value": value[:120]
                    })

        except Exception:
            pass

        return findings


    secrets = []

    with ThreadPoolExecutor(max_workers=25) as executor:

        for result in executor.map(scan_js, js_files):

            secrets.extend(result)


    # Remove duplicates

    unique = []

    seen = set()

    for secret in secrets:

        key = (
            secret["url"],
            secret["type"],
            secret["value"]
        )

        if key not in seen:

            seen.add(key)

            unique.append(secret)

    print(f"[+] Found {len(unique)} potential secrets")

    return unique

# ===============================================
# WAYBACK MACHINE
# ===============================================

def fetch_wayback_urls(domain):
    """Fetch archived URLs from the Wayback Machine."""

    print("[+] Fetching URLs from Wayback Machine...")

    urls = set()

    api = (
        "https://web.archive.org/cdx/search/cdx"
        f"?url=*.{domain}/*"
        "&output=text"
        "&fl=original"
        "&collapse=urlkey"
        "&limit=1000"
    )

    response = None

    for attempt in range(7):

        try:

            print(f"[+] Wayback attempt {attempt + 1}/7")

            response = session.get(
                api,
                headers=HEADERS,
                timeout=20
            )

            if response.status_code == 200:
                break

        except Exception as e:

            print(f"[!] Retry {attempt + 1} failed: {e}")

    if response and response.status_code == 200:

        for line in response.text.splitlines():

            line = html.unescape(line.strip())

            if not line:
                continue

            if line.startswith("mailto:"):
                continue

            if line.startswith("javascript:"):
                continue

            urls.add(line)

    urls = sorted(urls)

    print(f"[+] Fetched {len(urls)} Wayback URLs")

    return urls


# ===============================================
# URL FILTERING
# ===============================================

def filter_important_urls(urls):
    """Filter URLs that are most interesting for bug bounty."""

    print("[+] Filtering high-value URLs...")

    keywords = {

        "admin",
        "login",
        "logout",
        "signin",
        "signup",
        "register",
        "account",
        "profile",
        "dashboard",
        "user",
        "users",

        "api",
        "graphql",
        "rest",
        "oauth",
        "auth",
        "token",

        "password",
        "reset",
        "forgot",
        "verify",
        "confirm",

        "upload",
        "download",
        "file",
        "image",

        "redirect",
        "callback",
        "return",
        "next",

        "search",
        "query",
        "filter",
        "sort",

        "debug",
        "test",
        "dev",
        "internal",

        "config",
        "backup",
        "secret",
        "key",

        "payment",
        "invoice",
        "billing",

        "webhook",

        "=",
        "?"
    }

    important = []

    seen = set()

    for url in urls:

        url = html.unescape(url).strip()

        if not url:
            continue

        lower = url.lower()

        if any(lower.endswith(ext) for ext in SKIP_EXTENSIONS):
            continue

        if lower in seen:
            continue

        if any(keyword in lower for keyword in keywords):

            seen.add(lower)
            important.append(url)

    important.sort()

    print(f"[+] Found {len(important)} high-value URLs")

    return important


# ===============================================
# PARAMETER EXTRACTION
# ===============================================

def extract_parameters(urls):
    """Extract interesting URL parameters."""

    print("[+] Extracting URL parameters...")

    param_urls = []

    seen = set()

    interesting = {
        "id",
        "user",
        "userid",
        "uid",
        "account",
        "profile",
        "email",
        "token",
        "key",
        "auth",
        "redirect",
        "return",
        "next",
        "url",
        "callback",
        "file",
        "filename",
        "path",
        "page",
        "search",
        "query",
        "q",
        "lang",
        "debug",
        "admin"
    }

    for url in urls:

        try:

            parsed = urlparse(url)

            if not parsed.query:
                continue

            params = parse_qs(parsed.query)

            clean = []

            for p in params:

                p_lower = p.lower()

                if p_lower in NOISE_PARAMS:
                    continue

                clean.append(p)

            if not clean:
                continue

            key = (parsed.scheme, parsed.netloc, parsed.path, tuple(sorted(clean)))

            if key in seen:
                continue

            seen.add(key)

            clean.sort(
                key=lambda x: (
                    x.lower() not in interesting,
                    x.lower()
                )
            )

            param_urls.append((url, clean))

        except Exception:
            continue

    print(f"[+] Found {len(param_urls)} parameterized URLs")

    return param_urls


# ===============================================
# BASIC CRAWLER
# ===============================================

def _merge_forms(existing: list, new_forms: list) -> list:
    """
    Merge newly-discovered form metadata into the existing list,
    deduplicating by (url, method) — last writer wins for duplicate keys.
    """
    seen: dict = {(f["url"], f["method"]): i for i, f in enumerate(existing)}
    result = list(existing)
    for form in new_forms:
        key = (form["url"], form["method"])
        if key in seen:
            result[seen[key]] = form   # update in place
        else:
            seen[key] = len(result)
            result.append(form)
    return result


def basic_crawler(live_hosts):
    """
    HTML crawler for fallback URL discovery.

    Discovers both hyperlinks (<a href>) and HTML forms (<form>).
    Returns two values:
        discovered_urls : sorted list[str]   — same as before
        discovered_forms: list[dict]         — new: form metadata

    Form metadata dict schema:
        {
            "url":          str,           # absolute action URL
            "method":       str,           # "GET" or "POST" (uppercase, default "GET")
            "body_params":  list[str],     # input/textarea/select name attributes
            "content_type": str,           # enctype value (default "application/x-www-form-urlencoded")
            "source_page":  str,           # page URL the form was found on
        }

    The existing <a href> behaviour is unchanged.
    """

    print("[+] Running basic crawler...")

    discovered = set()
    forms_found: list = []
    forms_lock = __import__("threading").Lock()

    def crawl_host(host):

        urls  = set()
        forms = []

        try:

            response = session.get(
                host["url"],
                headers=HEADERS,
                timeout=8,
                verify=False,
                allow_redirects=True
            )

            if response.status_code != 200:
                return urls, forms

            content_type = response.headers.get(
                "Content-Type",
                ""
            ).lower()

            if "text/html" not in content_type:
                return urls, forms

            soup = BeautifulSoup(response.text, "html.parser")

            # ── Existing: <a href> link extraction (unchanged) ────────────
            for link in soup.find_all("a", href=True):

                href = link["href"].strip()

                if not href:
                    continue

                if href.startswith("#"):
                    continue

                if href.startswith("mailto:"):
                    continue

                if href.startswith("tel:"):
                    continue

                if href.startswith("javascript:"):
                    continue

                full = urljoin(host["url"], href)

                full = full.split("#")[0]

                if any(full.lower().endswith(ext) for ext in SKIP_EXTENSIONS):
                    continue

                urls.add(full)

                if len(urls) >= 300:
                    break

            # ── New: <form> extraction ────────────────────────────────────
            for form in soup.find_all("form"):

                try:
                    # Action URL — resolve relative to host, default to current page
                    raw_action = (form.get("action") or "").strip()
                    action_url = urljoin(host["url"], raw_action) if raw_action else host["url"]
                    action_url = action_url.split("#")[0]

                    if any(action_url.lower().endswith(ext) for ext in SKIP_EXTENSIONS):
                        continue

                    # HTTP method — default to GET per HTML spec
                    method = (form.get("method") or "GET").upper().strip()
                    if method not in ("GET", "POST", "PUT", "PATCH", "DELETE"):
                        method = "GET"

                    # Enctype — determines body serialisation format
                    enctype = (
                        form.get("enctype") or "application/x-www-form-urlencoded"
                    ).strip().lower()

                    # Field names — inputs, textareas, selects with a name attribute
                    field_names = []
                    for field in form.find_all(["input", "textarea", "select", "button"]):
                        name = (field.get("name") or "").strip()
                        ftype = (field.get("type") or "text").lower()
                        # Skip submit/reset/image/hidden-without-value buttons
                        if not name:
                            continue
                        if ftype in ("submit", "reset", "image", "button"):
                            continue
                        if name not in field_names:
                            field_names.append(name)

                    forms.append({
                        "url":          action_url,
                        "method":       method,
                        "body_params":  field_names,
                        "content_type": enctype,
                        "source_page":  host["url"],
                    })

                except Exception:
                    continue

        except Exception:
            pass

        return urls, forms


    with ThreadPoolExecutor(max_workers=10) as executor:

        results = executor.map(
            crawl_host,
            live_hosts[:20]
        )

        for urls, forms in results:
            discovered.update(urls)
            with forms_lock:
                forms_found.extend(forms)

    discovered = sorted(discovered)

    print(f"[+] Crawler found {len(discovered)} URLs, {len(forms_found)} forms")

    return discovered, forms_found


# ===============================================
# SMART ENDPOINT TESTER (lightweight single-URL check)
# ===============================================

def smart_test_endpoint(url):
    """
    Lightweight vulnerability heuristics.
    Fast enough for recon while reducing false positives.
    """

    findings = []

    try:

        ############################################
        # Base Request
        ############################################

        try:
            base = session.get(
                url,
                headers=HEADERS,
                timeout=5,
                verify=False,
                allow_redirects=True
            )
        except Exception:
            return findings

        body = base.text.lower()

        ############################################
        # Missing Security Headers
        # Endpoint-level: one finding per (host+path, header) regardless of
        # which query-param variant triggered the request.
        ############################################

        security_headers = {
            "Content-Security-Policy": "High",
            "X-Frame-Options": "Medium",
            "X-Content-Type-Options": "Medium",
            "Strict-Transport-Security": "Low",
            "Referrer-Policy": "Low"
        }

        for header, severity in security_headers.items():

            if header not in base.headers:

                findings.append({
                    "type": f"Missing {header}",
                    "url": url,
                    "severity": severity,
                    "reason": f"{header} header not present",
                    # Endpoint-level confirmed observation: the header IS absent.
                    # This is a real finding (no active exploit payload needed).
                    "smart_status": "confirmed",
                    "source": "Smart Tests",
                })

        ############################################
        # Information Disclosure
        ############################################

        error_patterns = [

            "traceback",
            "exception",
            "stack trace",
            "fatal error",

            "sql syntax",
            "mysql_fetch",
            "mysqli",
            "postgresql",
            "sqlite",
            "ora-",

            "django",
            "werkzeug debugger",
            "flask",
            "laravel",
            "symfony",
            "spring boot",
            "java.lang",

            "internal server error"

        ]

        for sig in error_patterns:

            if sig in body:

                findings.append({
                    "type": "Information Disclosure",
                    "url": url,
                    "severity": "Medium",
                    "reason": sig,
                    "smart_status": "confirmed",
                    "source": "Smart Tests",
                })

                break

        ############################################
        # Server Information Leakage
        ############################################

        leak_headers = [
            "Server",
            "X-Powered-By",
            "X-AspNet-Version",
            "X-Runtime"
        ]

        for header in leak_headers:

            if header in base.headers:

                findings.append({
                    "type": "Technology Disclosure",
                    "url": url,
                    "severity": "Low",
                    "reason": f"{header}: {base.headers[header]}",
                    "smart_status": "confirmed",
                    "source": "Smart Tests",
                })

        ############################################
        # Cookie Checks
        ############################################

        cookies = base.headers.get("Set-Cookie", "")

        if cookies:

            if "httponly" not in cookies.lower():

                findings.append({
                    "type": "Cookie Missing HttpOnly",
                    "url": url,
                    "severity": "Medium",
                    "smart_status": "confirmed",
                    "source": "Smart Tests",
                })

            if "secure" not in cookies.lower():

                findings.append({
                    "type": "Cookie Missing Secure",
                    "url": url,
                    "severity": "Medium",
                    "smart_status": "confirmed",
                    "source": "Smart Tests",
                })

        ############################################
        # Reflected XSS — payload must be reflected to count as confirmed
        ############################################

        xss_payloads = [

            "<script>alert(1)</script>",
            "\"><svg/onload=alert(1)>",
            "<img src=x onerror=alert(1)>"

        ]

        for payload in xss_payloads:

            sep = "&" if "?" in url else "?"

            test_url = f"{url}{sep}xss={requests.utils.quote(payload)}"

            try:

                r = session.get(
                    test_url,
                    headers=HEADERS,
                    timeout=5,
                    verify=False
                )

                ctype = r.headers.get("Content-Type", "")

                if (
                    payload in r.text
                    and "text/html" in ctype
                ):

                    findings.append({
                        "type": "Reflected XSS",
                        "url": test_url,
                        "severity": "High",
                        "reason": "Payload reflected in HTML response",
                        "parameter": "xss",
                        "payload": payload,
                        "smart_status": "confirmed",
                        "source": "Smart Tests",
                    })

                    break

            except Exception:
                pass

        ############################################
        # Open Redirect — redirect must actually follow to count as confirmed
        ############################################

        redirect_params = [
            "redirect",
            "url",
            "next",
            "return",
            "callback"
        ]

        parsed = urlparse(url)

        if parsed.query:

            qs = parse_qs(parsed.query)

            for param in redirect_params:

                if param in qs:

                    qs[param] = ["https://example.com"]

                    test = urlunparse(
                        parsed._replace(
                            query=urlencode(qs, doseq=True)
                        )
                    )

                    try:

                        r = session.get(
                            test,
                            headers=HEADERS,
                            timeout=5,
                            verify=False,
                            allow_redirects=False
                        )

                        if (
                            r.status_code in (301,302,303,307,308)
                            and "example.com" in r.headers.get("Location","")
                        ):

                            findings.append({
                                "type": "Open Redirect",
                                "url": test,
                                "severity": "High",
                                "parameter": param,
                                "smart_status": "confirmed",
                                "source": "Smart Tests",
                            })

                    except Exception:
                        pass

        ############################################
        # CORS — origin reflected or wildcard must be confirmed in response
        ############################################

        origin_headers = dict(HEADERS)
        origin_headers["Origin"] = "https://evil.com"

        try:

            r = session.get(
                url,
                headers=origin_headers,
                timeout=5,
                verify=False
            )

            allow = r.headers.get(
                "Access-Control-Allow-Origin",
                ""
            )

            if allow in ("*", "https://evil.com"):

                findings.append({
                    "type": "CORS Misconfiguration",
                    "url": url,
                    "severity": "Medium",
                    "smart_status": "confirmed",
                    "source": "Smart Tests",
                })

        except Exception:
            pass

    except Exception:
        pass

    return findings


# ===============================================
# MAIN RECON ORCHESTRATOR
# ===============================================

def run_recon(domain):
    """
    Full recon orchestration pipeline.

    Every stage reads from and writes to a ScanContext instance.
    Stage failures are isolated: ctx.metadata["stage_errors"] records what
    failed; the scan always continues.

    Returns the same dictionary as v2 (backwards compatible).
    New keys "timings", "statistics", and "stage_errors" are added but
    never remove existing keys.
    """

    # ===============================================
    # NORMALIZE TARGET
    # ===============================================
    domain = (
        str(domain)
        .strip()
        .lower()
        .replace("https://", "")
        .replace("http://", "")
        .split("/")[0]
        .rstrip("/")
    )

    if not domain:
        raise ValueError("Target domain cannot be empty")

    scan_start = time.perf_counter()

    print(f"\n{'='*60}")
    print(f"[*] Starting recon on: {domain}")
    print(f"{'='*60}\n")

    # ── Initialise ScanContext ─────────────────────────────────────────
    ctx = ScanContext(domain=domain)

    # ─────────────────────────────────────────────────────────────────────
    # STAGE: Subdomain Enumeration
    # ─────────────────────────────────────────────────────────────────────
    def _stage_subdomains(ctx):
        subs = get_subdomains(ctx.domain)
        if not subs:
            print("[!] No subdomains found, using root domain")
            subs = [ctx.domain]
        ctx.subdomains = subs
        return subs

    _run_stage(ctx, "Subdomain Enumeration", _stage_subdomains, ctx)

    # ─────────────────────────────────────────────────────────────────────
    # STAGE: Alive Check
    # ─────────────────────────────────────────────────────────────────────
    def _stage_alive(ctx):
        hosts = check_alive(ctx.subdomains)

        print("\n" + "=" * 80)
        print("[DEBUG] check_alive() returned:")
        print(hosts)
        print("=" * 80 + "\n")

        if not hosts:
            print("[!] No alive hosts detected, using root domain fallback")
            hosts = [{
                "url": f"https://{ctx.domain}",
                "status": 0,
                "title": "Fallback",
                "server": "",
                "content_type": "",
                "technologies": [],
            }]
        ctx.live_hosts = hosts

        print("\n[DEBUG] Live hosts stored in ScanContext:")
        for h in ctx.live_hosts:
            print(h)
        print()

        return hosts

    _run_stage(ctx, "Alive Check", _stage_alive, ctx)

    # ─────────────────────────────────────────────────────────────────────
    # STAGE: Screenshots
    # ─────────────────────────────────────────────────────────────────────
    def _stage_screenshots(ctx):
        shots = []
        for host in ctx.live_hosts[:6]:
            try:
                shot = capture_screenshot(host["url"])
                if not shot:
                    continue
                shots.append({
                    "url": shot.get("url", host["url"]),
                    "path": shot.get("path", ""),
                    "image": shot.get("image", ""),
                    "title": shot.get("title", ""),
                    "tech_hints": shot.get("tech_hints", [])
                })
            except Exception as e:
                ctx.add_warning("Screenshots", f"Failed for {host['url']}: {e}")
        print(f"[+] Captured {len(shots)} screenshots")
        ctx.screenshots = shots
        return shots

    _run_stage(ctx, "Screenshots", _stage_screenshots, ctx)

    # ─────────────────────────────────────────────────────────────────────
    # STAGE: Browser Reconnaissance
    # ─────────────────────────────────────────────────────────────────────
    def _stage_browser_recon(ctx):
        results = []
        for host in ctx.live_hosts[:10]:
            try:
                data = browser_recon(host["url"])
                results.append({"url": host["url"], "data": data or {}})
            except Exception as e:
                ctx.add_warning("Browser Recon", f"Failed for {host['url']}: {e}")
                results.append({"url": host["url"], "data": {}})
        print(f"[+] Browser recon completed for {len(results)} hosts")
        ctx.browser_recon = results
        return results

    _run_stage(ctx, "Browser Recon", _stage_browser_recon, ctx)

    # ─────────────────────────────────────────────────────────────────────
    # STAGE: Technology Fingerprinting
    # ─────────────────────────────────────────────────────────────────────
    def _stage_fingerprint(ctx):
        technologies = {}

        def fingerprint_host(host):
            url = host["url"]
            try:
                techs = detect_technologies(url)
                if not isinstance(techs, list):
                    techs = []
                return url, techs
            except Exception as e:
                ctx.add_warning("Technology Fingerprinting",
                                f"Failed for {url}: {e}")
                return url, []

        with ThreadPoolExecutor(max_workers=15) as executor:
            for url, techs in executor.map(fingerprint_host, ctx.live_hosts[:15]):
                technologies[url] = techs
                # Pre-warm the URL parse cache
                ctx.parsed_url(url)
                if techs:
                    print(f"[+] {url} -> {', '.join(techs[:5])}")
                else:
                    print(f"[+] {url} -> Unknown")

        ctx.technologies = technologies
        return technologies

    _run_stage(ctx, "Technology Fingerprinting", _stage_fingerprint, ctx)

    # ─────────────────────────────────────────────────────────────────────
    # STAGE: Infrastructure Analysis (ports + dirs + JS files — parallel)
    # ─────────────────────────────────────────────────────────────────────
    def _stage_infrastructure(ctx):
        print("[+] Running infrastructure analysis (parallel)...")
        with ThreadPoolExecutor(max_workers=3) as executor:
            future_ports = executor.submit(scan_ports, ctx.live_hosts)
            future_dirs = executor.submit(fuzz_directories, ctx.live_hosts)
            future_js = executor.submit(extract_js_files, ctx.live_hosts)
            port_results = future_ports.result()
            dir_results = future_dirs.result()
            js_files = future_js.result()

        ctx.ports = port_results
        ctx.directories = dir_results
        ctx.js_files = js_files

        print(f"[+] JS files found: {len(js_files)}")
        return js_files  # item count for stage logging

    _run_stage(ctx, "Infrastructure Analysis", _stage_infrastructure, ctx)

    # ─────────────────────────────────────────────────────────────────────
    # STAGE: JS Intelligence + Secrets
    # Reuses ctx.js_files from previous stage — no duplicate fetching.
    # ─────────────────────────────────────────────────────────────────────
    def _stage_js_intelligence(ctx):
        if not ctx.js_files:
            ctx.secrets = []
            ctx.js_intelligence = []
            return []

        print("[+] Looking for exposed secrets...")
        secrets = find_secrets(ctx.js_files)

        print("[+] Analysing JavaScript...")
        js_intel_raw = analyze_js_files(ctx.js_files)

        # Remove duplicate JS findings
        seen_js = set()
        js_intel = []
        for item in js_intel_raw:
            if not isinstance(item, dict):
                continue
            key = (item.get("type"), item.get("value"), item.get("source"))
            if key in seen_js:
                continue
            seen_js.add(key)
            js_intel.append(item)

        print(f"[+] Secrets found: {len(secrets)}")
        print(f"[+] JS intelligence findings: {len(js_intel)}")

        ctx.secrets = secrets
        ctx.js_intelligence = js_intel
        return js_intel

    _run_stage(ctx, "JS Intelligence", _stage_js_intelligence, ctx)

    # ─────────────────────────────────────────────────────────────────────
    # STAGE: URL Discovery (Wayback + crawler + fallback paths)
    # ─────────────────────────────────────────────────────────────────────
    def _stage_url_discovery(ctx):
        print("[+] Discovering URLs...")

        wayback = fetch_wayback_urls(ctx.domain)
        crawler_urls, crawler_forms = basic_crawler(ctx.live_hosts)
        ctx.form_endpoints = _merge_forms(ctx.form_endpoints, crawler_forms)

        COMMON_PATHS = [
            "/", "/login", "/logout", "/register", "/signup",
            "/dashboard", "/admin", "/administrator", "/panel",
            "/api", "/api/v1", "/api/v2", "/graphql", "/swagger",
            "/openapi.json", "/docs", "/search", "/profile",
            "/account", "/settings", "/user", "/users",
            "/auth", "/oauth", "/callback",
            "/reset-password", "/forgot-password",
        ]

        fallback = [
            host["url"].rstrip("/") + path
            for host in ctx.live_hosts
            for path in COMMON_PATHS
        ]

        merged = list(dict.fromkeys(wayback + crawler_urls + fallback))[:1000]
        merged = list(dict.fromkeys(merged))

        print(f"[+] Wayback URLs : {len(wayback)}")
        print(f"[+] Crawled URLs : {len(crawler_urls)}")
        print(f"[+] Fallback URLs: {len(fallback)}")
        print(f"[+] URL pool     : {len(merged)}")

        ctx.wayback_urls = merged
        return merged

    _run_stage(ctx, "URL Discovery", _stage_url_discovery, ctx)

    # ─────────────────────────────────────────────────────────────────────
    # STAGE: URL Filtering + Endpoint Classification
    # Reuses ctx.wayback_urls; no repeated parsing.
    # ─────────────────────────────────────────────────────────────────────
    def _stage_endpoint_discovery(ctx):
        important_urls = filter_important_urls(ctx.wayback_urls)

        important_urls.sort(
            key=lambda u: (
                "admin" not in u.lower(),
                "login" not in u.lower(),
                "api" not in u.lower(),
                "auth" not in u.lower(),
                "graphql" not in u.lower(),
                "token" not in u.lower(),
                "user" not in u.lower(),
                len(u)
            )
        )
        important_urls = important_urls[:500]

        print(f"[+] High-value URLs: {len(important_urls)}")

        def is_static(url):
            return any(url.lower().endswith(ext) for ext in SKIP_EXTENSIONS)

        endpoints = []
        seen_endpoints = set()

        # Build a lookup from form metadata: norm_url → form info
        # (only POST/non-GET forms contribute method/body_params)
        form_meta: dict = {}
        for fe in ctx.form_endpoints:
            fu = fe.get("url", "")
            if not fu:
                continue
            try:
                from urllib.parse import urlparse as _up_ep
                norm = f"{_up_ep(fu).scheme}://{_up_ep(fu).netloc}{_up_ep(fu).path}".rstrip("/")
            except Exception:
                norm = fu
            # Last writer wins; prefer POST over GET when multiple forms target same URL
            existing = form_meta.get(norm)
            if existing is None or fe.get("method", "GET") != "GET":
                form_meta[norm] = fe

        for url in important_urls:
            if is_static(url):
                continue
            if url in seen_endpoints:
                continue
            seen_endpoints.add(url)
            # Warm the URL cache for every endpoint that will be used later
            ctx.parsed_url(url)
            try:
                tags = classify_endpoint(url)
            except Exception:
                tags = []

            # Attach form metadata when discovered
            try:
                from urllib.parse import urlparse as _up_ep2
                norm = f"{_up_ep2(url).scheme}://{_up_ep2(url).netloc}{_up_ep2(url).path}".rstrip("/")
            except Exception:
                norm = url
            fe_meta = form_meta.get(norm, {})

            endpoints.append({
                "url":          url,
                "tags":         tags,
                "method":       fe_meta.get("method", "GET"),
                "body_params":  fe_meta.get("body_params", []),
                "content_type": fe_meta.get("content_type", ""),
            })

        print(f"[+] Classified endpoints: {len(endpoints)}")

        ctx.important_urls = important_urls
        ctx.endpoints = endpoints
        return endpoints

    _run_stage(ctx, "Endpoint Discovery", _stage_endpoint_discovery, ctx)

    # ─────────────────────────────────────────────────────────────────────
    # STAGE: Parameter Extraction
    # Reuses ctx.endpoints; ctx.parsed_url() avoids re-parsing.
    # ─────────────────────────────────────────────────────────────────────
    def _stage_parameters(ctx):
        print("[+] Building parameter candidates...")

        COMMON_PARAMS = [
            "id", "user", "username", "account", "email", "token", "key",
            "apikey", "search", "q", "query", "page", "file", "path",
            "redirect", "redirect_uri", "next", "url", "return",
            "callback", "continue",
        ]

        TEST_VALUES = {
            "id": "1", "user": "admin", "email": "test@example.com",
            "redirect": "https://example.com", "url": "https://example.com",
            "callback": "https://example.com",
            "file": "../../../../etc/passwd",
            "path": "../../../../etc/passwd",
            "token": "test", "apikey": "test",
        }

        expanded_urls = []
        seen_urls = set()

        for endpoint in ctx.endpoints[:500]:
            url = endpoint["url"]
            if url not in seen_urls:
                expanded_urls.append(url)
                seen_urls.add(url)

            lower = url.lower()
            if "login" in lower or "auth" in lower:
                params = ["redirect", "next", "return"]
            elif "search" in lower:
                params = ["q", "query", "search"]
            elif "user" in lower or "profile" in lower:
                params = ["id", "user", "account"]
            elif "api" in lower:
                params = ["id", "token", "apikey"]
            elif "file" in lower or "download" in lower:
                params = ["file", "path"]
            elif "redirect" in lower:
                params = ["redirect", "url"]
            else:
                params = COMMON_PARAMS

            sep = "&" if "?" in url else "?"
            for param in params:
                value = TEST_VALUES.get(param, "test")
                candidate = f"{url}{sep}{param}={value}"
                if candidate not in seen_urls:
                    expanded_urls.append(candidate)
                    seen_urls.add(candidate)

        print(f"[+] Expanded URLs: {len(expanded_urls)}")

        param_data = extract_parameters(expanded_urls)
        print(f"[+] Parameterized URLs: {len(param_data)}")

        ctx.parameters = param_data
        return param_data

    _run_stage(ctx, "Parameter Extraction", _stage_parameters, ctx)

    # ─────────────────────────────────────────────────────────────────────
    # STAGE: Smart Endpoint Tests (lightweight heuristics)
    # ─────────────────────────────────────────────────────────────────────
    def _stage_smart_tests(ctx):
        print("[+] Running smart endpoint tests...")

        all_targets = list(dict.fromkeys(
            [url for url, _ in ctx.parameters] +
            [e["url"] for e in ctx.endpoints]
        ))

        all_targets.sort(
            key=lambda u: (
                "admin" not in u.lower(),
                "login" not in u.lower(),
                "auth" not in u.lower(),
                "api" not in u.lower(),
                "graphql" not in u.lower(),
                "token" not in u.lower(),
                "redirect" not in u.lower(),
                len(u)
            )
        )
        all_targets = all_targets[:150]

        print(f"[+] Testing {len(all_targets)} endpoints...")

        smart_findings = []
        completed = 0
        failed = 0

        with ThreadPoolExecutor(max_workers=20) as executor:
            futures = {
                executor.submit(smart_test_endpoint, url): url
                for url in all_targets
            }
            for future in as_completed(futures):
                url = futures[future]
                try:
                    findings = future.result()
                    if findings:
                        smart_findings.extend(findings)
                    completed += 1
                except Exception as e:
                    failed += 1
                    ctx.add_warning("Smart Tests", f"Failed: {url} ({e})")

        # ── Canonical dedup: use normalised (host+path, vuln_class) key ────────
        # For endpoint-level findings (missing headers, CORS, etc.) the query
        # string is stripped so /admin?apikey=test and /admin?token=test collapse
        # to the same finding.  For parameter-level findings (XSS, open redirect)
        # the parameter name is included so distinct params stay distinct.
        seen = set()
        unique_findings = []
        smart_candidates = []   # attack-surface intelligence, not auto-confirmed
        smart_confirmed  = []   # actually validated by the smart test itself

        for finding in smart_findings:
            ftype      = (finding.get("type") or "").lower().strip()
            raw_url    = finding.get("url", "")
            param      = (finding.get("parameter") or "").lower()
            vuln_class = _SMART_TYPE_TO_VULN_CLASS.get(ftype, ftype.upper().replace(" ", "_"))

            if _ep_level(vuln_class):
                # Endpoint-level: strip query string from key
                dedup_url = _norm_url(raw_url)
                key = (dedup_url, "", vuln_class)
            else:
                # Parameter-level: include param name
                dedup_url = _norm_url(raw_url)
                key = (dedup_url, param, vuln_class)

            if key in seen:
                continue
            seen.add(key)
            unique_findings.append(finding)

            # Classify into confirmed vs candidate
            if ftype in _SMART_CANDIDATE_TYPES:
                finding["smart_status"] = "candidate"
                smart_candidates.append(finding)
            else:
                # Default for findings not listed in candidate set is confirmed
                # (they passed an active check in smart_test_endpoint)
                finding.setdefault("smart_status", "confirmed")
                smart_confirmed.append(finding)

        print(f"[+] Smart tests completed     : {completed}")
        print(f"[+] Smart tests failed        : {failed}")
        print(f"[+] Smart findings (raw)      : {len(smart_findings)}")
        print(f"[+] Smart confirmed           : {len(smart_confirmed)}")
        print(f"[+] Smart candidates          : {len(smart_candidates)}")
        print(f"[+] Smart unique (after dedup): {len(unique_findings)}")

        # Store in metadata for downstream stages
        ctx.metadata["smart_findings"]   = smart_confirmed   # only confirmed go to merge
        ctx.metadata["smart_candidates"] = smart_candidates  # available to VulnEngine/AI
        # Keep complete list for telemetry/reporting
        ctx.metadata["smart_all"]        = unique_findings
        return unique_findings

    _run_stage(ctx, "Smart Tests", _stage_smart_tests, ctx)

    # ─────────────────────────────────────────────────────────────────────
    # STAGE: Detection Engine
    # Builds an EndpointContext per endpoint using already-collected signals
    # (technologies, browser_recon, secrets, js_intelligence, parameters).
    # Reuses ctx.parsed_url() — no repeated urlparse() calls.
    # ─────────────────────────────────────────────────────────────────────
    def _stage_detection_engine(ctx):
        if not _DE_AVAILABLE:
            print("[!] DetectionEngine not available — skipping")
            ctx.metadata["detection_plans"] = {}
            return {}

        print(f"[+] Building detection plans for {len(ctx.endpoints)} endpoints...")

        detection_plans = {}

        # Build a quick set of secret types already found for JS-finding injection
        secret_types = {s.get("type", "") for s in ctx.secrets}

        # Index browser_recon by URL for O(1) lookup
        browser_by_url = {r["url"]: r.get("data", {}) for r in ctx.browser_recon}

        for endpoint in ctx.endpoints[:500]:
            ep_url = endpoint["url"]
            parsed = ctx.parsed_url(ep_url)

            # Reuse fingerprint from ctx.technologies
            techs = ctx.tech_for(ep_url)

            # Infer frameworks from technologies list
            _known_frameworks = [
                t for t in techs
                if t.lower() in {
                    "laravel", "symfony", "codeigniter", "yii", "django", "flask",
                    "fastapi", "express", "nestjs", "next.js", "react", "vue",
                    "angular", "nuxt", "spring", "spring boot", "asp.net", "rails",
                    "phoenix", "gin", "echo", "fiber", "wordpress", "drupal",
                    "magento", "shopify", "strapi", "graphql", "grpc",
                }
            ]

            # Collect query parameters (reuse parsed URL)
            params_raw = parse_qs(parsed.query, keep_blank_values=True)
            query_params = {k: v[0] for k, v in params_raw.items()}

            # Detect auth state from path
            path_lower = parsed.path.lower()
            if any(x in path_lower for x in ("login", "signin", "auth", "oauth")):
                auth_state = AuthState.UNAUTHENTICATED
            else:
                auth_state = AuthState.UNKNOWN

            # Reuse browser recon result for this host
            host_key = f"{parsed.scheme}://{parsed.netloc}"
            br_data = browser_by_url.get(ep_url, browser_by_url.get(host_key, {}))

            # Build JS findings from ctx.js_intelligence for this host
            js_findings = [
                {"type": item.get("type", ""), "source": item.get("source", "")}
                for item in ctx.js_intelligence
                if host_key in item.get("source", "")
            ]

            # Build secret findings for this host
            secret_findings = [
                {"type": s.get("type", ""), "source": s.get("url", "")}
                for s in ctx.secrets
                if host_key in s.get("url", "")
            ]

            # Directory findings for this host.
            # ctx.directories is a flat list[str] (paths) returned by
            # fuzz_directories().  Guard against both list and the hypothetical
            # dict[netloc -> list[str]] shape so this never crashes on either.
            _dirs = ctx.directories
            if isinstance(_dirs, dict):
                _dir_paths = _dirs.get(parsed.netloc, [])
            elif isinstance(_dirs, list):
                _dir_paths = _dirs
            else:
                _dir_paths = []
            dir_findings = [
                {"path": path, "status_code": 200}
                for path in _dir_paths
                if isinstance(path, str)
            ]

            ep_ctx = EndpointContext(
                url=ep_url,
                path=parsed.path,
                method="GET",
                query_parameters=query_params,
                headers={},
                cookies={},
                forms=[],
                technologies=techs,
                frameworks=_known_frameworks,
                content_type="",
                response_headers={},
                status_code=0,
                authentication_state=auth_state,
                graphql_detected=(
                    "graphql" in path_lower
                    or "graphiql" in path_lower
                ),
                rest_detected=(
                    "/api/" in path_lower
                    or path_lower.endswith("/api")
                    or any(f"/v{n}/" in path_lower for n in range(1, 5))
                ),
                javascript_findings=js_findings,
                secrets_found=secret_findings,
                directory_findings=dir_findings,
                fingerprinting_results={},
                browser_reconnaissance=br_data,
            )

            try:
                plan = DETECTION_ENGINE.generate_detection_plan(
                    ep_ctx, min_confidence=25
                )
                detection_plans[ep_url] = plan
            except Exception as e:
                ctx.add_warning("Detection Engine",
                                f"Plan failed for {ep_url}: {e}")

        total_rules = sum(len(p) for p in detection_plans.values())
        print(f"[+] Detection plans built: {len(detection_plans)} endpoints, "
              f"{total_rules} total rules")

        ctx.metadata["detection_plans"] = detection_plans
        return detection_plans

    _run_stage(ctx, "Detection Engine", _stage_detection_engine, ctx)

    # ─────────────────────────────────────────────────────────────────────
    # STAGE: Vulnerability Engine + AI Analysis (parallel)
    # Reuses ctx.parameters, ctx.endpoints, ctx.technologies.
    # ─────────────────────────────────────────────────────────────────────
    def _stage_vuln_and_ai(ctx):
        def is_static(url):
            return any(url.lower().endswith(ext) for ext in SKIP_EXTENSIONS)

        # ── Vulnerability Engine Targets ──────────────────────────────
        # ctx.parameters is list of (url, [param_names]) tuples.
        # We preserve the param_names here so _run_vuln_with_stats can forward
        # them to VulnEngine._extract_params() without re-parsing the URL query
        # string (which would lose body/path/form params and fail for REST
        # endpoints that embed params in the URL for test expansion only).
        ep_param_map: dict = {}  # url -> param_names, last writer wins
        for url, params in ctx.parameters:
            if params and not is_static(url):
                ep_param_map[url] = list(params)

        # Build a normalised-URL → endpoint metadata lookup for method/body_params.
        # Populated from ctx.endpoints which carries form metadata from Phase 1.
        from urllib.parse import urlparse as _up_st
        def _norm_for_target(u):
            try:
                p = _up_st(u)
                return f"{p.scheme}://{p.netloc}{p.path}".rstrip("/")
            except Exception:
                return u

        ep_meta_map: dict = {}  # norm_url -> {method, body_params, content_type}
        for ep in ctx.endpoints:
            ep_url  = ep.get("url", "")
            ep_norm = _norm_for_target(ep_url)
            ep_meta_map[ep_norm] = {
                "method":       ep.get("method", "GET"),
                "body_params":  ep.get("body_params", []),
                "content_type": ep.get("content_type", ""),
            }

        priority_keywords = (
            "login", "auth", "admin", "api", "account", "user",
            "search", "redirect", "callback", "upload", "file", "download",
        )

        # Build scan_targets as rich dicts so VulnEngine and _PlanDrivenDE
        # receive the actual discovered parameter names AND the HTTP method.
        def _make_target(url, params):
            norm = _norm_for_target(url)
            meta = ep_meta_map.get(norm, {})
            return {
                "url":          url,
                "parameters":   params,
                "tags":         [],
                "method":       meta.get("method", "GET"),
                "body_params":  meta.get("body_params", []),
                "content_type": meta.get("content_type", ""),
            }

        priority_targets = [
            _make_target(url, params)
            for url, params in ep_param_map.items()
            if any(k in url.lower() for k in priority_keywords)
        ]
        other_targets = [
            _make_target(url, params)
            for url, params in ep_param_map.items()
            if not any(k in url.lower() for k in priority_keywords)
        ]
        scan_targets = (priority_targets + other_targets)[:150]

        # ── AI Analysis Targets ───────────────────────────────────────
        analysis_targets = list(dict.fromkeys(
            e["url"] for e in ctx.endpoints
        ))
        analysis_targets.sort(
            key=lambda u: any(
                k in u.lower()
                for k in (
                    "login", "admin", "api", "auth", "account",
                    "user", "dashboard", "upload", "file", "search"
                )
            ),
            reverse=True
        )
        analysis_targets = analysis_targets[:250]

        print(f"[+] Vuln Engine Targets : {len(scan_targets)}")
        print(f"[+] AI Targets          : {len(analysis_targets)}")

        # ── Build PlanDrivenDE adapter ────────────────────────────────────
        # VulnEngine calls de.get_payloads(vuln_class) and de.get_vuln_classes().
        # DetectionEngine exposes select_payloads(vuln_id) and per-endpoint
        # DetectionRule lists (keyed by url).  The adapter bridges the two:
        # - get_vuln_classes() returns the union of all rule vulnerability IDs
        #   (payload_group slug, which maps to VulnEngine's class names)
        # - get_payloads(vuln_class) returns the merged recommended_payloads
        #   from every matching rule across all endpoints, falling back to
        #   DETECTION_ENGINE.select_payloads() when available.
        detection_plans = ctx.metadata.get("detection_plans", {})

        if _DE_AVAILABLE and detection_plans:
            plan_de = _PlanDrivenDE(detection_plans)
            total_plan_payloads = sum(
                len(v) for v in plan_de._class_payloads.values()
            )
            print(f"[+] Detection plans     : {len(detection_plans)} endpoints, "
                  f"{len(plan_de._class_payloads)} vuln classes, "
                  f"{total_plan_payloads} payloads queued")
        else:
            plan_de = None
            if not _DE_AVAILABLE:
                print("[!] Detection Engine unavailable — VulnEngine using default payloads")
            else:
                print("[!] No detection plans — VulnEngine using default payloads")

        # ── VulnEngine wrapper that preserves the __stats__ sentinel ─────
        # run_vuln_scan() strips the sentinel before returning, so we call
        # VulnEngine.scan() directly here via the same internal path,
        # capture stats with _extract_scan_stats() BEFORE _filter_real_findings()
        # strips them, then store the stats dict in ctx.metadata so the
        # reporting stage can read real telemetry values.
        #
        # run_vuln_scan() is NOT modified. VulnEngine.scan() is the same code
        # path — run_vuln_scan is a thin shim around it.
        def _run_vuln_with_stats(targets, technologies, detection_engine=None):
            from urllib.parse import urlparse as _up2, parse_qs as _pqs2
            endpoint_dicts, seen = [], set()
            for item in (targets or []):
                if isinstance(item, dict):
                    # Phase 1+2: scan_targets now carries pre-built
                    # {url, parameters, method, body_params, content_type} dicts.
                    # Use the preserved parameter names and method directly.
                    url = item.get("url", "")
                    if not url or url in seen:
                        continue
                    seen.add(url)
                    pre_params = item.get("parameters") or []
                    if not pre_params:
                        try:
                            pre_params = list(_pqs2(_up2(url).query).keys())
                        except Exception:
                            pre_params = []
                    endpoint_dicts.append({
                        "url":          url,
                        "tags":         item.get("tags", []),
                        "parameters":   pre_params,
                        "method":       item.get("method", "GET"),
                        "body_params":  item.get("body_params", []),
                        "content_type": item.get("content_type", ""),
                    })
                elif isinstance(item, str):
                    # Backward-compat: bare URL strings (e.g. from old callers)
                    url = item
                    if not url or url in seen:
                        continue
                    seen.add(url)
                    try:
                        qs_params = list(_pqs2(_up2(url).query).keys())
                    except Exception:
                        qs_params = []
                    endpoint_dicts.append({"url": url, "tags": [], "parameters": qs_params})
                else:
                    continue

            if not endpoint_dicts:
                return [], {}

            alive_hosts = []
            if technologies:
                for hk, tl in technologies.items():
                    if not isinstance(tl, list):
                        continue
                    hu = hk if hk.startswith(("http://", "https://")) else f"https://{hk}"
                    alive_hosts.append({"url": hu, "waf": "", "technologies": tl})

            if detection_engine is None:
                class _NoOpDE:
                    def get_vuln_classes(self): return []
                    def get_payloads(self, vc): return []
                    def test_endpoint(self, url, payload, param): return None
                detection_engine = _NoOpDE()

            # Phase 2: give the adapter its per-endpoint method/body metadata
            # BEFORE scan() is called so test_payload() can look it up.
            if hasattr(detection_engine, "populate_meta"):
                detection_engine.populate_meta(endpoint_dicts)

            engine = _VulnEngine(
                detection_engine=detection_engine,
                config=_ScanConfig(),
            )
            raw_output = engine.scan(
                endpoints=endpoint_dicts,
                alive_hosts=alive_hosts,
                technologies=technologies,
            )
            # Extract stats BEFORE stripping — the only place where raw_output
            # is available with the sentinel still present.
            stats = _extract_scan_stats(raw_output) or {}
            findings = _filter_real_findings(raw_output)
            return findings, stats

        # ── Run both simultaneously ───────────────────────────────────
        with ThreadPoolExecutor(max_workers=2) as executor:
            vuln_future = executor.submit(
                _run_vuln_with_stats,
                scan_targets,
                ctx.technologies,
                **({"detection_engine": plan_de} if plan_de is not None else {}),
            )
            ai_future = executor.submit(analyze_all, analysis_targets)

            try:
                vulns_engine, _vuln_stats = vuln_future.result()
            except Exception as e:
                ctx.add_warning("Vuln + AI", f"Vulnerability engine failed: {e}")
                vulns_engine, _vuln_stats = [], {}

            try:
                raw_analysis = ai_future.result()
            except Exception as e:
                ctx.add_warning("Vuln + AI", f"AI analysis failed: {e}")
                raw_analysis = []

        # Persist real VulnEngine telemetry for _stage_reporting.
        # Merge adapter HTTP counters (Fix 2) into the VulnEngine stats dict
        # so _stage_reporting sees all telemetry in one place.
        if plan_de is not None:
            _vuln_stats.setdefault("http_requests_attempted", 0)
            _vuln_stats.setdefault("http_request_failures",   0)
            _vuln_stats.setdefault("http_signals_detected",   0)
            _vuln_stats["http_requests_attempted"] = plan_de.http_requests_attempted
            _vuln_stats["http_request_failures"]   = plan_de.http_request_failures
            _vuln_stats["http_signals_detected"]   = plan_de.http_signals_detected
        ctx.metadata["_vuln_stats"]   = _vuln_stats
        ctx.metadata["_vuln_targets"] = scan_targets
        print(f"[+] Vulnerability findings: {len(vulns_engine)}")

        # Clean AI findings
        ai_findings = []
        for result in raw_analysis:
            if not isinstance(result, dict):
                continue
            findings = result.get("findings", [])
            if not findings:
                continue
            seen_types = set()
            cleaned = []
            for finding in findings:
                ftype = finding.get("type", "Unknown")
                if ftype in seen_types:
                    continue
                seen_types.add(ftype)
                cleaned.append(finding)
            result["findings"] = cleaned
            ai_findings.append(result)

        print(f"[+] AI produced "
              f"{sum(len(r['findings']) for r in ai_findings)} findings")

        ctx.analysis = ai_findings
        ctx.metadata["vulns_engine"] = vulns_engine
        return len(vulns_engine) + len(ai_findings)

    _run_stage(ctx, "Vulnerability Engine + AI", _stage_vuln_and_ai, ctx)

    # ─────────────────────────────────────────────────────────────────────
    # STAGE: Merge Findings
    # Combines smart_findings, vuln_engine, and AI engine results.
    # ─────────────────────────────────────────────────────────────────────
    def _stage_merge(ctx):
        print("[+] Merging findings from all engines...")

        smart_confirmed  = ctx.metadata.get("smart_findings", [])   # confirmed only
        smart_candidates = ctx.metadata.get("smart_candidates", []) # recon intel
        vulns_engine     = ctx.metadata.get("vulns_engine", [])
        ai_findings      = ctx.analysis

        all_raw = []

        # ── Smart confirmed findings ──────────────────────────────────
        for f in smart_confirmed:
            all_raw.append({
                "type":      f.get("type", "Unknown"),
                "url":       f.get("url", ""),
                "severity":  f.get("severity", "Low"),
                "reason":    f.get("reason", ""),
                "parameter": f.get("parameter", ""),
                "payload":   f.get("payload", ""),
                "source":    f.get("source", "Smart Tests"),
                "smart_status": "confirmed",
            })

        # ── Vulnerability engine findings ─────────────────────────────
        for f in vulns_engine:
            all_raw.append({
                "type":      f.get("type", "Unknown"),
                "url":       f.get("url", ""),
                "severity":  f.get("severity", "Low"),
                "reason":    f.get("reason", ""),
                "parameter": f.get("parameter", f.get("param", "")),
                "payload":   f.get("payload", ""),
                "source":    "Vuln Engine",
                "confidence": f.get("confidence", 50),
            })

        # ── AI analysis findings ──────────────────────────────────────
        for result in ai_findings:
            endpoint = result.get("url", "")
            for f in result.get("findings", []):
                all_raw.append({
                    "type":     f.get("type", "Unknown"),
                    "url":      endpoint,
                    "severity": f.get("severity", "Low"),
                    "reason":   f.get("reason", ""),
                    "source":   "AI",
                    "confidence": f.get("confidence", 50),
                })

        # ── Canonical identity dedup ──────────────────────────────────
        # Uses the same (normalised_url, param, vuln_class) key as
        # VulnEngine.FindingRegistry so the dedup boundary is identical
        # regardless of which engine produced the finding.
        #
        # Endpoint-level classes  → key = (norm_url, "",    vuln_class)
        # Parameter-level classes → key = (norm_url, param, vuln_class)
        #
        # This means /admin?apikey=test and /admin?token=test produce ONE
        # MISSING_CSP finding.  /search?q=x XSS and /search?name=x XSS
        # remain TWO findings.
        severity_rank   = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1}
        merged: dict    = {}
        ep_dedup_count  = 0
        param_dedup_count = 0

        for finding in all_raw:
            raw_url    = (finding.get("url") or "").strip()
            if not raw_url:
                continue
            ftype      = (finding.get("type") or "Unknown").strip()
            param      = (finding.get("parameter") or "").lower().strip()
            severity   = finding.get("severity", "Low").title()
            if severity not in severity_rank:
                severity = "Low"
            finding["severity"] = severity

            # Map display type → canonical vuln class for keying
            vuln_class = _SMART_TYPE_TO_VULN_CLASS.get(
                ftype.lower(),
                ftype.upper().replace(" ", "_")
            )

            norm_url = _norm_url(raw_url)
            if _ep_level(vuln_class):
                key = (norm_url, "", vuln_class)
            else:
                key = (norm_url, param, vuln_class)

            if key not in merged:
                merged[key] = finding
            else:
                existing = merged[key]
                # Track dedup collisions by type for telemetry
                if _ep_level(vuln_class):
                    ep_dedup_count += 1
                else:
                    param_dedup_count += 1
                # Keep the higher-severity / higher-confidence version
                existing_rank = severity_rank.get(existing.get("severity", "Low"), 1)
                new_rank      = severity_rank.get(severity, 1)
                incoming_conf = finding.get("confidence", 50)
                existing_conf = existing.get("confidence", 50)
                if new_rank > existing_rank or (
                    new_rank == existing_rank and incoming_conf > existing_conf
                ):
                    merged[key] = finding

        unique_findings = list(merged.values())

        print(f"[+] Raw findings (all engines)      : {len(all_raw)}")
        print(f"[+]   Smart confirmed                : {len(smart_confirmed)}")
        print(f"[+]   Smart candidates (not merged)  : {len(smart_candidates)}")
        print(f"[+]   Vuln Engine                    : {len(vulns_engine)}")
        print(f"[+]   AI                             : "
              f"{sum(len(r.get('findings', [])) for r in ai_findings)}")
        print(f"[+] Endpoint-level deduplications    : {ep_dedup_count}")
        print(f"[+] Parameter-level deduplications   : {param_dedup_count}")
        print(f"[+] Canonical unique findings        : {len(unique_findings)}")

        ctx.metadata["unique_findings"]      = unique_findings
        ctx.metadata["smart_candidates"]     = smart_candidates  # forward to report
        ctx.metadata["merge_telemetry"] = {
            "raw_total":           len(all_raw),
            "smart_confirmed":     len(smart_confirmed),
            "smart_candidates":    len(smart_candidates),
            "vuln_engine":         len(vulns_engine),
            "ai":                  sum(len(r.get("findings", [])) for r in ai_findings),
            "ep_dedup":            ep_dedup_count,
            "param_dedup":         param_dedup_count,
            "canonical_unique":    len(unique_findings),
        }
        return unique_findings

    _run_stage(ctx, "Merge Findings", _stage_merge, ctx)

    # ─────────────────────────────────────────────────────────────────────
    # STAGE: Validation + CVSS Scoring
    # ─────────────────────────────────────────────────────────────────────
    def _stage_validation(ctx):
        unique_findings = ctx.metadata.get("unique_findings", [])
        print(f"[+] Validating {len(unique_findings)} findings...")

        validators = {
            "redirect": validate_open_redirect,
            "xss": validate_xss,
            "sqli": validate_sqli,
        }

        validated_findings = []

        for finding in unique_findings:
            vuln_type = finding.get("type", "").lower()
            url = finding.get("url", "")
            confirmed = False
            poc = url
            validator_used = None

            for keyword, validator in validators.items():
                if keyword in vuln_type:
                    validator_used = keyword
                    try:
                        confirmed, poc = validator(url)
                    except Exception as e:
                        ctx.add_warning("Validation",
                                        f"Validator error ({keyword}): {e}")
                    break

            if confirmed:
                confidence = 95
            elif validator_used:
                confidence = 65
            else:
                confidence = 55

            try:
                cvss = calculate_cvss(finding.get("type", "Unknown"))
            except Exception:
                cvss = {"score": 5.0, "severity": "Medium"}

            validated_findings.append({
                "type": finding.get("type", "Unknown"),
                "url": url,
                "severity": cvss.get("severity", "Medium"),
                "cvss": cvss.get("score", 5.0),
                "confidence": confidence,
                "confirmed": confirmed,
                "validator": validator_used,
                "poc": poc,
                "reason": finding.get("reason", ""),
                "source": finding.get("source", "Unknown")
            })

        confirmed_count = sum(1 for f in validated_findings if f["confirmed"])
        print(f"[+] Confirmed findings: {confirmed_count}")

        ctx.findings = validated_findings
        return validated_findings

    _run_stage(ctx, "Validation + CVSS", _stage_validation, ctx)

    # ─────────────────────────────────────────────────────────────────────
    # STAGE: Exploit Generation + Validation
    # ─────────────────────────────────────────────────────────────────────
    def _stage_exploits(ctx):
        print("[+] Generating exploit PoCs...")

        sorted_findings = sorted(
            ctx.findings,
            key=lambda f: (
                f.get("confirmed", False),
                f.get("confidence", 0),
                f.get("cvss", 0)
            ),
            reverse=True
        )

        MAX_EXPLOITS = 50
        targets = [
            f for f in sorted_findings
            if f.get("confidence", 0) >= 60
        ][:MAX_EXPLOITS]

        exploits = []
        for finding in targets:
            try:
                exploit = generate_exploit(finding)
                if exploit:
                    exploit["confidence"] = finding.get("confidence")
                    exploit["severity"] = finding.get("severity")
                    exploit["cvss"] = finding.get("cvss")
                    exploit["confirmed"] = finding.get("confirmed")
                    exploit["source"] = finding.get("source")
                    exploits.append(exploit)
            except Exception as e:
                ctx.add_warning("Exploits", f"Generation failed: {e}")

        try:
            validated_exploits = validate_all(exploits) if exploits else []
        except Exception as e:
            ctx.add_warning("Exploits", f"Validation error: {e}")
            validated_exploits = []

        print(f"[+] Exploit targets    : {len(targets)}")
        print(f"[+] Exploits generated : {len(exploits)}")
        print(f"[+] Validated exploits : {len(validated_exploits)}")

        ctx.metadata["exploits"] = exploits
        ctx.validated_exploits = validated_exploits
        return validated_exploits

    _run_stage(ctx, "Exploit Generation", _stage_exploits, ctx)

    # ─────────────────────────────────────────────────────────────────────
    # STAGE: Risk Scoring + Prioritization
    # ─────────────────────────────────────────────────────────────────────
    def _stage_risk(ctx):
        print("[+] Calculating overall risk...")

        risk_targets = list(dict.fromkeys(e["url"] for e in ctx.endpoints))

        try:
            risk = calculate_risk(risk_targets, ctx.live_hosts, ctx.findings)
        except Exception as e:
            ctx.add_warning("Risk Scoring", f"Risk calculation failed: {e}")
            risk = {"critical": [], "high": [], "medium": [], "low": []}

        print("[+] Prioritizing attack targets...")

        try:
            priorities = prioritize_all(ctx.endpoints, findings=ctx.findings)
        except TypeError:
            # Backwards compatibility with older prioritizer.py
            priorities = prioritize_all(ctx.endpoints)
        except Exception as e:
            ctx.add_warning("Risk Scoring", f"Prioritizer failed: {e}")
            priorities = []

        print(f"[+] Priority targets: {len(priorities)}")

        ctx.risk = risk
        ctx.priorities = priorities
        return priorities

    _run_stage(ctx, "Risk + Prioritization", _stage_risk, ctx)

    # ─────────────────────────────────────────────────────────────────────
    # STAGE: Attack Surface Mapping
    # Reuses ctx.endpoints, ctx.findings, ctx.technologies, ctx.browser_recon.
    # ─────────────────────────────────────────────────────────────────────
    def _stage_attack_surface(ctx):
        print("[+] Mapping attack surface...")

        try:
            attack_surface = map_attack_surface(
                ctx.endpoints, findings=ctx.findings
            )
        except TypeError:
            # Backward compatibility
            attack_surface = map_attack_surface(ctx.endpoints)
        except Exception as e:
            ctx.add_warning("Attack Surface", f"Mapper failed: {e}")
            attack_surface = {"chains": [], "high_value_targets": []}

        print(f"[+] High-value targets : "
              f"{len(attack_surface.get('high_value_targets', []))}")
        print(f"[+] Attack chains      : "
              f"{len(attack_surface.get('chains', []))}")

        # Visualization — passes already-collected ctx fields; no extra HTTP
        try:
            attack_surface_map = generate_attack_surface({
                "domain": ctx.domain,
                "subdomains": ctx.subdomains,
                "live_hosts": ctx.live_hosts,
                "endpoints": ctx.endpoints,
                "findings": ctx.findings,
                "technologies": ctx.technologies,
                "browser_recon": ctx.browser_recon,
                "attack_surface": attack_surface,
            })
        except Exception as e:
            ctx.add_warning("Attack Surface", f"Visualization failed: {e}")
            attack_surface_map = {}

        ctx.attack_surface = attack_surface
        ctx.attack_surface_map = attack_surface_map
        return attack_surface

    _run_stage(ctx, "Attack Surface", _stage_attack_surface, ctx)

    # ─────────────────────────────────────────────────────────────────────
    # STAGE: Reporting (statistics + summary print)
    # ─────────────────────────────────────────────────────────────────────
    def _stage_reporting(ctx):
        exploits = ctx.metadata.get("exploits", [])
        mt       = ctx.metadata.get("merge_telemetry", {})

        # VulnEngine stats — stored by _stage_vuln_and_ai before sentinel was stripped.
        # _vuln_stats is the raw __stats__ dict from VulnEngine.scan(); it contains
        # real payloads_attempted, payloads_skipped, confirmations, etc.
        ve_stats = ctx.metadata.get("_vuln_stats", {})

        # Smart test counts
        smart_all        = ctx.metadata.get("smart_all", [])
        smart_confirmed  = ctx.metadata.get("smart_findings", [])
        smart_candidates = ctx.metadata.get("smart_candidates", [])

        # Detection plan counts
        detection_plans  = ctx.metadata.get("detection_plans", {})
        total_plan_rules = sum(len(v) for v in detection_plans.values())

        ctx.statistics = {
            "domain":             ctx.domain,
            "subdomains":         len(ctx.subdomains),
            "live_hosts":         len(ctx.live_hosts),
            "endpoints":          len(ctx.endpoints),
            "findings":           len(ctx.findings),
            "confirmed":          sum(1 for f in ctx.findings if f.get("confirmed")),
            "exploits":           len(exploits),
            "validated_exploits": len(ctx.validated_exploits),
            "priority_targets":   len(ctx.priorities),
            "js_files":           len(ctx.js_files),
            "secrets":            len(ctx.secrets),
            "js_intelligence":    len(ctx.js_intelligence),
            "parameters":         len(ctx.parameters),
            "screenshots":        len(ctx.screenshots),
            "stage_errors":       len(ctx.metadata.get("stage_errors", {})),
            # ── Telemetry: Smart Tests ──────────────────────────────────
            "smart_candidates":   len(smart_candidates),
            "smart_confirmed":    len(smart_confirmed),
            "smart_total":        len(smart_all),
            # ── Telemetry: Detection Engine ─────────────────────────────
            "detection_engine_available": _DE_AVAILABLE,
            "detection_plans_endpoints":  len(detection_plans),
            "detection_plans_rules":      total_plan_rules,
            # ── Telemetry: VulnEngine ───────────────────────────────────
            "vuln_engine_targets":        len(ctx.metadata.get("_vuln_targets", [])),
            "vuln_engine_findings":       mt.get("vuln_engine", 0),
            "vuln_payloads_attempted":    ve_stats.get("payloads_attempted", 0),
            "vuln_payloads_skipped":      ve_stats.get("payloads_skipped", 0),
            "vuln_confirmations":         ve_stats.get("confirmations", 0),
            "vuln_ep_dedup":              ve_stats.get("endpoint_level_deduplicated", 0),
            # ── Telemetry: Adapter HTTP counters (Fix 2) ────────────────────
            "http_requests_attempted":    ve_stats.get("http_requests_attempted", 0),
            "http_request_failures":      ve_stats.get("http_request_failures",   0),
            "http_signals_detected":      ve_stats.get("http_signals_detected",   0),
            # ── Telemetry: AI ───────────────────────────────────────────
            "ai_findings":                mt.get("ai", 0),
            # ── Telemetry: Merge ────────────────────────────────────────
            "merge_raw_total":            mt.get("raw_total", 0),
            "merge_ep_dedup":             mt.get("ep_dedup", 0),
            "merge_param_dedup":          mt.get("param_dedup", 0),
            "merge_canonical_unique":     mt.get("canonical_unique", 0),
        }

        total_elapsed = round(time.perf_counter() - scan_start, 2)

        print("\n" + "=" * 60)
        print("[✓] Recon completed successfully")
        print("=" * 60)
        print(f"Target            : {ctx.domain}")
        print(f"Subdomains        : {ctx.statistics['subdomains']}")
        print(f"Live Hosts        : {ctx.statistics['live_hosts']}")
        print(f"Endpoints         : {ctx.statistics['endpoints']}")
        print(f"--- Smart Tests ---")
        print(f"Smart Candidates  : {ctx.statistics['smart_candidates']}")
        print(f"Smart Confirmed   : {ctx.statistics['smart_confirmed']}")
        print(f"--- Detection Engine ---")
        print(f"DE Available      : {ctx.statistics['detection_engine_available']}")
        print(f"DE Plans          : {ctx.statistics['detection_plans_endpoints']} endpoints, "
              f"{ctx.statistics['detection_plans_rules']} rules")
        print(f"--- Vulnerability Engine ---")
        print(f"VE Targets        : {ctx.statistics['vuln_engine_targets']}")
        print(f"VE Payloads       : {ctx.statistics['vuln_payloads_attempted']} attempted, "
              f"{ctx.statistics['vuln_payloads_skipped']} skipped")
        print(f"VE HTTP Requests  : {ctx.statistics['http_requests_attempted']} attempted, "
              f"{ctx.statistics['http_request_failures']} failed, "
              f"{ctx.statistics['http_signals_detected']} signals")
        print(f"VE Findings       : {ctx.statistics['vuln_engine_findings']}")
        print(f"VE Confirmations  : {ctx.statistics['vuln_confirmations']}")
        print(f"--- AI ---")
        print(f"AI Findings       : {ctx.statistics['ai_findings']}")
        print(f"--- Merge ---")
        print(f"Raw Total         : {ctx.statistics['merge_raw_total']}")
        print(f"EP-level dedup    : {ctx.statistics['merge_ep_dedup']} collapsed")
        print(f"Param-level dedup : {ctx.statistics['merge_param_dedup']} collapsed")
        print(f"Canonical Unique  : {ctx.statistics['merge_canonical_unique']}")
        print(f"--- Final ---")
        print(f"Findings          : {ctx.statistics['findings']}")
        print(f"Confirmed         : {ctx.statistics['confirmed']}")
        print(f"Exploits          : {ctx.statistics['exploits']}")
        print(f"Validated PoCs    : {ctx.statistics['validated_exploits']}")
        print(f"Priority Targets  : {ctx.statistics['priority_targets']}")
        print(f"Stage Errors      : {ctx.statistics['stage_errors']}")
        print(f"Total Time        : {total_elapsed:.2f}s")
        print("=" * 60)

        if ctx.timings:
            print("\n[+] Stage timings:")
            for stage, elapsed in ctx.timings.items():
                items = ctx.metadata["stage_items"].get(stage, "")
                errs = "ERR" if stage in ctx.metadata.get("stage_errors", {}) else ""
                print(f"  {stage:<35} {elapsed:>6.2f}s  "
                      f"items={items!s:<6}  {errs}")

        if ctx.metadata.get("stage_errors"):
            print("\n[!] Stages with errors:")
            for stage, err in ctx.metadata["stage_errors"].items():
                print(f"  {stage}: {err}")

        return ctx.statistics

    _run_stage(ctx, "Reporting", _stage_reporting, ctx)

    # ─────────────────────────────────────────────────────────────────────
    # Return the same dict format as v2 (backwards compatible)
    # ─────────────────────────────────────────────────────────────────────
    return ctx.to_result_dict()


# ===============================================
# CLI TEST
# ===============================================

if __name__ == "__main__":
    target = input("Enter target domain: ").strip()
    results = run_recon(target)

    print("\n===== RESULTS =====")
    print(f"\nSubdomains ({len(results['subdomains'])}):")
    for s in results["subdomains"]:
        print(f"  {s}")

    print(f"\nLive Hosts ({len(results['live_hosts'])}):")
    for h in results["live_hosts"]:
        print(f"  [{h['status']}] {h['url']}")

    print(f"\nFindings ({len(results['findings'])}):")
    for f in results["findings"][:20]:
        print(f"  [{f['severity']}] {f['type']} - {f['url']}")

    print(f"\nExploits ({len(results['exploits'])}):")
    for e in results["exploits"][:10]:
        print(f"  {e}")
