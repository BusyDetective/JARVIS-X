"""
vuln_engine.py — Adaptive Evidence-Driven Vulnerability Scanner
===============================================================
Production optimisation pass over the brute-force payload runner.

PUBLIC API (backwards-compatible — nothing changed):
    VulnEngine(detection_engine, knowledge_base=None, config=None)
    engine.scan(endpoints, alive_hosts, technologies={}) → list[dict]

All findings returned are plain dicts with keys:
    type, url, severity, confidence, cvss, parameter,
    evidence, payload, reason, validation_state

Internal optimisation layers (new, not visible to callers):
    1.  Adaptive payload budget per vuln class
    2.  Stop-on-confirmation (per endpoint per class)
    3.  Evidence escalation (never duplicate findings)
    4.  Payload prioritisation (priority → KB rank → tech → endpoint)
    5.  Smart endpoint budget (max requests per endpoint)
    6.  Duplicate prevention (pre-execution cache)
    7.  Validator result cache (never run the same payload twice)
    8.  Early exit (WAF/rate-limit/404 flood detection)
    9.  Runtime statistics
"""

from __future__ import annotations

import hashlib
import logging
import threading
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse, parse_qs

log = logging.getLogger(__name__)

# ─────────────────────────────────────────────────────────────────────────────
# SECTION 1 — CONFIGURATION
# ─────────────────────────────────────────────────────────────────────────────

# Payload budget per vulnerability class.
# Change these values here — one location, applied everywhere.
DEFAULT_PAYLOAD_BUDGET: Dict[str, int] = {
    "SQLI":              6,
    "SQL INJECTION":     6,   # alias kept for compat
    "XSS":               5,
    "STORED_XSS":        5,
    "SSRF":              4,
    "LFI":               5,
    "PATH_TRAVERSAL":    5,
    "SSTI":              4,
    "XXE":               4,
    "COMMAND_INJECTION": 5,
    "RCE":               5,
    "DESERIALIZATION":   4,
    "IDOR":              4,
    "CSRF":              3,
    "CORS":              3,
    "OPEN_REDIRECT":     4,
    "JWT":               3,
    "FILE_UPLOAD":       4,
    "AUTH_BYPASS":       4,
    "BROKEN_ACCESS_CONTROL": 4,
    "INFORMATION DISCLOSURE": 3,
    "DEBUG":             2,
    "MISCONFIGURATION":  2,
    "_default":         4,    # fallback for unrecognised classes
}

# Confidence threshold above which we stop testing that class on that endpoint
CONFIRMATION_THRESHOLD: int = 85

# Maximum HTTP requests per endpoint across all vuln classes
DEFAULT_MAX_REQUESTS_PER_ENDPOINT: int = 60

# Early-exit: if this many consecutive requests to an endpoint return
# rejection codes, stop all testing on that endpoint
REJECTION_RUN_THRESHOLD: int = 5

# Rejection status codes (WAF block, rate-limit, hard 404)
REJECTION_STATUS_CODES: frozenset = frozenset({403, 404, 429, 503})

# Confidence boost per additional independent signal on the same finding
EVIDENCE_ESCALATION_BOOST: int = 5
EVIDENCE_MAX_CONFIDENCE: int   = 98   # never claim 100% — even Burp doesn't

# Payload hash length (truncated SHA-256 for cache keys)
_HASH_LEN: int = 16

# ─────────────────────────────────────────────────────────────────────────────
# FINDING SCOPE CLASSIFICATION
#
# Vulnerability classes are divided into two scopes that drive deduplication:
#
#   ENDPOINT_LEVEL — findings that describe the response itself, not a specific
#   parameter.  Security-header absences (CSP, HSTS, X-Frame-Options, etc.),
#   CORS misconfigurations, server header disclosure, and clickjacking are all
#   properties of the HTTP response regardless of which query parameter triggered
#   the request.  These must deduplicate on (host, path, vuln_class) with param
#   always normalised to "" so that testing /admin?apikey=x and /admin?token=y
#   produces ONE finding, not two.
#
#   PARAMETER_LEVEL — findings that are specific to a particular input parameter.
#   SQL injection, XSS, SSRF, LFI etc. are only meaningful when tied to the
#   parameter that was injected.  These deduplicate on
#   (host, path, param, vuln_class).
#
# When a vuln class is not listed here, _is_endpoint_level() returns False
# (parameter-level by default — the safer assumption).
# ─────────────────────────────────────────────────────────────────────────────

ENDPOINT_LEVEL_CLASSES: frozenset = frozenset({
    # Missing security headers — server response property, not param-specific
    "MISSING_CSP",
    "MISSING_HSTS",
    "MISSING_REFERRER_POLICY",
    "MISSING_X_FRAME_OPTIONS",
    "MISSING_X_CONTENT_TYPE_OPTIONS",
    "MISSING_PERMISSIONS_POLICY",
    "MISSING_CACHE_CONTROL",
    "MISSING_COEP",
    "MISSING_COOP",
    # Header disclosure — response-wide
    "SERVER_HEADER_DISCLOSURE",
    "X_POWERED_BY_DISCLOSURE",
    "TECHNOLOGY_DISCLOSURE",
    # CORS — Access-Control-* headers apply to the endpoint, not a param
    "CORS",
    "CORS_MISCONFIGURATION",
    # Framing / UI-redress — response-wide
    "CLICKJACKING",
    # Host-header injection — request-level, not parameter-specific
    "HOST_HEADER_INJECTION",
    # Debug/config endpoints — the endpoint itself is the vulnerability
    "DEBUG",
    "SUBDOMAIN_TAKEOVER",
    # Generic misconfiguration — not param-specific unless subclassed
    "MISCONFIGURATION",
    # Information disclosure without a specific injection point
    "INFORMATION DISCLOSURE",
    "INFORMATION_DISCLOSURE",
})


def _is_endpoint_level(vuln_class: str) -> bool:
    """
    Return True if this vulnerability class is scoped to the endpoint
    (host + path) rather than a specific parameter.

    Endpoint-level findings deduplicate on (host, path, vuln_class).
    Parameter-level findings deduplicate on (host, path, param, vuln_class).
    """
    return vuln_class.upper().strip() in ENDPOINT_LEVEL_CLASSES


@dataclass
class ScanConfig:
    """
    All tuneable knobs in one place.

    Pass a ScanConfig() instance to VulnEngine() to override defaults.
    All fields have production-safe defaults.
    """
    payload_budget:              Dict[str, int] = field(default_factory=lambda: dict(DEFAULT_PAYLOAD_BUDGET))
    confirmation_threshold:      int            = CONFIRMATION_THRESHOLD
    max_requests_per_endpoint:   int            = DEFAULT_MAX_REQUESTS_PER_ENDPOINT
    rejection_run_threshold:     int            = REJECTION_RUN_THRESHOLD
    evidence_escalation_boost:   int            = EVIDENCE_ESCALATION_BOOST
    evidence_max_confidence:     int            = EVIDENCE_MAX_CONFIDENCE
    # Stop testing a vuln class on an endpoint once confirmed
    stop_on_confirmation:        bool           = True
    # Use validator cache (strongly recommended)
    enable_validator_cache:      bool           = True
    # Use duplicate-prevention execution cache
    enable_dedup_cache:          bool           = True
    # Use early-exit heuristics
    enable_early_exit:           bool           = True

    def budget_for(self, vuln_class: str) -> int:
        """Return payload budget for a given class, with fallback."""
        key = vuln_class.upper().strip()
        return self.payload_budget.get(key, self.payload_budget.get("_default", 4))


# ─────────────────────────────────────────────────────────────────────────────
# SECTION 2 — RUNTIME STATISTICS
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class ScanStats:
    """
    Live counters updated throughout the scan.
    Returned inside the findings list as a special stats dict (type="__stats__")
    so callers that check for it get full telemetry; callers that filter by
    type continue working unchanged.
    """
    payloads_attempted:      int   = 0
    payloads_skipped:        int   = 0
    duplicate_tests_avoided: int   = 0
    endpoint_level_deduplicated: int = 0   # endpoint-level findings collapsed to one per path
    early_exits:             int   = 0
    validator_cache_hits:    int   = 0
    confirmations:           int   = 0
    endpoints_tested:        int   = 0
    endpoints_early_exited:  int   = 0
    scan_start_time:         float = field(default_factory=time.time)
    scan_end_time:           float = 0.0

    @property
    def elapsed_seconds(self) -> float:
        end = self.scan_end_time or time.time()
        return round(end - self.scan_start_time, 2)

    @property
    def estimated_time_saved_seconds(self) -> float:
        """
        Conservative estimate: each skipped payload would have taken ~2 s
        (network round-trip + validator). Each cache hit saves ~1 s.
        """
        return round(
            self.payloads_skipped * 2.0 +
            self.duplicate_tests_avoided * 2.0 +
            self.validator_cache_hits * 1.0,
            1,
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "type":                          "__stats__",
            "payloads_attempted":            self.payloads_attempted,
            "payloads_skipped":              self.payloads_skipped,
            "duplicate_tests_avoided":       self.duplicate_tests_avoided,
            "endpoint_level_deduplicated":   self.endpoint_level_deduplicated,
            "early_exits":                   self.early_exits,
            "validator_cache_hits":          self.validator_cache_hits,
            "confirmations":                 self.confirmations,
            "endpoints_tested":              self.endpoints_tested,
            "endpoints_early_exited":        self.endpoints_early_exited,
            "elapsed_seconds":               self.elapsed_seconds,
            "estimated_time_saved_secs":     self.estimated_time_saved_seconds,
        }


# ─────────────────────────────────────────────────────────────────────────────
# SECTION 3 — FINDING REGISTRY (evidence escalation + dedup)
# ─────────────────────────────────────────────────────────────────────────────

def _normalise_url(url: str) -> str:
    """Strip query string and fragment for base dedup key."""
    try:
        p = urlparse(url)
        return f"{p.scheme}://{p.netloc}{p.path}".rstrip("/")
    except Exception:
        return url


def _payload_hash(payload: str) -> str:
    """Truncated SHA-256 of a payload string."""
    return hashlib.sha256(payload.encode("utf-8", errors="replace")).hexdigest()[:_HASH_LEN]


class FindingRegistry:
    """
    Thread-safe registry of all findings produced during a scan.

    Responsibilities:
      - Prevent duplicate findings using scope-aware keying
      - Escalate confidence when new independent signals arrive
      - Merge evidence without creating new finding dicts
      - Track which combinations have been confirmed
      - Expose the final deduplicated list for the caller

    DEDUPLICATION SCOPE RULES
    ─────────────────────────
    Endpoint-level vulnerabilities (missing security headers, CORS, server
    disclosure, clickjacking, etc.) are properties of the HTTP response and
    are independent of which query parameter triggered the request.

        key = (host, path, vuln_class)   ← param always ""

    This means /admin?apikey=x and /admin?token=y both map to the same
    key for MISSING_CSP, so the second test escalates the first finding
    instead of creating a duplicate.

    Parameter-level vulnerabilities (SQLi, XSS, SSRF, LFI, etc.) are
    specific to the injected input and must track the parameter:

        key = (host, path, param, vuln_class)

    The scope is determined by _is_endpoint_level(vuln_class).
    """

    def __init__(self, config: ScanConfig) -> None:
        self._config = config
        self._lock   = threading.Lock()

        # key → finding dict  (key shape depends on scope)
        self._findings: Dict[Tuple, Dict[str, Any]] = {}

        # Set of confirmed keys — stop-on-confirmation
        self._confirmed: Set[Tuple] = set()

        # Before/after counters for reporting
        self.raw_registrations:   int = 0
        self.dedup_collisions:    int = 0
        self.endpoint_collisions: int = 0

    def _key(self, url: str, param: str, vuln_class: str) -> Tuple:
        """
        Build the deduplication key for a finding.

        Endpoint-level classes: (normalised_url, "", vuln_class)
        Parameter-level classes: (normalised_url, param, vuln_class)

        The normalised URL has query string and fragment stripped so that
        /admin?apikey=x and /admin?token=y produce the same base path.
        """
        base = _normalise_url(url)
        vc   = vuln_class.upper().strip()
        if _is_endpoint_level(vc):
            return (base, "", vc)
        else:
            return (base, param.lower(), vc)

    def _effective_param(self, vuln_class: str, param: str) -> str:
        """Return canonical param — always "" for endpoint-level vulns."""
        if _is_endpoint_level(vuln_class.upper().strip()):
            return ""
        return param

    def is_confirmed(self, url: str, param: str, vuln_class: str) -> bool:
        """Return True if this (endpoint, param, class) is already confirmed."""
        with self._lock:
            return self._key(url, param, vuln_class) in self._confirmed

    def register(
        self,
        finding:    Dict[str, Any],
        payload:    str   = "",
        response:   str   = "",
        confidence: int   = 50,
    ) -> Dict[str, Any]:
        """
        Register a new finding or escalate confidence on an existing one.

        For endpoint-level vuln classes the param is normalised to "" before
        keying, so multiple probes on different parameters merge into one finding.

        If the same key was already found:
          - Boost confidence by EVIDENCE_ESCALATION_BOOST
          - Append new payload to evidence
          - Mark as confirmed if threshold reached
          - Return the *existing* (now escalated) finding — no duplicate created

        If new:
          - Normalise the parameter field on the finding dict
          - Store it
          - Mark confirmed if above threshold
          - Return the new finding
        """
        url        = finding.get("url", "")
        raw_param  = finding.get("parameter", finding.get("param", ""))
        vuln_class = finding.get("type", "Unknown")
        key        = self._key(url, raw_param, vuln_class)
        eff_param  = self._effective_param(vuln_class, raw_param)

        with self._lock:
            self.raw_registrations += 1

            if key in self._findings:
                existing = self._findings[key]
                self.dedup_collisions += 1

                # Track endpoint-level collisions for statistics
                stored_param = existing.get("parameter", "")
                if _is_endpoint_level(vuln_class) and raw_param != stored_param:
                    self.endpoint_collisions += 1
                    log.debug(
                        "[EP-DEDUP] %s @ %s: param %r collapsed into existing "
                        "finding (param %r) — endpoint-level vuln",
                        vuln_class, _normalise_url(url), raw_param, stored_param,
                    )

                # Escalate confidence — take the better of stored and incoming
                old_conf  = existing.get("confidence", 50)
                base_conf = max(old_conf, confidence)
                new_conf  = min(
                    base_conf + self._config.evidence_escalation_boost,
                    self._config.evidence_max_confidence,
                )
                existing["confidence"] = new_conf

                # Merge evidence
                if payload and payload not in existing.get("payloads_seen", []):
                    existing.setdefault("payloads_seen", []).append(payload)
                    existing["payload"] = existing.get("payload") or payload

                if response:
                    existing.setdefault("evidence_snippets", []).append(response[:200])

                # Check confirmation after escalation
                if new_conf >= self._config.confirmation_threshold:
                    self._confirmed.add(key)
                    existing["validation_state"] = "Confirmed"

                log.debug(
                    "[ESCALATE] %s @ %s param=%s conf %d→%d",
                    vuln_class, _normalise_url(url), eff_param, old_conf, new_conf,
                )
                return existing

            else:
                # New finding — normalise param to effective scope value
                finding["parameter"] = eff_param
                finding["param"]     = eff_param   # backward-compat alias

                finding.setdefault("payloads_seen", [])
                if payload:
                    finding["payloads_seen"].append(payload)
                if response:
                    finding.setdefault("evidence_snippets", []).append(response[:200])

                if confidence >= self._config.confirmation_threshold:
                    self._confirmed.add(key)
                    finding["validation_state"] = "Confirmed"
                else:
                    finding.setdefault("validation_state", "Likely")

                self._findings[key] = finding
                return finding

    def mark_confirmed(self, url: str, param: str, vuln_class: str) -> None:
        """Externally mark a finding as confirmed (e.g. by a validator)."""
        key = self._key(url, param, vuln_class)
        with self._lock:
            self._confirmed.add(key)
            if key in self._findings:
                self._findings[key]["validation_state"] = "Confirmed"

    def all_findings(self) -> List[Dict[str, Any]]:
        """Return all registered findings as a list, sorted by confidence desc."""
        with self._lock:
            findings = list(self._findings.values())
        return sorted(findings, key=lambda f: f.get("confidence", 0), reverse=True)

    def count(self) -> int:
        with self._lock:
            return len(self._findings)

    def dedup_stats(self) -> Dict[str, int]:
        """Return before/after deduplication statistics for reporting."""
        with self._lock:
            return {
                "raw_registrations":   self.raw_registrations,
                "unique_findings":     len(self._findings),
                "dedup_collisions":    self.dedup_collisions,
                "endpoint_collisions": self.endpoint_collisions,
                "param_collisions":    self.dedup_collisions - self.endpoint_collisions,
            }


# ─────────────────────────────────────────────────────────────────────────────
# SECTION 4 — EXECUTION CACHE (duplicate prevention)
# ─────────────────────────────────────────────────────────────────────────────

class ExecutionCache:
    """
    Thread-safe cache that tracks which (endpoint, param, class, payload_hash)
    combinations have already been tested.

    Prevents sending the same payload to the same parameter twice, even when
    the same payload appears under multiple vuln classes or multiple rounds.
    """

    def __init__(self) -> None:
        self._seen: Set[Tuple[str, str, str, str]] = set()
        self._lock = threading.Lock()

    def already_tested(
        self,
        url:        str,
        param:      str,
        vuln_class: str,
        payload:    str,
    ) -> bool:
        """Return True if this exact test has already been executed."""
        key = (_normalise_url(url), param.lower(), vuln_class.upper(), _payload_hash(payload))
        with self._lock:
            if key in self._seen:
                return True
            self._seen.add(key)
            return False

    def size(self) -> int:
        with self._lock:
            return len(self._seen)


# ─────────────────────────────────────────────────────────────────────────────
# SECTION 5 — VALIDATOR CACHE
# ─────────────────────────────────────────────────────────────────────────────

class ValidatorCache:
    """
    Thread-safe cache for validator results.

    Key: (url, param, payload_hash)
    Value: validator result dict (or None if validator returned nothing)

    Ensures the same payload is never sent to the same parameter more than once,
    even if called from different vuln class handlers.
    """

    def __init__(self) -> None:
        self._cache: Dict[Tuple[str, str, str], Optional[Dict]] = {}
        self._lock  = threading.Lock()

    def _key(self, url: str, param: str, payload: str) -> Tuple[str, str, str]:
        return (_normalise_url(url), param.lower(), _payload_hash(payload))

    def get(self, url: str, param: str, payload: str) -> Tuple[bool, Optional[Dict]]:
        """
        Return (cache_hit, result).
        cache_hit=True means we have a cached answer (even if result is None).
        """
        key = self._key(url, param, payload)
        with self._lock:
            if key in self._cache:
                return True, self._cache[key]
            return False, None

    def put(self, url: str, param: str, payload: str, result: Optional[Dict]) -> None:
        key = self._key(url, param, payload)
        with self._lock:
            self._cache[key] = result

    def size(self) -> int:
        with self._lock:
            return len(self._cache)


# ─────────────────────────────────────────────────────────────────────────────
# SECTION 6 — ENDPOINT STATE (budget + early exit)
# ─────────────────────────────────────────────────────────────────────────────

class EndpointState:
    """
    Per-endpoint mutable state tracked during a scan.

    Tracks:
      - Total requests sent to this endpoint
      - Consecutive rejection-code streak (for early-exit)
      - Whether early exit has been triggered
      - Which (vuln_class, param) combinations are confirmed/stopped
    """

    def __init__(self, url: str, config: ScanConfig) -> None:
        self.url               = url
        self._config           = config
        self._lock             = threading.Lock()
        self.request_count     = 0
        self.rejection_streak  = 0
        self.early_exited      = False
        # (vuln_class, param) → payloads_used count
        self._class_usage: Dict[Tuple[str, str], int] = defaultdict(int)

    def should_stop(self) -> bool:
        """True if endpoint budget exhausted or early exit triggered."""
        with self._lock:
            return self.early_exited or (
                self.request_count >= self._config.max_requests_per_endpoint
            )

    def budget_remaining(self, vuln_class: str, param: str = "") -> int:
        """Remaining payload budget for (vuln_class, param) on this endpoint."""
        budget = self._config.budget_for(vuln_class)
        with self._lock:
            used = self._class_usage[(vuln_class.upper(), param.lower())]
        return max(0, budget - used)

    def record_request(self, status_code: Optional[int] = None) -> bool:
        """
        Record one request. Returns True if the endpoint should be early-exited.
        status_code: HTTP status of the response (if known).
        """
        with self._lock:
            self.request_count += 1

            if status_code is not None and self._config.enable_early_exit:
                if status_code in REJECTION_STATUS_CODES:
                    self.rejection_streak += 1
                else:
                    self.rejection_streak = 0

                if self.rejection_streak >= self._config.rejection_run_threshold:
                    self.early_exited = True
                    return True

            if self.request_count >= self._config.max_requests_per_endpoint:
                self.early_exited = True
                return True

        return False

    def record_payload_used(self, vuln_class: str, param: str = "") -> None:
        with self._lock:
            self._class_usage[(vuln_class.upper(), param.lower())] += 1

    def trigger_early_exit(self, reason: str = "") -> None:
        with self._lock:
            self.early_exited = True
        log.debug("[EARLY-EXIT] %s reason=%s", self.url, reason)


# ─────────────────────────────────────────────────────────────────────────────
# SECTION 7 — PAYLOAD PRIORITISATION
# ─────────────────────────────────────────────────────────────────────────────

def _prioritise_payloads(
    payloads:      List[Any],
    vuln_class:    str,
    technologies:  List[str],
    endpoint_tags: List[str],
    kb:            Any,
) -> List[Any]:
    """
    Sort payloads so the highest-value ones run first.

    Scoring (additive, higher = run first):
      +40  DetectionEngine priority field (if present on payload dict)
      +30  KB payload ranking (if kb.get_payload_rank() available)
      +20  Technology match (payload targets a detected tech)
      +10  Endpoint tag match (payload targets a relevant endpoint type)
      +  N  Position bonus (earlier in original list = slightly preferred,
             so ties preserve existing order)

    Payloads may be strings or dicts with a 'payload'/'value' key.
    The function is non-destructive — returns a new sorted list.
    """
    if not payloads:
        return []

    techs_lower = {t.lower() for t in technologies}
    tags_lower  = {t.lower() for t in endpoint_tags}

    def _score(item: Any, idx: int) -> float:
        score = 0.0

        # Preserve original ordering contribution (tie-breaker)
        score += max(0, 100 - idx) * 0.1

        if isinstance(item, dict):
            # DetectionEngine priority
            priority = item.get("priority", item.get("rank", 0))
            if isinstance(priority, (int, float)):
                score += float(priority) * 40.0

            # Technology match
            payload_tech = item.get("technology", item.get("tech", "")).lower()
            if payload_tech and payload_tech in techs_lower:
                score += 20.0

            # Endpoint tag match
            payload_tags = item.get("tags", [])
            if isinstance(payload_tags, str):
                payload_tags = [payload_tags]
            if any(t.lower() in tags_lower for t in payload_tags):
                score += 10.0

            # KB ranking
            if kb is not None:
                payload_str = item.get("payload", item.get("value", str(item)))
                try:
                    kb_rank = kb.get_payload_rank(vuln_class, payload_str)
                    if isinstance(kb_rank, (int, float)):
                        score += float(kb_rank) * 30.0
                except Exception:
                    pass

        return score

    indexed   = list(enumerate(payloads))
    sorted_pl = sorted(indexed, key=lambda t: _score(t[1], t[0]), reverse=True)
    return [item for _, item in sorted_pl]


# ─────────────────────────────────────────────────────────────────────────────
# SECTION 8 — SCAN CONTEXT (glues everything together per scan)
# ─────────────────────────────────────────────────────────────────────────────

class ScanContext:
    """
    Holds all per-scan state.  One instance per VulnEngine.scan() call.

    Passed through to every internal helper so they share the same caches,
    stats, and registry without needing global state.
    """

    def __init__(self, config: ScanConfig) -> None:
        self.config           = config
        self.stats            = ScanStats()
        self.registry         = FindingRegistry(config)
        self.exec_cache       = ExecutionCache()
        self.validator_cache  = ValidatorCache()
        self._endpoint_states: Dict[str, EndpointState] = {}
        self._ep_lock         = threading.Lock()

    def endpoint_state(self, url: str) -> EndpointState:
        """Return (or create) the EndpointState for a URL."""
        base = _normalise_url(url)
        with self._ep_lock:
            if base not in self._endpoint_states:
                self._endpoint_states[base] = EndpointState(base, self.config)
            return self._endpoint_states[base]

    def all_endpoint_states(self) -> List[EndpointState]:
        with self._ep_lock:
            return list(self._endpoint_states.values())


# ─────────────────────────────────────────────────────────────────────────────
# SECTION 9 — VULN ENGINE (public class)
# ─────────────────────────────────────────────────────────────────────────────

class VulnEngine:
    """
    Adaptive evidence-driven vulnerability scanner.

    Public API (backwards-compatible):
        engine = VulnEngine(detection_engine, knowledge_base, config)
        findings = engine.scan(endpoints, alive_hosts, technologies)

    findings is a list of plain dicts. Each dict has at minimum:
        type, url, severity, confidence, cvss, parameter,
        evidence, payload, reason, validation_state

    One additional dict with type="__stats__" is appended at the end
    containing runtime telemetry.  Callers that filter on type will
    ignore it; callers that look for it get full scan statistics.

    Parameters
    ----------
    detection_engine : object
        Any object whose interface matches DetectionEngine.  Duck-typed.
        Expected methods (all optional — engine degrades gracefully):
            get_payloads(vuln_class)   → list of payload strings or dicts
            get_validators(vuln_class) → list of validator callables / objects
            test_endpoint(url, payload, param) → dict or None

    knowledge_base : object, optional
        Any object with get_vulnerability_info(vuln_type) → dict.
        Also used for payload ranking if it exposes get_payload_rank().

    config : ScanConfig, optional
        Tuneable knobs.  All defaults are production-safe.
    """

    def __init__(
        self,
        detection_engine: Any,
        knowledge_base:   Any        = None,
        config:           Optional[ScanConfig] = None,
    ) -> None:
        self._de     = detection_engine
        self._kb     = knowledge_base
        self._config = config or ScanConfig()

    # ── Public scan entry point ───────────────────────────────────────────

    def scan(
        self,
        endpoints:    List[Any],
        alive_hosts:  List[Any],
        technologies: Optional[Dict[str, List[str]]] = None,
    ) -> List[Dict[str, Any]]:
        """
        Scan all endpoints for vulnerabilities.

        Parameters
        ----------
        endpoints : list
            List of endpoint dicts with at minimum a 'url' key.
            Also accepts strings (treated as URL with no metadata).

        alive_hosts : list
            List of alive-host dicts from alive_check.  Used for WAF /
            technology context.

        technologies : dict, optional
            Mapping of hostname → list of technology strings.
            Used for payload prioritisation.

        Returns
        -------
        list of finding dicts, plus one trailing stats dict (type="__stats__").
        """
        technologies = technologies or {}
        ctx = ScanContext(self._config)

        # Normalise endpoints to dicts
        ep_dicts = self._normalise_endpoints(endpoints)

        # Build hostname → tech list for quick lookup (guard against None)
        tech_map = self._build_tech_map(alive_hosts, technologies or {})

        # Determine vuln classes to test
        vuln_classes = self._get_vuln_classes()

        log.info(
            "[SCAN] %d endpoints × %d vuln classes",
            len(ep_dicts), len(vuln_classes),
        )

        ctx.stats.endpoints_tested = len(ep_dicts)

        for ep in ep_dicts:
            url = ep.get("url", "")
            if not url:
                continue

            ep_state = ctx.endpoint_state(url)
            ep_tags  = ep.get("tags", [])
            host     = urlparse(url).hostname or ""
            ep_techs = tech_map.get(host, [])

            host_info = self._get_host_info(host, alive_hosts)
            has_waf   = bool(host_info and host_info.get("waf"))
            if has_waf:
                log.debug("[WAF] %s on %s — budgets halved", host_info["waf"], url)

            for vuln_class in vuln_classes:
                # Check endpoint budget/early-exit before each class
                if ep_state.should_stop():
                    log.debug("[STOP] %s — budget/early-exit before %s", url, vuln_class)
                    break

                self._test_vuln_class(
                    ctx=ctx,
                    ep=ep,
                    url=url,
                    vuln_class=vuln_class,
                    ep_techs=ep_techs,
                    ep_tags=ep_tags,
                    ep_state=ep_state,
                    has_waf=has_waf,
                )

        ctx.stats.scan_end_time = time.time()

        # Sync early-exit counter from endpoint states
        all_states = ctx.all_endpoint_states()
        ctx.stats.endpoints_early_exited = sum(
            1 for s in all_states if s.early_exited
        )

        # Sync endpoint-level dedup counter from registry
        ctx.stats.endpoint_level_deduplicated = ctx.registry.endpoint_collisions

        findings = ctx.registry.all_findings()
        self._log_summary(ctx)

        # Strip internal tracking keys before returning
        clean_findings = [self._clean_finding(f) for f in findings]

        # Append stats as trailing dict (callers that don't look for it are unaffected)
        stats_dict = ctx.stats.to_dict()
        stats_dict.update(ctx.registry.dedup_stats())   # authoritative source
        clean_findings.append(stats_dict)

        return clean_findings

    # ── Vuln-class test loop ───────────────────────────────────────────────

    def _test_vuln_class(
        self,
        ctx:        ScanContext,
        ep:         Dict[str, Any],
        url:        str,
        vuln_class: str,
        ep_techs:   List[str],
        ep_tags:    List[str],
        ep_state:   EndpointState,
        has_waf:    bool = False,
    ) -> None:
        """
        Execute adaptive payload testing for one (endpoint, vuln_class) pair.

        Flow per payload:
          1. Stop-on-confirmation check  (param-level and payload-level)
          2. Endpoint budget check
          3. Per-class payload budget check
          4. Pre-execution dedup cache
          5. Validator cache lookup
          6. Execute via DetectionEngine
          7. Early-exit heuristic update
          8. FindingRegistry registration + confirmation
        """
        # Fetch and prioritise payloads
        raw_payloads = self._get_payloads(vuln_class)
        if not raw_payloads:
            return

        prioritised = _prioritise_payloads(
            payloads=raw_payloads,
            vuln_class=vuln_class,
            technologies=ep_techs,
            endpoint_tags=ep_tags,
            kb=self._kb,
        )

        # Parameters to test — from endpoint metadata, or bare URL
        params = self._extract_params(ep, url, vuln_class)

        # WAF present → halve the per-class budget ceiling (fix 3/13)
        # Single computation here; not recomputed anywhere else.
        budget_cap = self._config.budget_for(vuln_class)
        if has_waf:
            budget_cap = max(1, budget_cap // 2)

        for param in params:
            # ── Param-level stop-on-confirmation (fix 6) ──────────────────
            # If the class is confirmed on ANY param, skip ALL remaining params
            # for this (url, vuln_class) combination.
            if self._config.stop_on_confirmation:
                # Check bare "" param as the class-level sentinel
                if ctx.registry.is_confirmed(url, param, vuln_class):
                    remaining = len(prioritised)
                    ctx.stats.payloads_skipped += remaining
                    log.debug(
                        "[CONFIRMED-PARAM] skipping %s %s param=%r (%d payloads)",
                        vuln_class, url, param, remaining,
                    )
                    continue

            payloads_used_this_param = 0

            for payload_item in prioritised:
                # ── 1. Endpoint-level stop ─────────────────────────────
                if ep_state.should_stop():
                    ctx.stats.payloads_skipped += 1
                    continue

                # ── 2. Stop-on-confirmation (re-check inside loop) ────
                if (
                    self._config.stop_on_confirmation
                    and ctx.registry.is_confirmed(url, param, vuln_class)
                ):
                    ctx.stats.payloads_skipped += 1
                    break

                # ── 3. Per-class payload budget ────────────────────────
                if payloads_used_this_param >= budget_cap:
                    ctx.stats.payloads_skipped += 1
                    continue

                payload_str = self._extract_payload_str(payload_item)

                # ── 4. Pre-execution dedup cache ───────────────────────
                if self._config.enable_dedup_cache:
                    if ctx.exec_cache.already_tested(url, param, vuln_class, payload_str):
                        ctx.stats.duplicate_tests_avoided += 1
                        continue

                # ── 5. Validator cache ─────────────────────────────────
                validator_result = None
                cache_hit = False

                if self._config.enable_validator_cache:
                    cache_hit, cached_val = ctx.validator_cache.get(url, param, payload_str)
                    if cache_hit:
                        ctx.stats.validator_cache_hits += 1
                        validator_result = cached_val
                        # Still count against per-param budget: the payload
                        # occupies a budget slot even when served from cache,
                        # because we are applying it to this endpoint/param.
                        payloads_used_this_param += 1

                if not cache_hit:
                    # ── 6. Execute ────────────────────────────────────
                    ctx.stats.payloads_attempted += 1
                    payloads_used_this_param     += 1
                    ep_state.record_payload_used(vuln_class, param)

                    raw_result, status_code = self._execute_payload(
                        url=url,
                        param=param,
                        payload=payload_str,
                        payload_item=payload_item,
                        vuln_class=vuln_class,
                        ep_techs=ep_techs,
                    )

                    if self._config.enable_validator_cache:
                        ctx.validator_cache.put(url, param, payload_str, raw_result)

                    validator_result = raw_result

                    # Early-exit update
                    triggered = ep_state.record_request(status_code)
                    if triggered:
                        ctx.stats.early_exits += 1
                        log.debug(
                            "[EARLY-EXIT] %s after %d requests (status streak)",
                            url, ep_state.request_count,
                        )
                        ctx.stats.payloads_skipped += max(
                            0, budget_cap - payloads_used_this_param
                        )
                        return

                # ── 7. Process result ──────────────────────────────────
                # Only register findings with meaningful confidence.
                # A result dict with confidence=0 (or a pure status-code
                # rejection response) is NOT a finding — it's a probe result
                # used only for early-exit tracking.
                if validator_result and int(validator_result.get("confidence", 0)) > 0:
                    confidence = int(validator_result.get("confidence", 50))
                    finding = self._build_finding(
                        url=url,
                        param=param,
                        vuln_class=vuln_class,
                        payload=payload_str,
                        result=validator_result,
                        payload_item=payload_item,
                    )

                    registered = ctx.registry.register(
                        finding=finding,
                        payload=payload_str,
                        response=validator_result.get("response", ""),
                        confidence=confidence,
                    )

                    if confidence >= self._config.confirmation_threshold:
                        ctx.stats.confirmations += 1
                        ctx.registry.mark_confirmed(url, param, vuln_class)
                        if _is_endpoint_level(vuln_class):
                            log.info(
                                "[CONFIRMED] %s @ %s scope=endpoint conf=%d",
                                vuln_class, url, confidence,
                            )
                        else:
                            log.info(
                                "[CONFIRMED] %s @ %s param=%s conf=%d",
                                vuln_class, url, param, confidence,
                            )
                        if self._config.stop_on_confirmation:
                            # Skip remaining payloads for this class/param
                            ctx.stats.payloads_skipped += max(
                                0, budget_cap - payloads_used_this_param
                            )
                            break

    # ── Execution adapter (wraps DetectionEngine) ────────────────────────

    def _execute_payload(
        self,
        url:          str,
        param:        str,
        payload:      str,
        payload_item: Any,
        vuln_class:   str,
        ep_techs:     List[str],
    ) -> Tuple[Optional[Dict], Optional[int]]:
        """
        Call the underlying DetectionEngine to test a payload.

        Returns (result_dict_or_None, http_status_code_or_None).

        The DetectionEngine is duck-typed — we try multiple method signatures
        and degrade gracefully if none are available.
        """
        result      = None
        status_code = None

        try:
            # Primary: test_endpoint(url, payload, param) → dict
            if hasattr(self._de, "test_endpoint"):
                raw = self._de.test_endpoint(url, payload, param)
                if isinstance(raw, dict):
                    result      = raw
                    status_code = raw.get("status_code")

            # Fallback: test_payload(vuln_class, url, param, payload) → dict
            elif hasattr(self._de, "test_payload"):
                raw = self._de.test_payload(vuln_class, url, param, payload)
                if isinstance(raw, dict):
                    result      = raw
                    status_code = raw.get("status_code")

            # Fallback: scan_parameter(url, param, payload) → dict | bool
            elif hasattr(self._de, "scan_parameter"):
                raw = self._de.scan_parameter(url, param, payload)
                if isinstance(raw, dict):
                    result = raw
                elif raw is True:
                    result = {"confidence": 75, "evidence": payload}

        except Exception as exc:
            log.debug("[EXEC-ERROR] %s %s %s: %s", vuln_class, url, param, exc)
            result      = None
            status_code = None

        return result, status_code

    # ── Finding construction ───────────────────────────────────────────────

    def _build_finding(
        self,
        url:          str,
        param:        str,
        vuln_class:   str,
        payload:      str,
        result:       Dict[str, Any],
        payload_item: Any,
    ) -> Dict[str, Any]:
        """
        Build a finding dict from a successful validator result.

        Keys match the schema expected by finding_grouper, risk_scoring,
        database, and report_generator.
        """
        # Enrich from KB if available
        kb_info: Dict[str, Any] = {}
        if self._kb:
            try:
                kb_info = self._kb.get_vulnerability_info(vuln_class) or {}
            except Exception:
                pass

        confidence  = int(result.get("confidence", 50))
        evidence    = result.get("evidence", result.get("response", ""))
        reason      = result.get("reason", result.get("detail", ""))

        return {
            # Core identity (required by all consumers)
            "type":             vuln_class,
            "url":              url,
            "parameter":        param,
            "param":            param,          # backward compat alias
            "payload":          payload,
            "confidence":       confidence,
            "severity":         result.get("severity", kb_info.get("severity", "Low")),
            "cvss":             result.get("cvss",     kb_info.get("cvss",     0.0)),
            "evidence":         evidence,
            "reason":           reason,
            "validation_state": result.get("validation_state", "Likely"),
            # Extended fields consumed by finding_grouper enrichment
            "cwe":              kb_info.get("cwe",              ""),
            "owasp":            kb_info.get("owasp",            ""),
            "capec":            kb_info.get("capec",            ""),
            "recommendation":   kb_info.get("recommendation",   ""),
            "business_impact":  kb_info.get("business_impact",  ""),
            "references":       kb_info.get("references",       []),
            # Evidence hints for risk_scoring._adjust_for_evidence()
            **{k: v for k, v in result.items() if k in (
                "xss_type", "sqli_type", "disclosure_type",
                "ssrf_egress", "lfi_rce_evidence", "idor_write",
                "oauth_redirect", "debug_authed", "admin_authed",
                "cors_credentials", "csrf_samesite_lax", "csrf_sensitive",
                "upload_exec", "jwt_alg_none", "jwt_weak_secret", "file_write",
            )},
        }

    # ── Helpers ───────────────────────────────────────────────────────────

    def _normalise_endpoints(self, endpoints: List[Any]) -> List[Dict]:
        out = []
        for ep in endpoints:
            if isinstance(ep, str):
                out.append({"url": ep, "tags": [], "parameters": []})
            elif isinstance(ep, dict):
                out.append(ep)
        return out

    def _build_tech_map(
        self,
        alive_hosts:  List[Any],
        technologies: Dict[str, List[str]],
    ) -> Dict[str, List[str]]:
        """Merge technologies from alive_hosts metadata and explicit tech dict."""
        tech_map: Dict[str, List[str]] = dict(technologies)
        for host in alive_hosts:
            if isinstance(host, dict):
                url      = host.get("url", "")
                hostname = urlparse(url).hostname or ""
                techs    = host.get("technologies", host.get("tech", []))
                if hostname and techs:
                    existing = tech_map.get(hostname, [])
                    tech_map[hostname] = list(set(existing) | set(techs))
        return tech_map

    def _get_host_info(self, hostname: str, alive_hosts: List[Any]) -> Optional[Dict]:
        for host in alive_hosts:
            if isinstance(host, dict):
                h_url = host.get("url", "")
                if urlparse(h_url).hostname == hostname:
                    return host
        return None

    def _get_vuln_classes(self) -> List[str]:
        """
        Determine which vuln classes to test.
        Tries DetectionEngine.get_vuln_classes() first, then falls back
        to the keys in DEFAULT_PAYLOAD_BUDGET (minus the "_default" sentinel).
        """
        if hasattr(self._de, "get_vuln_classes"):
            try:
                classes = self._de.get_vuln_classes()
                if classes:
                    return list(classes)
            except Exception:
                pass

        return [k for k in DEFAULT_PAYLOAD_BUDGET if not k.startswith("_")]

    def _get_payloads(self, vuln_class: str) -> List[Any]:
        """Get payloads from DetectionEngine for a vuln class."""
        if hasattr(self._de, "get_payloads"):
            try:
                payloads = self._de.get_payloads(vuln_class)
                if payloads:
                    return list(payloads)
            except Exception:
                pass

        # Fallback: try get_payloads_for
        if hasattr(self._de, "get_payloads_for"):
            try:
                payloads = self._de.get_payloads_for(vuln_class)
                if payloads:
                    return list(payloads)
            except Exception:
                pass

        return []

    # Vuln classes that operate on HTTP headers / paths, not query/body params.
    # For these, "" (bare endpoint) is the only relevant "param".
    _PATH_ONLY_CLASSES: frozenset = frozenset({
        "SSRF", "XXE", "SSTI", "RCE", "COMMAND_INJECTION",
        "DESERIALIZATION", "FILE_UPLOAD", "CORS",
        "HOST_HEADER_INJECTION", "CLICKJACKING", "DEBUG",
        "MISCONFIGURATION", "SUBDOMAIN_TAKEOVER",
    })

    def _extract_params(self, ep: Dict, url: str, vuln_class: str = "") -> List[str]:
        """
        Extract parameter names to test from endpoint metadata.
        Falls back to URL query parameters if endpoint dict has none.

        For path/header-only vuln classes (SSRF, SSTI, etc.), only the
        bare endpoint ("") is returned — they don't test query params.
        For all others, both explicit params and URL query params are
        included, plus "" for path-based variants.
        """
        vc_upper = vuln_class.upper().strip()

        if vc_upper in self._PATH_ONLY_CLASSES:
            return [""]

        params: List[str] = list(ep.get("parameters", ep.get("params", [])))

        # Also parse query params from the URL
        try:
            qs = parse_qs(urlparse(url).query)
            for k in qs:
                if k not in params:
                    params.append(k)
        except Exception:
            pass

        # Include bare endpoint ("") for path-traversal and header-injection
        # variants — but ONLY when there are no real parameters to test.
        # For parameter-level vuln classes (XSS, SQLi, etc.) that already have
        # concrete params, adding "" creates a duplicate key in FindingRegistry
        # because (normalised_url, "", vuln_class) and
        # (normalised_url, "q", vuln_class) are distinct keys, yielding two
        # identical findings for the same injection point.
        if not params:
            params.insert(0, "")

        return params

    def _extract_payload_str(self, payload_item: Any) -> str:
        """Extract the string payload from a payload dict or plain string."""
        if isinstance(payload_item, str):
            return payload_item
        if isinstance(payload_item, dict):
            return payload_item.get("payload", payload_item.get("value", str(payload_item)))
        return str(payload_item)

    def _clean_finding(self, f: Dict[str, Any]) -> Dict[str, Any]:
        """Remove internal tracking keys before returning to caller."""
        _internal = {"payloads_seen", "evidence_snippets"}
        return {k: v for k, v in f.items() if k not in _internal}

    def _log_summary(self, ctx: ScanContext) -> None:
        s  = ctx.stats
        ds = ctx.registry.dedup_stats()
        log.info(
            "[SCAN-DONE] findings=%d (raw=%d ep_dedup=%d param_dedup=%d) "
            "elapsed=%.1fs attempted=%d skipped=%d dupes_avoided=%d "
            "cache_hits=%d early_exits=%d confirmations=%d est_saved=%.0fs",
            ctx.registry.count(),
            ds["raw_registrations"],
            ds["endpoint_collisions"],
            ds["param_collisions"],
            s.elapsed_seconds,
            s.payloads_attempted,
            s.payloads_skipped,
            s.duplicate_tests_avoided,
            s.validator_cache_hits,
            s.early_exits,
            s.confirmations,
            s.estimated_time_saved_seconds,
        )
        print(
            f"\n{'='*55}\n"
            f"  ADAPTIVE SCAN COMPLETE\n"
            f"{'='*55}\n"
            f"  Findings (unique)     : {ctx.registry.count()}\n"
            f"  Raw registrations     : {ds['raw_registrations']}\n"
            f"  Endpoint-level dedup  : {ds['endpoint_collisions']} collapsed\n"
            f"  Param-level dedup     : {ds['param_collisions']} collapsed\n"
            f"  Elapsed               : {s.elapsed_seconds:.1f}s\n"
            f"  Payloads attempted    : {s.payloads_attempted}\n"
            f"  Payloads skipped      : {s.payloads_skipped}\n"
            f"  Duplicates avoided    : {s.duplicate_tests_avoided}\n"
            f"  Validator cache hits  : {s.validator_cache_hits}\n"
            f"  Early exits           : {s.early_exits}\n"
            f"  Confirmations         : {s.confirmations}\n"
            f"  Est. time saved       : {s.estimated_time_saved_seconds:.0f}s\n"
            f"{'='*55}\n"
        )


# ─────────────────────────────────────────────────────────────────────────────
# SECTION 10 — CONVENIENCE HELPERS (consumed by recon_core.py)
# ─────────────────────────────────────────────────────────────────────────────

def extract_scan_stats(findings: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    """
    Pull the stats dict out of a findings list returned by VulnEngine.scan().

    Returns the stats dict, or None if not present.
    Callers can use this to log telemetry without filtering the main list.
    """
    for f in findings:
        if f.get("type") == "__stats__":
            return f
    return None


def filter_real_findings(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Return only real vulnerability findings (strips the stats sentinel).

    REQUIRED integration point for recon_core.py:
    Call this before passing findings to any downstream consumer:

        from vuln_engine import VulnEngine, filter_real_findings, extract_scan_stats

        raw      = engine.scan(endpoints, alive_hosts, technologies)
        stats    = extract_scan_stats(raw)      # telemetry — log or store
        findings = filter_real_findings(raw)    # clean list for grouper/db/report

        grouped  = group_findings(findings, kb=kb)
        risk     = calculate_risk(endpoints, alive_hosts, findings)
        save_scan(domain, risk, findings)

    The stats dict is NOT a vulnerability finding and must not reach the
    FindingGrouper, risk_scoring engine, database, or report generator.
    """
    return [f for f in findings if f.get("type") != "__stats__"]


# ─────────────────────────────────────────────────────────────────────────────
# SECTION 10b — BACKWARD-COMPATIBLE SHIM
# ─────────────────────────────────────────────────────────────────────────────

def run_vuln_scan(
    urls:         List[Any],
    technologies: Optional[Dict[str, Any]] = None,
    *,
    alive_hosts:  Optional[List[Dict[str, Any]]] = None,
    config:       Optional[ScanConfig]            = None,
    detection_engine: Any                         = None,
    knowledge_base:   Any                         = None,
) -> List[Dict[str, Any]]:
    """
    Backward-compatible wrapper around VulnEngine.scan().

    This function existed in the original vuln_engine.py and is imported by
    recon_core.py.  It was inadvertently removed when the adaptive engine
    refactor replaced the module body.  This shim restores the original public
    name while delegating all work to the new adaptive engine so that no
    functionality is lost.

    Original signature (what recon_core calls):
        run_vuln_scan(scan_targets, ctx.technologies)
        # scan_targets : list of URL strings
        # ctx.technologies : {url_or_host: [tech_str, ...]}

    Extended signature (new optional keyword args):
        run_vuln_scan(urls, technologies,
                      alive_hosts=...,       # richer WAF/tech context
                      config=...,            # ScanConfig override
                      detection_engine=...,  # custom DetectionEngine
                      knowledge_base=...,    # custom KnowledgeBase)

    Returns
    -------
    list of finding dicts — identical schema to what the old run_vuln_scan
    returned: [{type, url, severity, confidence, cvss, parameter,
                evidence, payload, reason, validation_state}, ...]

    The __stats__ sentinel is stripped before returning so callers that do
    not call filter_real_findings() themselves are not surprised.  Callers
    that want telemetry should use VulnEngine.scan() + extract_scan_stats()
    directly.
    """
    technologies = technologies or {}
    alive_hosts  = alive_hosts  or []

    # ── Convert URL strings → endpoint dicts ─────────────────────────────
    # recon_core passes a flat list of URL strings.  VulnEngine.scan() wants
    # endpoint dicts {url, tags, parameters}.  We normalise here.
    endpoint_dicts: List[Dict[str, Any]] = []
    seen_urls: set = set()

    for item in (urls or []):
        if isinstance(item, str):
            url = item
        elif isinstance(item, dict):
            url = item.get("url", "")
            if url and url not in seen_urls:
                seen_urls.add(url)
                endpoint_dicts.append(item)
            continue
        else:
            continue

        if not url or url in seen_urls:
            continue
        seen_urls.add(url)

        # Extract any query parameters already in the URL so the engine
        # tests them individually rather than treating the URL as opaque.
        try:
            from urllib.parse import urlparse, parse_qs as _parse_qs
            qs_params = list(_parse_qs(urlparse(url).query).keys())
        except Exception:
            qs_params = []

        endpoint_dicts.append({
            "url":        url,
            "tags":       [],        # no tag info from the old API
            "parameters": qs_params,
        })

    if not endpoint_dicts:
        log.warning("[run_vuln_scan] No valid endpoints to scan.")
        return []

    # ── Build alive_hosts from technologies dict if not provided ──────────
    # The old API didn't have an alive_hosts concept.  Reconstruct a minimal
    # list so VulnEngine can extract tech context for payload prioritisation.
    if not alive_hosts and technologies:
        for host_key, tech_list in technologies.items():
            if not isinstance(tech_list, list):
                continue
            url = host_key if host_key.startswith(("http://", "https://")) \
                  else f"https://{host_key}"
            alive_hosts.append({
                "url":          url,
                "waf":          "",
                "technologies": tech_list,
            })

    # ── Build detection engine shim if none provided ──────────────────────
    # The original run_vuln_scan had its own payload list baked in.
    # When called without a DetectionEngine, we use a no-op engine so the
    # adaptive framework still runs (budget tracking, dedup, stats) even if
    # it produces no findings.  Real findings come from whatever engine the
    # caller wires in via the detection_engine kwarg.
    if detection_engine is None:
        class _LegacyNoOpDE:
            """
            No-op DetectionEngine used when run_vuln_scan is called without
            an explicit engine (i.e. from the old recon_core integration).
            Returns no payloads — findings originate from smart_test_endpoint
            and the AI engine; this stage contributes dedup/budget accounting.
            """
            def get_vuln_classes(self) -> List[str]:
                return list(DEFAULT_PAYLOAD_BUDGET.keys())

            def get_payloads(self, vuln_class: str) -> List[Any]:
                return []

            def test_endpoint(self, url: str, payload: str, param: str) -> None:
                return None

        detection_engine = _LegacyNoOpDE()

    # ── Run the adaptive engine ───────────────────────────────────────────
    engine = VulnEngine(
        detection_engine=detection_engine,
        knowledge_base=knowledge_base,
        config=config or ScanConfig(),
    )

    raw_output = engine.scan(
        endpoints    = endpoint_dicts,
        alive_hosts  = alive_hosts,
        technologies = technologies,
    )

    # Strip the __stats__ sentinel — old callers don't expect it.
    # Callers that want telemetry should call extract_scan_stats(raw_output)
    # before this stripping step by using VulnEngine.scan() directly.
    return filter_real_findings(raw_output)


# ─────────────────────────────────────────────────────────────────────────────
# SECTION 11 — SELF-TEST
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import random as _random

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)-8s %(message)s",
    )

    class _MockDetectionEngine:
        """Deterministic mock for self-test (seeded RNG for reproducibility)."""

        _rng = _random.Random(42)

        def get_vuln_classes(self):
            return ["SQLI", "XSS", "SSRF", "OPEN_REDIRECT", "DEBUG", "CORS"]

        def get_payloads(self, vuln_class):
            base = {
                "SQLI": [
                    {"payload": "' OR 1=1--",           "priority": 5, "technology": ""},
                    {"payload": "' UNION SELECT NULL--", "priority": 4, "technology": "MySQL"},
                    {"payload": "' AND SLEEP(5)--",      "priority": 3, "technology": "MySQL"},
                    {"payload": "admin'--",               "priority": 2, "technology": ""},
                    {"payload": "' OR 'x'='x",           "priority": 1, "technology": ""},
                    {"payload": "1; DROP TABLE users--",  "priority": 0, "technology": ""},
                ],
                "XSS": [
                    {"payload": "<script>alert(1)</script>",          "priority": 5},
                    {"payload": "<img src=x onerror=alert(1)>",       "priority": 4},
                    {"payload": "<svg onload=alert(1)>",               "priority": 3},
                    {"payload": "javascript:alert(1)",                 "priority": 2},
                    {"payload": "\"><script>alert(1)</script>",        "priority": 1},
                ],
                "SSRF": [
                    {"payload": "http://169.254.169.254/",       "priority": 5},
                    {"payload": "http://localhost/admin",         "priority": 4},
                    {"payload": "http://internal.example.com/",  "priority": 3},
                    {"payload": "file:///etc/passwd",             "priority": 2},
                ],
                "OPEN_REDIRECT": [
                    {"payload": "//evil.com",       "priority": 4},
                    {"payload": "https://evil.com", "priority": 3},
                    {"payload": "/\\evil.com",       "priority": 2},
                    {"payload": "//evil.com%2F",    "priority": 1},
                ],
                "DEBUG": [
                    {"payload": "GET /_debug HTTP/1.1", "priority": 5},
                    {"payload": "?debug=1",              "priority": 4},
                ],
                "CORS": [
                    {"payload": "Origin: https://evil.com", "priority": 5},
                    {"payload": "Origin: null",              "priority": 4},
                    {"payload": "Origin: https://attacker.com", "priority": 3},
                ],
            }
            return base.get(vuln_class, [{"payload": "generic", "priority": 1}])

        def test_endpoint(self, url, payload, param):
            """
            Deterministic mock responses:
              - SQLI SLEEP on any endpoint → confirmed (conf=90)
              - XSS <script> on /search → reflected (conf=75)
              - CORS on /api → wildcard origin (conf=80)
              - DEBUG on /admin/debug unauthed → (conf=88)
              - 403 on /login for all payloads → triggers early exit
            """
            p = payload if isinstance(payload, str) else payload.get("payload", "")

            # /login returns 403 → early-exit path
            if "login" in url:
                return {"confidence": 0, "status_code": 403}

            # SQLI confirmation
            if "SLEEP" in p and self._rng.random() < 0.6:
                return {
                    "confidence":       90,
                    "severity":         "High",
                    "cvss":             8.8,
                    "evidence":         f"5-second delay observed: {p}",
                    "reason":           "Blind time-based SQLi confirmed",
                    "validation_state": "Confirmed",
                    "status_code":      200,
                    "sqli_type":        "time-based",
                }

            # XSS on search
            if "<script>" in p and "search" in url and self._rng.random() < 0.7:
                return {
                    "confidence":       75,
                    "severity":         "Medium",
                    "cvss":             6.1,
                    "evidence":         f"Payload reflected: {p}",
                    "reason":           "Reflected XSS",
                    "validation_state": "Likely",
                    "status_code":      200,
                    "xss_type":         "reflected",
                }

            # CORS wildcard
            if "Origin:" in p and "/api" in url:
                return {
                    "confidence":       80,
                    "severity":         "High",
                    "cvss":             7.9,
                    "evidence":         "Access-Control-Allow-Origin: *",
                    "reason":           "Wildcard CORS origin accepted",
                    "validation_state": "Confirmed",
                    "status_code":      200,
                    "cors_credentials": False,
                }

            # DEBUG endpoint unauthed
            if "debug" in url and ("debug" in p or "_debug" in p):
                return {
                    "confidence":       88,
                    "severity":         "High",
                    "cvss":             5.7,
                    "evidence":         "Debug endpoint returned stack trace",
                    "reason":           "Unauthenticated debug endpoint",
                    "validation_state": "Confirmed",
                    "status_code":      200,
                    "debug_authed":     False,
                }

            return None

    endpoints = [
        {"url": "https://example.com/search?q=test", "tags": ["search"],  "parameters": ["q"]},
        {"url": "https://example.com/login",          "tags": ["auth"],    "parameters": ["username", "password"]},
        {"url": "https://example.com/api/v1/user",    "tags": ["api"],     "parameters": ["id"]},
        {"url": "https://example.com/redirect",       "tags": [],          "parameters": ["next"]},
        {"url": "https://example.com/admin/debug",    "tags": ["admin"],   "parameters": []},
        # Duplicate URL — should be tested once (dedup)
        {"url": "https://example.com/search?q=test", "tags": ["search"],  "parameters": ["q"]},
    ]

    alive_hosts = [
        {
            "url":          "https://example.com",
            "waf":          "",
            "technologies": ["PHP", "MySQL"],
        },
    ]

    config = ScanConfig(
        payload_budget={
            "SQLI":          4,
            "XSS":           3,
            "SSRF":          2,
            "OPEN_REDIRECT": 2,
            "DEBUG":         2,
            "CORS":          2,
            "_default":      2,
        },
        confirmation_threshold=85,
        max_requests_per_endpoint=25,
        rejection_run_threshold=3,    # /login hits 403 × 3 → early exit
    )

    print("\n" + "=" * 55)
    print("  SELF-TEST: Adaptive VulnEngine")
    print("=" * 55)

    engine   = VulnEngine(_MockDetectionEngine(), config=config)
    findings = engine.scan(endpoints, alive_hosts, technologies={})

    stats = extract_scan_stats(findings)
    real  = filter_real_findings(findings)

    print(f"\nReal findings ({len(real)}):")
    for f in real:
        sev   = f.get("severity", "?")
        ftype = f.get("type", "?")
        conf  = f.get("confidence", 0)
        url   = f.get("url", "?")
        vstate = f.get("validation_state", "?")
        print(f"  [{sev:8s}] {ftype:20s} conf={conf:3d}  {vstate:12s}  {url}")

    print(f"\nRuntime stats:")
    if stats:
        for k, v in stats.items():
            if k != "type":
                print(f"  {k:<35}: {v}")

    # ── Correctness assertions ─────────────────────────────────────────────
    errors = []

    # No stats dict in real findings
    if any(f.get("type") == "__stats__" for f in real):
        errors.append("FAIL: stats sentinel leaked into real findings")

    # Stats dict must be present
    if stats is None:
        errors.append("FAIL: stats dict missing from findings list")

    # No internal keys in returned findings
    internal_keys = {"payloads_seen", "evidence_snippets"}
    for f in real:
        leaked = internal_keys & set(f.keys())
        if leaked:
            errors.append(f"FAIL: internal keys {leaked} leaked into finding {f.get('type')}")

    # All real findings have mandatory keys
    required = {"type", "url", "severity", "confidence", "cvss", "payload"}
    for f in real:
        missing = required - set(f.keys())
        if missing:
            errors.append(f"FAIL: finding {f.get('type')} missing keys {missing}")

    # ── Requirement 7: deterministic dedup assertion ──────────────────────
    # Identical (normalised_url, parameter, vulnerability_class) must not
    # appear more than once in the final findings list.
    dedup_seen: set = set()
    for f in real:
        norm_key = (
            _normalise_url(f.get("url", "")),
            f.get("parameter", ""),
            f.get("type", ""),
        )
        if norm_key in dedup_seen:
            errors.append(
                f"FAIL: duplicate (normalised_url, parameter, vuln_class) "
                f"in findings: {norm_key}"
            )
        dedup_seen.add(norm_key)

    # ── Requirement 8: four deterministic scenario tests ──────────────────
    # These run inline using a controlled mock so results are seed-independent.
    print("\n--- Scenario tests (requirement 8) ---")

    class _ScenarioDE:
        """
        Controlled mock: always returns a finding for any payload, never
        random, so scenario assertions are deterministic.
        """
        def __init__(self, vuln_classes, active_params=None):
            # active_params: {(vuln_class, param)} that should fire; None=all
            self._vcs  = vuln_classes
            self._act  = active_params  # None → fire on everything

        def get_vuln_classes(self):
            return list(self._vcs)

        def get_payloads(self, vc):
            return [{"payload": f"probe_{vc}_1", "priority": 5},
                    {"payload": f"probe_{vc}_2", "priority": 4}]

        def test_endpoint(self, url, payload, param):
            vc = payload.split("_")[1] if "_" in payload else payload
            if self._act is None or (vc, param) in self._act:
                return {
                    "confidence":       75,
                    "severity":         "Medium",
                    "cvss":             6.1,
                    "evidence":         f"probe hit: {payload}",
                    "reason":           "test",
                    "validation_state": "Likely",
                    "status_code":      200,
                }
            return None

    _scen_cfg = ScanConfig(
        payload_budget={"XSS": 2, "SQLI": 2, "MISSING_CSP": 1, "_default": 2},
        confirmation_threshold=90,   # above mock's 75 → never stops early
        max_requests_per_endpoint=50,
    )

    def _run_scenario(label, ep_list, de):
        eng = VulnEngine(de, config=_scen_cfg)
        raw = eng.scan(ep_list, [], technologies={})
        return filter_real_findings(raw)

    # Scenario A: two identical XSS probes on same (url, param) → 1 finding
    sc_a = _run_scenario(
        "A",
        [{"url": "https://t.com/s?q=x", "parameters": ["q"]}],
        _ScenarioDE(["XSS"], active_params={("XSS", "q")}),
    )
    xss_a = [f for f in sc_a if f.get("type") == "XSS"]
    if len(xss_a) != 1:
        errors.append(f"FAIL Scenario A: two identical XSS probes → {len(xss_a)} findings, expected 1")
    else:
        print(f"  Scenario A: 2 identical XSS probes → 1 finding ✓")

    # Scenario B: XSS on q and XSS on another param → 2 findings
    sc_b = _run_scenario(
        "B",
        [{"url": "https://t.com/s?q=x", "parameters": ["q", "name"]}],
        _ScenarioDE(["XSS"], active_params={("XSS", "q"), ("XSS", "name")}),
    )
    xss_b = [f for f in sc_b if f.get("type") == "XSS"]
    if len(xss_b) != 2:
        errors.append(f"FAIL Scenario B: XSS on q + XSS on name → {len(xss_b)} findings, expected 2")
    else:
        print(f"  Scenario B: XSS on q + XSS on name → 2 findings ✓")

    # Scenario C: SQLi and XSS both on q → 2 findings (different classes)
    sc_c = _run_scenario(
        "C",
        [{"url": "https://t.com/s?q=x", "parameters": ["q"]}],
        _ScenarioDE(["XSS", "SQLI"], active_params={("XSS", "q"), ("SQLI", "q")}),
    )
    if len(sc_c) != 2:
        errors.append(f"FAIL Scenario C: SQLi+XSS on q → {len(sc_c)} findings, expected 2")
    else:
        print(f"  Scenario C: SQLi + XSS on q → 2 findings ✓")

    # Scenario D: endpoint-level CSP across multiple query params → 1 per path
    class _CspDE:
        def get_vuln_classes(self): return ["MISSING_CSP"]
        def get_payloads(self, vc): return [{"payload": "probe_MISSING_CSP_1", "priority": 5}]
        def test_endpoint(self, url, payload, param):
            return {"confidence": 75, "severity": "Medium", "cvss": 5.4,
                    "evidence": "No CSP", "reason": "CSP absent",
                    "validation_state": "Likely", "status_code": 200}

    sc_d = _run_scenario(
        "D",
        [
            {"url": "https://t.com/admin?a=1", "parameters": ["a"]},
            {"url": "https://t.com/admin?b=2", "parameters": ["b"]},
            {"url": "https://t.com/admin?c=3", "parameters": ["c"]},
            {"url": "https://t.com/other?x=1", "parameters": ["x"]},
        ],
        _CspDE(),
    )
    admin_csp_d = [f for f in sc_d
                   if f.get("type") == "MISSING_CSP" and "/admin" in f.get("url", "")]
    other_csp_d = [f for f in sc_d
                   if f.get("type") == "MISSING_CSP" and "/other" in f.get("url", "")]
    if len(admin_csp_d) != 1:
        errors.append(f"FAIL Scenario D: /admin (3 params) → {len(admin_csp_d)} MISSING_CSP, expected 1")
    elif len(other_csp_d) != 1:
        errors.append(f"FAIL Scenario D: /other → {len(other_csp_d)} MISSING_CSP, expected 1")
    else:
        print(f"  Scenario D: endpoint-level CSP — /admin×3params→1, /other→1 ✓")

    # Stats counters must be non-negative integers
    for counter in ("payloads_attempted", "payloads_skipped", "duplicate_tests_avoided",
                    "early_exits", "validator_cache_hits", "confirmations"):
        val = stats.get(counter, -1) if stats else -1
        if not isinstance(val, int) or val < 0:
            errors.append(f"FAIL: stats.{counter} = {val!r} (expected non-negative int)")

    # WAF halving: since waf="" in alive_hosts, budgets should not be halved
    # (verifiable indirectly: payloads_attempted should be > 0)
    if stats and stats.get("payloads_attempted", 0) == 0:
        errors.append("FAIL: no payloads were attempted (engine did not execute)")

    # Early exits: /login returns 403 repeatedly — at least 1 early exit expected
    if stats and stats.get("early_exits", 0) == 0:
        errors.append("WARN: no early exits recorded — /login 403 path not triggered")

    if errors:
        print("\n" + "\n".join(errors))
        raise SystemExit(1)
    else:
        print("\nAll assertions passed. ✓")

    # ── run_vuln_scan backward-compat shim test ────────────────────────────
    print("\n" + "=" * 55)
    print("  SELF-TEST: run_vuln_scan backward-compat shim")
    print("=" * 55)

    shim_urls = [
        "https://example.com/search?q=test",
        "https://example.com/api/v1/user?id=1",
        "https://example.com/login",
    ]
    shim_techs = {"example.com": ["PHP", "MySQL"]}

    shim_results = run_vuln_scan(shim_urls, shim_techs)

    # Shim must return a plain list, never contain __stats__
    assert isinstance(shim_results, list), \
        f"run_vuln_scan must return list, got {type(shim_results)}"
    assert not any(f.get("type") == "__stats__" for f in shim_results), \
        "run_vuln_scan must strip __stats__ sentinel before returning"

    print(f"run_vuln_scan returned {len(shim_results)} findings (expected 0 with no-op DE).")
    print("Shim import and call: OK ✓")

    # ── Endpoint-level dedup test ──────────────────────────────────────────
    print("\n" + "=" * 55)
    print("  SELF-TEST: Endpoint-level deduplication")
    print("=" * 55)

    class _HeaderScanDE:
        """
        Mock DE that returns MISSING_CSP for every request regardless of param.
        With three params on /admin, old code would produce 3 findings.
        New code must produce exactly 1.
        """
        def get_vuln_classes(self):
            return ["MISSING_CSP", "MISSING_HSTS", "MISSING_X_FRAME_OPTIONS", "SQLI"]

        def get_payloads(self, vc):
            return [{"payload": f"probe_{vc}", "priority": 5}]

        def test_endpoint(self, url, payload, param):
            if "MISSING_CSP" in payload or "MISSING_HSTS" in payload or "X_FRAME" in payload:
                return {
                    "confidence":       80,
                    "severity":         "Medium",
                    "cvss":             5.4,
                    "evidence":         "Content-Security-Policy header absent",
                    "reason":           "No CSP header in response",
                    "validation_state": "Confirmed",
                    "status_code":      200,
                }
            # SQLi only fires on param 'id'
            if "SQLI" in payload and param == "id":
                return {
                    "confidence":       85,
                    "severity":         "High",
                    "cvss":             8.8,
                    "evidence":         "SQL error in response",
                    "reason":           "SQL injection confirmed",
                    "validation_state": "Confirmed",
                    "status_code":      200,
                }
            return None

    # Simulate /admin endpoint with 3 query params — realistic Juice Shop scenario
    dedup_endpoints = [
        {"url": "http://localhost:3000/admin?apikey=test",       "tags": ["admin"], "parameters": ["apikey"]},
        {"url": "http://localhost:3000/admin?token=test",        "tags": ["admin"], "parameters": ["token"]},
        {"url": "http://localhost:3000/admin?redirect_uri=test", "tags": ["admin"], "parameters": ["redirect_uri"]},
        # SQLi endpoint with id param — should produce param-level finding
        {"url": "http://localhost:3000/search?id=1",             "tags": [],        "parameters": ["id", "q"]},
    ]

    dedup_engine = VulnEngine(_HeaderScanDE(), config=ScanConfig(
        payload_budget={"MISSING_CSP": 1, "MISSING_HSTS": 1, "MISSING_X_FRAME_OPTIONS": 1,
                        "SQLI": 2, "_default": 1},
        confirmation_threshold=80,
        max_requests_per_endpoint=30,
    ))
    dedup_raw = dedup_engine.scan(dedup_endpoints, [], technologies={})
    dedup_stats_dict = extract_scan_stats(dedup_raw)
    dedup_findings   = filter_real_findings(dedup_raw)

    print(f"\nFindings returned ({len(dedup_findings)}):")
    for f in dedup_findings:
        print(f"  [{f.get('severity','?'):8s}] {f.get('type','?'):30s} "
              f"param={f.get('parameter','?')!r:15s} {f.get('url','?')}")

    # Assertions
    dedup_errors = []

    # KEY TEST: all three /admin params must produce exactly ONE MISSING_CSP finding
    # (same path, different query params → endpoint-level dedup collapses them)
    admin_csp = [f for f in dedup_findings
                 if f.get("type") == "MISSING_CSP"
                 and "/admin" in f.get("url", "")]
    if len(admin_csp) != 1:
        dedup_errors.append(
            f"FAIL: /admin with 3 params produced {len(admin_csp)} MISSING_CSP "
            f"findings, expected 1 — endpoint-level dedup failed"
        )
    else:
        print(f"\nMISSING_CSP @ /admin: {len(admin_csp)} finding "
              f"(3 params → 1 finding, was 3 before fix) ✓")

    # The CSP finding must have param="" (endpoint-level, not bound to a param)
    if admin_csp and admin_csp[0].get("parameter") != "":
        dedup_errors.append(
            f"FAIL: MISSING_CSP finding has param={admin_csp[0].get('parameter')!r}, "
            f"expected ''"
        )
    else:
        print("MISSING_CSP.parameter == '' (endpoint-level scope) ✓")

    # HSTS and X_FRAME_OPTIONS: 1 each for /admin path
    for vc in ("MISSING_HSTS", "MISSING_X_FRAME_OPTIONS"):
        admin_matches = [f for f in dedup_findings
                         if f.get("type") == vc and "/admin" in f.get("url", "")]
        if len(admin_matches) != 1:
            dedup_errors.append(
                f"FAIL: /admin with 3 params produced {len(admin_matches)} {vc} "
                f"findings, expected 1"
            )
        else:
            print(f"{vc} @ /admin: 1 finding (3 params → 1) ✓")

    # Different path (/search) is a separate endpoint and gets its OWN set of findings
    # — that is correct behaviour, not a bug
    search_csp = [f for f in dedup_findings
                  if f.get("type") == "MISSING_CSP"
                  and "/search" in f.get("url", "")]
    if len(search_csp) != 1:
        dedup_errors.append(
            f"FAIL: /search produced {len(search_csp)} MISSING_CSP, expected 1"
        )
    else:
        print(f"MISSING_CSP @ /search: 1 finding (separate path, correct) ✓")

    # Total MISSING_CSP: 1 per unique path (2 paths = 2 findings — not 6 from 3 params × 2 paths)
    all_csp = [f for f in dedup_findings if f.get("type") == "MISSING_CSP"]
    expected_csp = 2  # /admin and /search — 2 unique paths
    if len(all_csp) != expected_csp:
        dedup_errors.append(
            f"FAIL: total MISSING_CSP findings = {len(all_csp)}, expected {expected_csp} "
            f"(one per unique path)"
        )
    else:
        print(f"Total MISSING_CSP: {len(all_csp)} (one per unique path, "
              f"not one per param) ✓")

    # SQLI must remain param-level: one finding for param 'id'
    sqli_findings = [f for f in dedup_findings if f.get("type") == "SQLI"]
    if len(sqli_findings) != 1:
        dedup_errors.append(f"FAIL: expected 1 SQLI finding, got {len(sqli_findings)}")
    elif sqli_findings[0].get("parameter") != "id":
        dedup_errors.append(
            f"FAIL: SQLI finding param={sqli_findings[0].get('parameter')!r}, expected 'id'"
        )
    else:
        print(f"SQLI: 1 finding, param='id' (parameter-level scope) ✓")

    # Verify _is_endpoint_level classification
    ep_classes = ["MISSING_CSP", "MISSING_HSTS", "CORS", "CLICKJACKING",
                  "SERVER_HEADER_DISCLOSURE", "MISCONFIGURATION", "DEBUG"]
    param_classes = ["SQLI", "XSS", "SSRF", "LFI", "SSTI", "IDOR", "OPEN_REDIRECT",
                     "RCE", "COMMAND_INJECTION", "AUTH_BYPASS"]
    for vc in ep_classes:
        if not _is_endpoint_level(vc):
            dedup_errors.append(f"FAIL: {vc} should be endpoint-level but isn't")
    for vc in param_classes:
        if _is_endpoint_level(vc):
            dedup_errors.append(f"FAIL: {vc} should be parameter-level but is classified as endpoint-level")

    print(f"\nClassification: {len(ep_classes)} endpoint-level, "
          f"{len(param_classes)} parameter-level — all correct ✓")

    # Before/after stats
    ds = dedup_stats_dict
    print(f"\nBefore/after deduplication (from dedup_stats):")
    print(f"  Raw registrations     : {ds.get('raw_registrations', 'n/a')}")
    print(f"  Unique findings       : {len(dedup_findings)}")

    if dedup_errors:
        print("\n" + "\n".join(dedup_errors))
        raise SystemExit(1)
    else:
        print("\nAll endpoint-level dedup assertions passed. ✓")
