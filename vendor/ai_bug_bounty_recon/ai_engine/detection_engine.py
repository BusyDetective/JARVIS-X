"""
detection_engine.py
====================

Commercial-grade Detection Engine for the AI Bug Bounty Recon &
Vulnerability Assessment Platform.

This module is the decision layer sitting directly on top of
``knowledge_base.py``. Given everything recon has learned about a single
endpoint (parameters, headers, cookies, forms, detected frameworks,
GraphQL/REST posture, JavaScript findings, secrets, directory findings,
browser reconnaissance, ...), the Detection Engine decides:

    * WHAT vulnerability classes are worth testing on this endpoint
    * WHEN (priority order) they should be tested
    * WHY (a human-readable justification, for the report and for the UI)
    * WITH WHAT CONFIDENCE (a dynamically computed 0-100 score)
    * WITH WHICH PAYLOADS (sourced from the KnowledgeBase, never duplicated)

The Detection Engine is a pure intelligence/planning layer:

    * It NEVER performs an HTTP request.
    * It NEVER exploits anything.
    * It NEVER stores or duplicates vulnerability, payload, CVSS, CWE,
      OWASP, CAPEC, compliance, or framework data -- all of that is
      sourced live from ``KB`` (the ``KnowledgeBase`` singleton).

Architecture
------------
``EndpointContext`` is the frozen-ish input describing everything recon
observed about one endpoint. ``DetectionEngine.generate_detection_plan()``
is the single public orchestration entry point most callers will use; it
runs every specialised ``*_rules()`` method, merges/deduplicates the
resulting ``DetectionRule`` objects (keeping the highest-confidence
version of any given vulnerability), attaches recommended payloads from
the KnowledgeBase, and returns a priority-ranked, cost-estimated
detection plan ready to be handed to the (separate) scanning/execution
layer.

Every individual ``*_rules()`` method is also public and independently
callable, so the vuln_engine / recon_core layers can ask narrower
questions (e.g. "just the GraphQL-specific rules for this endpoint")
without paying the cost of a full analysis pass.

Fixes applied (v2)
------------------
- Eliminated all_parameter_names() repeated calls; computed once per
  parameter_rules() invocation.
- Unified _match_signals() helper replacing the duplicated
  _matching_parameter_signals / _matching_technology_signals functions.
- Switched to O(1) dict lookup for framework profiles (init-time index).
- Removed dead _vulns_by_tag() method (zero callers).
- Removed redundant parameter_missing kwarg; parameter_hit alone suffices.
- Eliminated empty-string injection into optional_conditions lists.
- Cached path_lower() resolution on EndpointContext via __post_init__.
- Collapsed double max() calls in score() to a single keyed max().
- Promoted FRAMEWORK_AFFINITY_BONUS to module-level named constant.
- Replaced list(a.items()) + list(b.items()) with itertools.chain.
- Promoted TECH_TO_VULN_ID mapping to module-level constant.
- Removed duplicate WordPress special-case block (covered by framework_rules).
- Pre-built param_count and reason_prefix outside the per-vuln loop.
- Unified path computation: path_hit resolved once in _build_rule, not twice.
- Wired vuln.detection_intel.required_conditions from KB into rules.
- Wired vuln.affected_frameworks intersection for framework scoring bonus.
- Wired high-signal vuln.tags (rce, critical) for tag-based score bonus.
- Wired vuln.exploit_intel.authentication_required for auth-state penalty.
- Collapsed plan_summary() from 5 list passes to a single pass.
"""

from __future__ import annotations

import itertools
import logging
from dataclasses import dataclass, field
from enum import IntEnum
from functools import lru_cache
from typing import Any, Callable, Optional
from urllib.parse import urlparse

from ai_engine.knowledge_base import (
    KB,
    Category,
    Exploitability,
    FrameworkProfile,
    Severity,
    Vulnerability,
)

logger = logging.getLogger("detection_engine")
logger.addHandler(logging.NullHandler())


# ======================================================================
# ENUMERATIONS
# ======================================================================


class Priority(IntEnum):
    """Test-ordering priority. Higher value == test sooner."""

    CRITICAL = 4
    HIGH = 3
    MEDIUM = 2
    LOW = 1
    INFORMATIONAL = 0

    @property
    def label(self) -> str:
        return self.name.title()


class AuthState:
    """String constants for ``EndpointContext.authentication_state``."""

    UNKNOWN = "unknown"
    UNAUTHENTICATED = "unauthenticated"
    AUTHENTICATED = "authenticated"
    ADMIN = "admin"


# ======================================================================
# SCORING CONFIGURATION
# ======================================================================
#
# Every number below is a *signal weight*, not a hardcoded confidence.
# DetectionEngine.score() sums whichever of these signals are actually
# present for a given (Vulnerability, EndpointContext) pair and clamps
# the result into the 0-100 range. Nothing here duplicates KnowledgeBase
# content — these are purely endpoint-context heuristics.

# Parameter-name -> point value. Matched case-insensitively against
# query-string and form-field parameter names.
PARAMETER_SIGNAL_WEIGHTS: dict[str, int] = {
    # redirect / SSRF / open-redirect family
    "redirect": 30, "redirect_uri": 30, "redirecturl": 30, "return": 25,
    "returnurl": 25, "return_url": 25, "redir": 28, "url": 22, "uri": 20,
    "next": 25, "dest": 22, "destination": 22, "continue": 20,
    "callback": 22, "target": 20, "out": 15, "view": 12, "link": 15,
    "goto": 25, "forward": 22, "checkout_url": 22, "site": 15,
    # file / path / LFI-RFI family
    "file": 28, "filename": 28, "filepath": 28, "path": 26, "folder": 22,
    "dir": 22, "document": 20, "doc": 15, "load": 18, "page": 15,
    "template": 26, "tpl": 22, "include": 26, "resource": 18,
    # injection-prone identifiers
    "id": 15, "user_id": 16, "uid": 15, "account_id": 16,
    "object_id": 16, "order_id": 15, "invoice_id": 16, "item_id": 14,
    "query": 22, "search": 18, "q": 12, "filter": 16, "sort": 12,
    "order": 12, "where": 20,
    # auth / token related
    "token": 22, "jwt": 26, "session": 16, "auth": 16, "apikey": 20,
    "api_key": 20, "access_token": 22, "refresh_token": 22, "otp": 18,
    "code": 15,
    # command / template / code execution family
    "cmd": 30, "command": 30, "exec": 30, "execute": 28, "run": 20,
    "eval": 28, "shell": 28,
    # data / generic body carriers
    "xml": 22, "data": 12, "input": 12, "payload": 15, "body": 12,
    "content": 10, "html": 18, "message": 12, "comment": 15,
    # identity
    "email": 10, "username": 10, "password": 8,
    # upload
    "upload": 24, "attachment": 20, "avatar": 14,
}

# Path segment keyword -> point value (smart prioritization per spec).
HIGH_VALUE_PATH_KEYWORDS: dict[str, int] = {
    "admin": 20, "administrator": 20, "login": 18, "signin": 16,
    "oauth": 22, "sso": 18, "jwt": 20, "graphql": 25, "upload": 20,
    "file": 14, "download": 14, "webhook": 20, "callback": 18,
    "reset-password": 22, "reset_password": 22, "password-reset": 22,
    "forgot-password": 20, "api": 12, "account": 14, "profile": 12,
    "billing": 20, "invoice": 20, "payment": 22, "checkout": 20,
    "search": 12, "redirect": 22, "internal": 18, "debug": 22,
    "console": 20, "actuator": 22, "swagger": 16, "graphiql": 20,
    "playground": 18, "export": 14, "import": 16, "backup": 18,
    "config": 18, "settings": 12, "user": 10, "users": 10, "token": 16,
}

# Technology/framework fingerprint -> modest confidence bonus.
TECHNOLOGY_SIGNAL_WEIGHTS: dict[str, int] = {
    "nginx": 5, "apache": 5, "iis": 6, "php": 8, "wordpress": 10,
    "drupal": 8, "magento": 8, "jquery": 4, "redis": 10, "mongodb": 10,
    "elasticsearch": 10, "memcached": 8, "docker": 8, "kubernetes": 8,
    "aws": 6, "s3": 8, "firebase": 10, "graphql": 12, "swagger": 8,
    "openapi": 8, "werkzeug": 12, "express": 6, "spring": 6,
    "laravel": 8, "django": 6, "flask": 8, "asp.net": 8,
}

# High-signal vulnerability tags that add a score bonus when present.
HIGH_SIGNAL_TAGS: frozenset[str] = frozenset({"rce", "critical", "owasp-top10"})
HIGH_SIGNAL_TAG_BONUS = 8

BASE_CONFIDENCE_BY_KB_CONFIDENCE: dict[str, int] = {
    "Confirmed": 55,
    "Tentative": 35,
}

BASE_CONFIDENCE_BY_EXPLOITABILITY: dict[Exploitability, int] = {
    Exploitability.TRIVIAL: 15,
    Exploitability.EASY: 10,
    Exploitability.MODERATE: 5,
    Exploitability.DIFFICULT: -5,
    Exploitability.THEORETICAL: -15,
}

FRAMEWORK_AFFINITY_BONUS = 10   # vuln in ctx.framework's common_vulnerabilities
AUTH_REQUIRED_BONUS = 10        # endpoint needs auth and we have a session
AUTH_MISMATCH_PENALTY = -15     # KB says auth required but endpoint is public
GRAPHQL_ENDPOINT_BONUS = 20
FRAMEWORK_HIT_BONUS = 10        # vuln.affected_frameworks intersects ctx.frameworks
NO_REFLECTION_PENALTY = -20
CONFIDENCE_FLOOR = 0
CONFIDENCE_CEILING = 100

# Runtime/request cost model (scheduling/UI only — never used for scoring).
SECONDS_PER_REQUEST_BY_DIFFICULTY: dict[str, float] = {
    "Trivial": 0.20,
    "Easy": 0.35,
    "Moderate": 0.55,
    "Difficult": 0.90,
}
DEFAULT_SECONDS_PER_REQUEST = 0.45
DEFAULT_MAX_PAYLOADS_PER_RULE = 6

# Static technology-keyword -> KB vulnerability ID mapping.
# Module-level constant: built once, never reconstructed per call.
TECH_TO_VULN_ID: dict[str, str] = {
    "redis": "REDIS-001",
    "elasticsearch": "ES-001",
    "mongodb": "MONGO-001",
    "memcached": "MEMCACHED-001",
    "smtp": "SMTP-001",
    "ftp": "FTP-001",
    "snmp": "SNMP-001",
    "docker": "DOCKER-001",
    "kubernetes": "K8S-001",
    "firebase": "FIREBASE-001",
    "s3": "S3-001",
}

# Known session-cookie name substrings (used by cookie_rules).
_SESSION_COOKIE_NAMES: frozenset[str] = frozenset({
    "session", "sessionid", "sid", "connect.sid",
    "jsessionid", "phpsessid", "laravel_session",
})

# Security headers whose absence is flagged by header_rules.
_SECURITY_HEADERS: tuple[str, ...] = (
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Content-Type-Options",
)

# Auth-surface path keywords checked by authentication_rules.
_AUTH_PATH_KEYWORDS: tuple[str, ...] = (
    "login", "signin", "auth", "oauth", "sso",
    "password", "register", "signup", "mfa", "otp",
)


# ======================================================================
# INTERNAL HELPERS
# ======================================================================


def _clamp(value: int) -> int:
    """Clamp an integer confidence score to [CONFIDENCE_FLOOR, CONFIDENCE_CEILING]."""
    return max(CONFIDENCE_FLOOR, min(CONFIDENCE_CEILING, value))


def _match_signals(tokens: list[str], weight_table: dict[str, int]) -> dict[str, int]:
    """
    Generic O(T + K) signal matcher.

    Joins ``tokens`` into a single space-separated lowercase string, then
    tests each keyword in ``weight_table`` with a single ``in`` lookup
    instead of the previous O(K * N) nested-loop approach.

    Returns {keyword: weight} for every keyword that appears in any token.
    """
    if not tokens:
        return {}
    joined = " ".join(tokens)          # single pass to build the haystack
    return {kw: pts for kw, pts in weight_table.items() if kw in joined}


def _best_hit(hits: dict[str, int]) -> tuple[str, int]:
    """Return (keyword, max_points) from a signal-hit dict in one pass."""
    best_kw = max(hits, key=hits.__getitem__)
    return best_kw, hits[best_kw]


def _priority_from_severity_and_confidence(
    severity: Severity, confidence: int, path_bonus_hit: bool
) -> Priority:
    """
    Derive test-ordering priority from KB severity, computed confidence,
    and whether the endpoint matched a high-value path keyword.
    """
    if severity == Severity.CRITICAL:
        return Priority.CRITICAL if confidence >= 40 else Priority.HIGH
    if severity == Severity.HIGH:
        if confidence >= 75:
            return Priority.CRITICAL
        if confidence >= 50 or path_bonus_hit:
            return Priority.HIGH
        return Priority.MEDIUM
    if severity == Severity.MEDIUM:
        return Priority.HIGH if (confidence >= 65 or path_bonus_hit) else Priority.MEDIUM
    if severity == Severity.LOW:
        return Priority.MEDIUM if (confidence >= 70 or path_bonus_hit) else Priority.LOW
    return Priority.INFORMATIONAL


def _payload_group_for(vuln: Vulnerability) -> str:
    """Stable payload-group slug derived from the vulnerability's own ID prefix."""
    return vuln.id.split("-")[0].lower()


# ======================================================================
# DATACLASSES
# ======================================================================


@dataclass(slots=True)
class EndpointContext:
    """
    Everything recon has learned about a single endpoint, handed to the
    Detection Engine so it can decide what is worth testing.

    All fields default to empty/neutral values so callers can construct
    a context incrementally as recon modules populate it.

    ``_path_lower_cache`` is computed once at construction time to avoid
    repeated urlparse calls on the hot path.
    """

    url: str = ""
    path: str = ""
    method: str = "GET"

    query_parameters: dict[str, str] = field(default_factory=dict)
    headers: dict[str, str] = field(default_factory=dict)
    cookies: dict[str, str] = field(default_factory=dict)
    # Each form: {"action": str, "method": str, "fields": list[str], "enctype": str}
    forms: list[dict[str, Any]] = field(default_factory=list)

    technologies: list[str] = field(default_factory=list)
    frameworks: list[str] = field(default_factory=list)

    content_type: str = ""
    response_headers: dict[str, str] = field(default_factory=dict)
    status_code: int = 0

    authentication_state: str = AuthState.UNKNOWN

    graphql_detected: bool = False
    rest_detected: bool = False

    # e.g. [{"type": "reflected_param", "parameter": "q"}, ...]
    javascript_findings: list[dict[str, Any]] = field(default_factory=list)
    # e.g. [{"type": "api_key", "value_redacted": "sk_live_***", "source": "app.js"}]
    secrets_found: list[dict[str, Any]] = field(default_factory=list)
    # e.g. [{"path": "/.git/", "status_code": 200}, ...]
    directory_findings: list[dict[str, Any]] = field(default_factory=list)
    # Arbitrary fingerprinting evidence
    fingerprinting_results: dict[str, Any] = field(default_factory=dict)
    # e.g. {"dom_xss_sinks": [...], "postmessage_listeners": [...],
    #       "reflected_in_dom": True, "iframe_embeddable": True}
    browser_reconnaissance: dict[str, Any] = field(default_factory=dict)

    # Internal cache — populated by __post_init__, never set by callers.
    _path_lower_cache: str = field(default="", init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        # Resolve and cache the normalised path once at construction time.
        raw = self.path or urlparse(self.url).path or ""
        object.__setattr__(self, "_path_lower_cache", raw.lower())

    # ------------------------------------------------------------------

    def all_parameter_names(self) -> list[str]:
        """Every distinct parameter name observed across query string and forms."""
        names: set[str] = set(self.query_parameters.keys())
        for form in self.forms:
            names.update(form.get("fields", []))
        return sorted(names)

    def has_parameter_signal(self, keyword: str) -> bool:
        """True if any parameter name contains ``keyword`` (case-insensitive)."""
        kw = keyword.lower()
        return any(kw in name.lower() for name in self.all_parameter_names())

    def path_lower(self) -> str:
        """Return the normalised, lower-cased path (cached — O(1))."""
        return self._path_lower_cache

    def is_authenticated(self) -> bool:
        return self.authentication_state in (AuthState.AUTHENTICATED, AuthState.ADMIN)

    def cookie_names_lower(self) -> list[str]:
        return [c.lower() for c in self.cookies]

    def header_value(self, name: str) -> Optional[str]:
        """Case-insensitive header lookup across both request and response headers."""
        target = name.lower()
        for source in (self.headers, self.response_headers):
            for k, v in source.items():
                if k.lower() == target:
                    return v
        return None

    def reflects_input(self) -> bool:
        """
        Heuristic: do JS/browser findings indicate input is reflected into the DOM?
        """
        reflection_types = {"reflected_param", "dom_xss_sink", "reflection"}
        if any(f.get("type") in reflection_types for f in self.javascript_findings):
            return True
        return bool(self.browser_reconnaissance.get("reflected_in_dom"))


@dataclass(slots=True)
class DetectionRule:
    """
    A single actionable recommendation: test this vulnerability class on
    this endpoint, with this priority/confidence, using these payloads.
    """

    vulnerability: str          # KnowledgeBase vulnerability ID
    priority: Priority
    confidence: int             # 0-100, dynamically computed
    reason: str
    payload_group: str
    recommended_payloads: list[str] = field(default_factory=list)
    required_conditions: list[str] = field(default_factory=list)
    optional_conditions: list[str] = field(default_factory=list)
    framework_bonus: int = 0
    technology_bonus: int = 0
    estimated_runtime: float = 0.0   # seconds
    estimated_requests: int = 0

    # Convenience metadata mirrored from the KnowledgeBase so callers
    # don't need a second KB.get() call on every rule they receive.
    title: str = ""
    severity: str = ""
    cvss: float = 0.0
    category: str = ""

    def merge_higher_confidence(self, other: "DetectionRule") -> "DetectionRule":
        """Merge two rules for the same vulnerability, keeping the higher-confidence one."""
        winner, loser = (self, other) if self.confidence >= other.confidence else (other, self)
        if loser.reason and loser.reason not in winner.reason:
            winner.reason = f"{winner.reason}; {loser.reason}"
        winner.framework_bonus = max(winner.framework_bonus, loser.framework_bonus)
        winner.technology_bonus = max(winner.technology_bonus, loser.technology_bonus)
        # dict.fromkeys preserves insertion order and deduplicates in O(n).
        winner.required_conditions = list(
            dict.fromkeys(winner.required_conditions + loser.required_conditions)
        )
        winner.optional_conditions = list(
            dict.fromkeys(winner.optional_conditions + loser.optional_conditions)
        )
        return winner


# ======================================================================
# DETECTION ENGINE
# ======================================================================


class DetectionEngine:
    """
    Endpoint-aware, KnowledgeBase-driven decision engine.

    Instantiate once (or use the module-level DETECTION_ENGINE singleton).

    KB-derived lookups that are stable across a scan are cached:
    - per-category vulnerability tuples via lru_cache
    - framework profile dict built at __init__ time (O(1) lookup)
    """

    def __init__(self, knowledge_base=KB) -> None:
        self.kb = knowledge_base

        # O(1) framework-profile index: normalised-name -> FrameworkProfile.
        # Built once at init; avoids O(n) linear scan on every framework_rules call.
        self._fw_profile_index: dict[str, FrameworkProfile] = {
            p.name.lower(): p for p in self.kb.frameworks()
        }

        logger.info(
            "DetectionEngine initialised: %d vulnerabilities, %d framework profiles",
            self.kb.count(),
            len(self._fw_profile_index),
        )

    # ------------------------------------------------------------------
    # Cached KB accessors
    # ------------------------------------------------------------------

    @lru_cache(maxsize=64)
    def _vulns_by_category(self, category: Category) -> tuple[Vulnerability, ...]:
        return tuple(self.kb.filter_by_category(category))

    @lru_cache(maxsize=128)
    def _vulns_by_framework(self, framework: str) -> tuple[Vulnerability, ...]:
        return tuple(self.kb.filter_by_framework(framework))

    def _framework_profile(self, name: str) -> Optional[FrameworkProfile]:
        """O(1) framework profile lookup via the init-time index."""
        return self._fw_profile_index.get(name.strip().lower())

    # ------------------------------------------------------------------
    # Scoring
    # ------------------------------------------------------------------

    def score(
        self,
        vuln: Vulnerability,
        ctx: EndpointContext,
        *,
        parameter_hit: bool = False,
        path_hit: bool = False,
        framework_hit: bool = False,
        technology_hit: bool = False,
        graphql_hit: bool = False,
        auth_required_context: bool = False,
        requires_reflection: bool = False,
        extra_bonus: int = 0,
        extra_reasons: Optional[list[str]] = None,
    ) -> tuple[int, list[str]]:
        """
        Compute a dynamic 0-100 confidence score for testing ``vuln`` on
        ``ctx``. Every component is a function of KB metadata × endpoint
        context — nothing is hardcoded per vulnerability.

        Returns (confidence: int, reasons: list[str]).
        """
        reasons: list[str] = []

        # ── Base: KB confidence rating ──────────────────────────────────
        confidence = BASE_CONFIDENCE_BY_KB_CONFIDENCE.get(vuln.confidence, 30)
        reasons.append(
            f"KB confidence '{vuln.confidence}' → base {confidence}"
        )

        # ── Exploitability delta (from KB) ──────────────────────────────
        exploit_delta = BASE_CONFIDENCE_BY_EXPLOITABILITY.get(vuln.exploitability, 0)
        if exploit_delta:
            confidence += exploit_delta
            reasons.append(f"exploitability '{vuln.exploitability.value}' ({exploit_delta:+d})")

        # ── High-signal tags from KB (rce, critical, owasp-top10) ───────
        matching_tags = HIGH_SIGNAL_TAGS & set(vuln.tags)
        if matching_tags:
            confidence += HIGH_SIGNAL_TAG_BONUS
            reasons.append(
                f"high-signal tag(s) {sorted(matching_tags)} (+{HIGH_SIGNAL_TAG_BONUS})"
            )

        # ── Parameter signal ────────────────────────────────────────────
        if parameter_hit:
            param_hits = _match_signals(
                [n.lower() for n in ctx.all_parameter_names()],
                PARAMETER_SIGNAL_WEIGHTS,
            )
            if param_hits:
                best_kw, gained = _best_hit(param_hits)
                confidence += gained
                reasons.append(f"parameter name matched signal '{best_kw}' (+{gained})")

        # ── Path keyword signal ─────────────────────────────────────────
        if path_hit:
            path_hits = _match_signals([ctx.path_lower()], HIGH_VALUE_PATH_KEYWORDS)
            if path_hits:
                best_kw, gained = _best_hit(path_hits)
                confidence += gained
                reasons.append(f"path contains high-value keyword '{best_kw}' (+{gained})")

        # ── Technology fingerprint signal ───────────────────────────────
        if technology_hit:
            tech_tokens = [t.lower() for t in ctx.technologies] + [
                f.lower() for f in ctx.frameworks
            ]
            tech_hits = _match_signals(tech_tokens, TECHNOLOGY_SIGNAL_WEIGHTS)
            if tech_hits:
                best_kw, gained = _best_hit(tech_hits)
                confidence += gained
                reasons.append(f"technology '{best_kw}' fingerprinted (+{gained})")

        # ── Framework-affinity bonus (caller-supplied) ──────────────────
        if framework_hit:
            confidence += FRAMEWORK_HIT_BONUS
            reasons.append(f"framework known to exhibit this class (+{FRAMEWORK_HIT_BONUS})")

        # ── vuln.affected_frameworks ∩ ctx.frameworks (KB-driven) ───────
        if vuln.affected_frameworks and ctx.frameworks:
            af_lower = {f.lower() for f in vuln.affected_frameworks}
            ctx_fw_lower = {f.lower() for f in ctx.frameworks}
            if af_lower & ctx_fw_lower:
                confidence += FRAMEWORK_AFFINITY_BONUS
                reasons.append(
                    f"KB affected_frameworks intersects detected stack (+{FRAMEWORK_AFFINITY_BONUS})"
                )

        # ── GraphQL endpoint bonus ──────────────────────────────────────
        if graphql_hit:
            confidence += GRAPHQL_ENDPOINT_BONUS
            reasons.append(f"GraphQL endpoint detected (+{GRAPHQL_ENDPOINT_BONUS})")

        # ── Authentication context signals ──────────────────────────────
        if auth_required_context:
            if ctx.is_authenticated():
                confidence += AUTH_REQUIRED_BONUS
                reasons.append(
                    f"auth-required endpoint, session available (+{AUTH_REQUIRED_BONUS})"
                )
            elif vuln.exploit_intel.authentication_required:
                # KB says auth is required but we have none — less likely to be exploitable
                confidence += AUTH_MISMATCH_PENALTY
                reasons.append(
                    f"KB exploit requires auth but endpoint is public ({AUTH_MISMATCH_PENALTY})"
                )

        # ── Reflection requirement ──────────────────────────────────────
        if requires_reflection and not ctx.reflects_input():
            confidence += NO_REFLECTION_PENALTY
            reasons.append(f"no observed input reflection ({NO_REFLECTION_PENALTY})")

        # ── Caller-supplied extra bonus ─────────────────────────────────
        if extra_bonus:
            confidence += extra_bonus
            if extra_reasons:
                reasons.extend(extra_reasons)

        return _clamp(confidence), reasons

    # ------------------------------------------------------------------
    # Payload selection
    # ------------------------------------------------------------------

    def select_payloads(
        self, vuln_id: str, max_payloads: int = DEFAULT_MAX_PAYLOADS_PER_RULE
    ) -> list[str]:
        """
        Return up to ``max_payloads`` payload strings sourced live from
        the KnowledgeBase. The best (easiest/highest-confidence) payload
        is promoted to the front when rich payload metadata is available.
        """
        vuln = self.kb.get(vuln_id)
        if vuln is None:
            return []

        ordered: list[str] = []
        best = self.kb.best_payload(vuln_id)
        if best is not None:
            ordered.append(best.payload)

        for payload in vuln.payloads:
            if payload not in ordered:
                ordered.append(payload)
            if len(ordered) >= max_payloads:
                break

        return ordered[:max_payloads]

    # ------------------------------------------------------------------
    # Cost estimation
    # ------------------------------------------------------------------

    def _estimate_cost(
        self, vuln: Vulnerability, payload_count: int, injection_points: int
    ) -> tuple[float, int]:
        """Return (estimated_runtime_seconds, estimated_request_count)."""
        requests = max(1, payload_count) * max(1, injection_points)
        seconds_each = SECONDS_PER_REQUEST_BY_DIFFICULTY.get(
            vuln.exploit_intel.difficulty, DEFAULT_SECONDS_PER_REQUEST
        )
        return round(requests * seconds_each, 2), requests

    def _build_rule(
        self,
        vuln: Vulnerability,
        ctx: EndpointContext,
        reason_summary: str,
        *,
        required_conditions: Optional[list[str]] = None,
        optional_conditions: Optional[list[str]] = None,
        framework_bonus: int = 0,
        technology_bonus: int = 0,
        injection_points: int = 1,
        **score_kwargs: Any,
    ) -> DetectionRule:
        """
        Build a fully-populated DetectionRule for ``vuln`` on ``ctx``.

        Required conditions are seeded from the KB's own
        detection_intel.required_conditions, then extended by the caller.
        path_hit for priority derivation is resolved here once from the
        cached path_lower(), never recomputed inside score().
        """
        confidence, score_reasons = self.score(vuln, ctx, **score_kwargs)

        # Compute path_hit once from the cached path string.
        path_hit_for_priority = bool(
            _match_signals([ctx.path_lower()], HIGH_VALUE_PATH_KEYWORDS)
        )
        priority = _priority_from_severity_and_confidence(
            vuln.severity, confidence, path_hit_for_priority
        )

        payloads = self.select_payloads(vuln.id)
        runtime, requests = self._estimate_cost(vuln, len(payloads) or 1, injection_points)

        # Seed required_conditions from KB intelligence, then add caller extras.
        kb_required = list(vuln.detection_intel.required_conditions)
        caller_required = [c for c in (required_conditions or []) if c]
        merged_required = list(dict.fromkeys(kb_required + caller_required))

        caller_optional = [c for c in (optional_conditions or []) if c]

        full_reason = (
            f"{reason_summary} [{'; '.join(score_reasons)}]" if score_reasons
            else reason_summary
        )

        return DetectionRule(
            vulnerability=vuln.id,
            priority=priority,
            confidence=confidence,
            reason=full_reason,
            payload_group=_payload_group_for(vuln),
            recommended_payloads=payloads,
            required_conditions=merged_required,
            optional_conditions=caller_optional,
            framework_bonus=framework_bonus,
            technology_bonus=technology_bonus,
            estimated_runtime=runtime,
            estimated_requests=requests,
            title=vuln.title,
            severity=vuln.severity.value,
            cvss=vuln.cvss,
            category=vuln.category.value,
        )

    # ------------------------------------------------------------------
    # RULE METHODS
    # ------------------------------------------------------------------

    def parameter_rules(self, ctx: EndpointContext) -> list[DetectionRule]:
        """
        Rules driven by the names of observed parameters (query string +
        form fields). Covers injection, XSS, SSRF, file-handling, and
        open-redirect classes.
        """
        # Compute once; reuse across all vulns in the loop.
        param_names = ctx.all_parameter_names()
        if not param_names:
            return []

        param_count = len(param_names)
        param_tokens = [n.lower() for n in param_names]
        param_hits = _match_signals(param_tokens, PARAMETER_SIGNAL_WEIGHTS)
        has_signal = bool(param_hits)
        reason_prefix = (
            f"Endpoint exposes {param_count} parameter(s); "
            "'{{title}}' targets user-controllable input of this kind."
        )

        candidate_categories = (
            Category.INJECTION, Category.XSS, Category.SSRF,
            Category.FILE_HANDLING, Category.CLIENT_SIDE,
        )
        rules: list[DetectionRule] = []
        for category in candidate_categories:
            requires_reflection = category is Category.XSS
            for vuln in self._vulns_by_category(category):
                rule = self._build_rule(
                    vuln, ctx,
                    reason_summary=reason_prefix.replace("{title}", vuln.title),
                    required_conditions=["At least one attacker-controllable parameter present"],
                    optional_conditions=(
                        ["Parameter reflected in response"] if requires_reflection else []
                    ),
                    injection_points=param_count,
                    parameter_hit=has_signal,
                    requires_reflection=requires_reflection,
                )
                rules.append(rule)
        return rules

    def header_rules(self, ctx: EndpointContext) -> list[DetectionRule]:
        """Rules driven by request/response header posture."""
        rules: list[DetectionRule] = []

        # ── CORS misconfiguration ───────────────────────────────────────
        cors_header = ctx.header_value("Access-Control-Allow-Origin")
        if cors_header:
            vuln = self.kb.get("CORS-001")
            if vuln:
                reflective = cors_header.strip() not in ("*", "")
                acac = ctx.header_value("Access-Control-Allow-Credentials")
                bonus = 25 if (reflective and str(acac).lower() == "true") else 0
                rules.append(self._build_rule(
                    vuln, ctx,
                    reason_summary=f"Access-Control-Allow-Origin header present ('{cors_header}')",
                    required_conditions=["Access-Control-Allow-Origin header observed"],
                    extra_bonus=bonus,
                    extra_reasons=["reflects Origin with credentials allowed (+25)"] if bonus else None,
                ))

        # ── Missing framing protection (Clickjacking / Tabnabbing) ──────
        csp = ctx.header_value("Content-Security-Policy") or ""
        if not ctx.header_value("X-Frame-Options") and "frame-ancestors" not in csp:
            for vuln_id in ("CLICKJACK-001", "TABNAB-001"):
                vuln = self.kb.get(vuln_id)
                if vuln:
                    rules.append(self._build_rule(
                        vuln, ctx,
                        reason_summary="No X-Frame-Options / frame-ancestors CSP directive observed",
                        required_conditions=["Response renders HTML content"],
                    ))

        # ── Missing defence-in-depth headers ───────────────────────────
        missing = [h for h in _SECURITY_HEADERS if not ctx.header_value(h)]
        if missing:
            vuln = self.kb.get("HEADERS-001")
            if vuln:
                rules.append(self._build_rule(
                    vuln, ctx,
                    reason_summary=f"Missing security headers: {', '.join(missing)}",
                    extra_bonus=5 * len(missing),
                ))

        # ── Host header injection (password-reset paths) ─────────────
        path = ctx.path_lower()
        if ctx.header_value("Host") and ("password" in path or "reset" in path):
            vuln = self.kb.get("HOSTHDR-001")
            if vuln:
                rules.append(self._build_rule(
                    vuln, ctx,
                    reason_summary="Host header present at a password-reset style endpoint",
                    required_conditions=["Application builds absolute URLs from Host header"],
                    path_hit=True,
                ))

        # ── HTTP Parameter Pollution ────────────────────────────────────
        if len(ctx.query_parameters) != len({k.lower() for k in ctx.query_parameters}):
            vuln = self.kb.get("HPP-001")
            if vuln:
                rules.append(self._build_rule(
                    vuln, ctx,
                    reason_summary="Duplicate parameter names observed in query string",
                    required_conditions=["Backend and validation layer parse duplicates differently"],
                ))

        # ── CRLF injection (CR/LF in any header value) ─────────────────
        crlf_markers = ("\r\n", "%0d%0a", "%0D%0A")
        for header_name, value in itertools.chain(
            ctx.headers.items(), ctx.response_headers.items()
        ):
            if any(m in str(value) for m in crlf_markers):
                vuln = self.kb.get("CRLFI-001")
                if vuln:
                    rules.append(self._build_rule(
                        vuln, ctx,
                        reason_summary=f"CR/LF-like sequence in header '{header_name}'",
                        required_conditions=["Header value reflected without CR/LF sanitisation"],
                    ))
                break  # one finding is enough to recommend the test

        # ── HTTP Request Smuggling / Desync ─────────────────────────────
        if ctx.header_value("Transfer-Encoding") and ctx.header_value("Content-Length"):
            for vuln_id in ("SMUGGLE-001", "DESYNC-001"):
                vuln = self.kb.get(vuln_id)
                if vuln:
                    rules.append(self._build_rule(
                        vuln, ctx,
                        reason_summary="Both Transfer-Encoding and Content-Length present",
                        required_conditions=["Front-end and back-end parse request framing differently"],
                    ))

        return rules

    def cookie_rules(self, ctx: EndpointContext) -> list[DetectionRule]:
        """Rules driven by cookie attributes and naming (session security posture)."""
        if not ctx.cookies:
            return []

        rules: list[DetectionRule] = []
        set_cookie_raw = (ctx.header_value("Set-Cookie") or "").lower()
        insecure_flags = (
            "secure" not in set_cookie_raw
            or "httponly" not in set_cookie_raw
            or "samesite" not in set_cookie_raw
        )
        cookie_names_lower = ctx.cookie_names_lower()
        session_like = any(n in _SESSION_COOKIE_NAMES for n in cookie_names_lower)

        if session_like and insecure_flags:
            vuln = self.kb.get("COOKIE-001")
            if vuln:
                rules.append(self._build_rule(
                    vuln, ctx,
                    reason_summary="Session cookie without confirmed Secure/HttpOnly/SameSite flags",
                    required_conditions=["Session cookie identified"],
                ))

        if session_like and not ctx.is_authenticated():
            vuln = self.kb.get("SESS-001")
            if vuln:
                rules.append(self._build_rule(
                    vuln, ctx,
                    reason_summary="Session cookie present prior to authentication",
                    required_conditions=[
                        "Session identifier accepted before login",
                        "Not regenerated post-auth",
                    ],
                ))

        # Detect JWT-shaped cookie values (three base64url segments).
        for name, value in ctx.cookies.items():
            if value.count(".") == 2 and len(value) > 20:
                vuln = self.kb.get("JWT-001")
                if vuln:
                    rules.append(self._build_rule(
                        vuln, ctx,
                        reason_summary=f"Cookie '{name}' has JWT-like structure (header.payload.signature)",
                        required_conditions=["Cookie value is a JWT"],
                        auth_required_context=True,
                    ))
                break  # one JWT detection is enough

        return rules

    def authentication_rules(self, ctx: EndpointContext) -> list[DetectionRule]:
        """Rules driven by login/OAuth/password-reset/MFA/JWT surface area."""
        path = ctx.path_lower()
        is_auth_surface = any(kw in path for kw in _AUTH_PATH_KEYWORDS)
        if not is_auth_surface and not ctx.is_authenticated():
            return []

        candidate_ids = [
            "AUTH-001", "CSRF-001", "RATELIMIT-001",
            "WEAKPW-001", "MFA-001", "SESS-002",
        ]
        if "oauth" in path or "sso" in path:
            candidate_ids.append("OAUTH-001")
        has_jwt = (
            ctx.header_value("Authorization") is not None
            or any("jwt" in n for n in ctx.cookie_names_lower())
        )
        if has_jwt:
            candidate_ids.extend(["JWT-001", "JWT-002"])

        endpoint_label = ctx.path or ctx.url
        rules: list[DetectionRule] = []
        for vuln_id in candidate_ids:
            vuln = self.kb.get(vuln_id)
            if not vuln:
                continue
            rules.append(self._build_rule(
                vuln, ctx,
                reason_summary=f"Authentication-related surface detected at '{endpoint_label}'",
                required_conditions=["Endpoint participates in the authentication/session lifecycle"],
                path_hit=True,
                auth_required_context=ctx.is_authenticated(),
            ))
        return rules

    def graphql_rules(self, ctx: EndpointContext) -> list[DetectionRule]:
        """Rules specific to detected GraphQL endpoints."""
        if not ctx.graphql_detected:
            return []

        candidate_ids = ("GRAPHQL-001", "BOLA-001", "SSRF-001", "SQLI-001", "INFODISC-001")
        rules: list[DetectionRule] = []
        for vuln_id in candidate_ids:
            vuln = self.kb.get(vuln_id)
            if not vuln:
                continue
            rules.append(self._build_rule(
                vuln, ctx,
                reason_summary="GraphQL endpoint detected",
                required_conditions=["Endpoint accepts GraphQL queries/mutations"],
                optional_conditions=["Introspection enabled"],
                graphql_hit=True,
            ))
        return rules

    def rest_rules(self, ctx: EndpointContext) -> list[DetectionRule]:
        """Rules specific to detected REST API surfaces."""
        if not ctx.rest_detected:
            return []

        candidate_ids = (
            "BOLA-001", "EXCESSDATA-001", "MASSASSIGN-001",
            "ASSETMGMT-001", "OPENAPI-001",
        )
        has_id_param = ctx.has_parameter_signal("id")
        rules: list[DetectionRule] = []
        for vuln_id in candidate_ids:
            vuln = self.kb.get(vuln_id)
            if not vuln:
                continue
            rules.append(self._build_rule(
                vuln, ctx,
                reason_summary="REST API surface detected",
                required_conditions=["Endpoint returns or mutates a discrete resource"],
                parameter_hit=has_id_param,
                technology_hit=True,
            ))
        return rules

    def browser_rules(self, ctx: EndpointContext) -> list[DetectionRule]:
        """Rules driven by headless-browser reconnaissance results."""
        recon = ctx.browser_reconnaissance
        if not recon:
            return []

        rules: list[DetectionRule] = []

        if recon.get("dom_xss_sinks"):
            vuln = self.kb.get("XSS-003")
            if vuln:
                sink_count = len(recon["dom_xss_sinks"])
                rules.append(self._build_rule(
                    vuln, ctx,
                    reason_summary=f"Browser recon observed {sink_count} dangerous DOM sink(s)",
                    required_conditions=["Attacker-influenceable data reaches a DOM sink"],
                    requires_reflection=True,
                ))

        if recon.get("iframe_embeddable"):
            vuln = self.kb.get("CLICKJACK-001")
            if vuln:
                rules.append(self._build_rule(
                    vuln, ctx,
                    reason_summary="Browser recon confirmed page is embeddable in a foreign iframe",
                    required_conditions=["No frame-busting / frame-ancestors protection observed"],
                ))

        if recon.get("postmessage_listeners"):
            vuln = self.kb.get("PROTOPOLL-001")
            if vuln:
                listener_count = len(recon["postmessage_listeners"])
                rules.append(self._build_rule(
                    vuln, ctx,
                    reason_summary=(
                        f"{listener_count} postMessage listener(s) without confirmed origin checks"
                    ),
                    required_conditions=["postMessage handler does not validate event.origin"],
                ))

        if recon.get("target_blank_without_noopener"):
            vuln = self.kb.get("TABNAB-001")
            if vuln:
                rules.append(self._build_rule(
                    vuln, ctx,
                    reason_summary='target="_blank" link(s) observed without rel="noopener noreferrer"',
                    required_conditions=["Outbound link opens with window.opener access"],
                ))

        if recon.get("webview_bridge_detected"):
            vuln = self.kb.get("WEBVIEW-001")
            if vuln:
                rules.append(self._build_rule(
                    vuln, ctx,
                    reason_summary="Mobile WebView JavaScript bridge interface detected",
                    required_conditions=["Native bridge reachable from loaded web content"],
                ))

        return rules

    def directory_rules(self, ctx: EndpointContext) -> list[DetectionRule]:
        """Rules driven by directory/file enumeration findings."""
        # Static marker -> vuln-id table (ordered: most specific first).
        _DIR_MARKERS: tuple[tuple[str, str], ...] = (
            (".git",          "GITEXP-001"),
            (".env",          "HARDCODEDSEC-001"),
            (".bak",          "BACKUP-001"),
            ("backup",        "BACKUP-001"),
            ("wp-admin",      "ADMINPANEL-001"),
            ("admin",         "ADMINPANEL-001"),
            ("__debugger__",  "DEBUGEP-001"),
            ("actuator",      "DEBUGEP-001"),
            ("debug",         "DEBUGEP-001"),
            ("swagger",       "OPENAPI-001"),
            ("openapi",       "OPENAPI-001"),
            ("/",             "DIRLIST-001"),
        )

        rules: list[DetectionRule] = []
        for finding in ctx.directory_findings:
            status = finding.get("status_code", 0)
            if status and status >= 400:
                continue
            found_path = str(finding.get("path", "")).lower()
            for marker, vuln_id in _DIR_MARKERS:
                if marker in found_path:
                    vuln = self.kb.get(vuln_id)
                    if not vuln:
                        continue
                    raw_path = finding.get("path", found_path)
                    rules.append(self._build_rule(
                        vuln, ctx,
                        reason_summary=f"Directory enumeration found reachable path '{raw_path}'",
                        required_conditions=[
                            f"Path '{raw_path}' returns a non-error status"
                        ],
                        extra_bonus=15,
                        extra_reasons=[f"matched sensitive marker '{marker}' (+15)"],
                    ))
                    break  # only one vuln per finding
        return rules

    def js_rules(self, ctx: EndpointContext) -> list[DetectionRule]:
        """Rules driven by JavaScript static/dynamic analysis findings."""
        # Static dispatch table: finding type -> KB vuln ID.
        _JS_TYPE_TO_VULN: dict[str, str] = {
            "api_key":                "APIKEY-001",
            "hardcoded_secret":       "HARDCODEDSEC-001",
            "prototype_pollution_sink": "PROTOPOLL-001",
            "jsonp_callback":         "JSONP-001",
            "dom_xss_sink":           "XSS-003",
            "reflected_param":        "XSS-003",
        }

        rules: list[DetectionRule] = []
        seen_vuln_ids: set[str] = set()  # avoid duplicate rules from same finding type
        for finding in ctx.javascript_findings:
            ftype = finding.get("type", "")
            vuln_id = _JS_TYPE_TO_VULN.get(ftype)
            if not vuln_id or vuln_id in seen_vuln_ids:
                continue
            vuln = self.kb.get(vuln_id)
            if not vuln:
                continue
            seen_vuln_ids.add(vuln_id)
            rules.append(self._build_rule(
                vuln, ctx,
                reason_summary=f"JavaScript analysis flagged finding type '{ftype}'",
                required_conditions=["Finding confirmed reachable from a loaded script"],
                requires_reflection=(vuln_id == "XSS-003"),
            ))
        return rules

    def secret_rules(self, ctx: EndpointContext) -> list[DetectionRule]:
        """Rules driven by exposed-secret findings (API keys, credentials, tokens)."""
        _SECRET_TYPE_TO_VULN: dict[str, str] = {
            "api_key":       "APIKEY-001",
            "access_token":  "APIKEY-001",
            "password":      "HARDCODEDSEC-001",
            "db_credential": "HARDCODEDSEC-001",
            "private_key":   "HARDCODEDSEC-001",
        }
        _DEFAULT_SECRET_VULN = "CREDLEAK-001"

        rules: list[DetectionRule] = []
        seen_vuln_ids: set[str] = set()
        for finding in ctx.secrets_found:
            stype = finding.get("type", "")
            vuln_id = _SECRET_TYPE_TO_VULN.get(stype, _DEFAULT_SECRET_VULN)
            if vuln_id in seen_vuln_ids:
                continue
            vuln = self.kb.get(vuln_id)
            if not vuln:
                continue
            seen_vuln_ids.add(vuln_id)
            source = finding.get("source", "unknown")
            rules.append(self._build_rule(
                vuln, ctx,
                reason_summary=f"Secret scanner found candidate '{stype}' at '{source}'",
                required_conditions=["Secret value confirmed live/functional"],
                extra_bonus=20,
                extra_reasons=["direct secret-scanner hit (+20)"],
            ))
        return rules

    def framework_rules(self, ctx: EndpointContext) -> list[DetectionRule]:
        """
        Rules sourced from each detected framework's FrameworkProfile
        (common_vulnerabilities list), scored with a framework-affinity bonus.
        """
        rules: list[DetectionRule] = []
        for fw_name in ctx.frameworks:
            profile = self._framework_profile(fw_name)  # O(1)
            if profile is None:
                continue
            for vuln_id in profile.common_vulnerabilities:
                vuln = self.kb.get(vuln_id)
                if not vuln:
                    continue
                rules.append(self._build_rule(
                    vuln, ctx,
                    reason_summary=(
                        f"Framework '{profile.name}' commonly exhibits '{vuln.title}'"
                    ),
                    required_conditions=[f"Target confirmed running {profile.name}"],
                    framework_bonus=FRAMEWORK_AFFINITY_BONUS,
                    framework_hit=True,
                ))
        return rules

    def technology_rules(self, ctx: EndpointContext) -> list[DetectionRule]:
        """
        Rules sourced from detected backing-service technologies
        (Redis, MongoDB, Elasticsearch, etc.) mapped to KB NETWORK_SERVICE records.
        """
        if not ctx.technologies:
            return []

        tech_tokens = [t.lower() for t in ctx.technologies]
        rules: list[DetectionRule] = []

        for tech, vuln_id in TECH_TO_VULN_ID.items():
            if not any(tech in t for t in tech_tokens):
                continue
            vuln = self.kb.get(vuln_id)
            if not vuln:
                continue
            rules.append(self._build_rule(
                vuln, ctx,
                reason_summary=f"Technology fingerprint identified '{tech}' in use",
                required_conditions=[
                    f"'{tech}' service reachable from the tested network position"
                ],
                technology_hit=True,
            ))

        return rules

    # ------------------------------------------------------------------
    # Orchestration
    # ------------------------------------------------------------------

    def analyze(self, ctx: EndpointContext) -> list[DetectionRule]:
        """
        Run every specialised rule method against ``ctx`` and return the
        raw, undeduplicated list of all DetectionRules produced.
        """
        rule_methods: tuple[Callable[[EndpointContext], list[DetectionRule]], ...] = (
            self.parameter_rules,
            self.header_rules,
            self.cookie_rules,
            self.authentication_rules,
            self.graphql_rules,
            self.rest_rules,
            self.browser_rules,
            self.directory_rules,
            self.js_rules,
            self.secret_rules,
            self.framework_rules,
            self.technology_rules,
        )
        all_rules: list[DetectionRule] = []
        for method in rule_methods:
            try:
                all_rules.extend(method(ctx))
            except Exception:
                logger.exception(
                    "Rule method %s failed for endpoint %s", method.__name__, ctx.url
                )
        logger.debug("analyze() produced %d raw rules for %s", len(all_rules), ctx.url)
        return all_rules

    def _deduplicate(self, rules: list[DetectionRule]) -> list[DetectionRule]:
        """Collapse multiple rules for the same vulnerability to the highest-confidence one."""
        by_vuln: dict[str, DetectionRule] = {}
        for rule in rules:
            existing = by_vuln.get(rule.vulnerability)
            by_vuln[rule.vulnerability] = (
                rule if existing is None else existing.merge_higher_confidence(rule)
            )
        return list(by_vuln.values())

    def rank(self, rules: list[DetectionRule]) -> list[DetectionRule]:
        """
        Sort rules for execution ordering:
        priority DESC → confidence DESC → CVSS DESC → vuln ID ASC (deterministic).
        """
        return sorted(
            rules,
            key=lambda r: (-int(r.priority), -r.confidence, -r.cvss, r.vulnerability),
        )

    def generate_detection_plan(
        self,
        ctx: EndpointContext,
        *,
        min_confidence: int = 0,
        max_rules: Optional[int] = None,
    ) -> list[DetectionRule]:
        """
        Single public orchestration entry point.

        Runs the full rule suite, deduplicates to one rule per
        vulnerability (highest-confidence wins), filters below
        ``min_confidence``, ranks by priority/confidence/CVSS, and
        optionally truncates to ``max_rules``.
        """
        raw = self.analyze(ctx)
        deduped = self._deduplicate(raw)
        filtered = [r for r in deduped if r.confidence >= min_confidence]
        ranked = self.rank(filtered)
        if max_rules is not None:
            ranked = ranked[:max_rules]

        total_requests = sum(r.estimated_requests for r in ranked)
        total_runtime = round(sum(r.estimated_runtime for r in ranked), 2)
        logger.info(
            "generate_detection_plan(%s): %d rule(s), ~%d request(s), ~%.2fs estimated",
            ctx.url or ctx.path, len(ranked), total_requests, total_runtime,
        )
        return ranked

    # ------------------------------------------------------------------
    # Convenience reporting
    # ------------------------------------------------------------------

    def plan_summary(self, rules: list[DetectionRule]) -> dict[str, Any]:
        """Return aggregate statistics for a generated detection plan (single pass)."""
        if not rules:
            return {
                "total_rules": 0,
                "by_priority": {},
                "total_estimated_requests": 0,
                "total_estimated_runtime_seconds": 0.0,
                "average_confidence": 0.0,
                "distinct_categories": [],
            }

        by_priority: dict[str, int] = {}
        total_requests = 0
        total_runtime = 0.0
        total_confidence = 0
        categories: set[str] = set()

        for r in rules:
            label = r.priority.label
            by_priority[label] = by_priority.get(label, 0) + 1
            total_requests += r.estimated_requests
            total_runtime += r.estimated_runtime
            total_confidence += r.confidence
            categories.add(r.category)

        return {
            "total_rules": len(rules),
            "by_priority": by_priority,
            "total_estimated_requests": total_requests,
            "total_estimated_runtime_seconds": round(total_runtime, 2),
            "average_confidence": round(total_confidence / len(rules), 1),
            "distinct_categories": sorted(categories),
        }


# ======================================================================
# GLOBAL SINGLETON
# ======================================================================

DETECTION_ENGINE = DetectionEngine()


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)

    demo_ctx = EndpointContext(
        url="https://target.tld/api/v1/account/profile?redirect=/dashboard&user_id=42",
        path="/api/v1/account/profile",
        method="GET",
        query_parameters={"redirect": "/dashboard", "user_id": "42"},
        headers={"Authorization": "Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.xxx"},
        cookies={"laravel_session": "abc123"},
        technologies=["nginx", "php", "laravel"],
        frameworks=["Laravel"],
        content_type="application/json",
        response_headers={
            "Access-Control-Allow-Origin": "https://evil.example",
            "Access-Control-Allow-Credentials": "true",
        },
        status_code=200,
        authentication_state=AuthState.AUTHENTICATED,
        rest_detected=True,
    )

    plan = DETECTION_ENGINE.generate_detection_plan(demo_ctx, min_confidence=20)
    for detection_rule in plan[:10]:
        logger.info(
            "[%s] %s (confidence=%d, cvss=%.1f) :: %s",
            detection_rule.priority.label,
            detection_rule.vulnerability,
            detection_rule.confidence,
            detection_rule.cvss,
            detection_rule.reason,
        )
    logger.info("Summary: %s", DETECTION_ENGINE.plan_summary(plan))
