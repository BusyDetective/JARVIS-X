"""
finding_grouper.py — AI Bug Bounty Recon Platform
==================================================
Finding Aggregation Engine v2.0

OVERVIEW
--------
Transforms raw scanner detections into intelligently aggregated findings,
mirroring the grouping philosophy of commercial scanners (Burp Enterprise,
Invicti, Acunetix) without copying their implementation.

GROUPING STRATEGY
-----------------
Phase 1 — Fingerprinting
  Each raw detection receives a deterministic FindingFingerprint derived from:
    • Normalised endpoint   (path IDs → {id}, UUIDs → {uuid}, etc.)
    • Vulnerability type
    • Normalised parameter  (uid/user_id/userid → canonical form)
    • CWE identifier
    • Validation state      (Confirmed/Likely/Manual Review/Rejected)
    • Technology & framework

  Fingerprints are hashed to a hex digest that serves as the primary grouping
  key.  Two detections that share a fingerprint are treated as the same
  logical vulnerability observed with different payloads.

Phase 2 — Similarity scoring (secondary grouping)
  Findings that do NOT share an exact fingerprint are scored against each
  other using a weighted multi-dimensional similarity function:

    Dimension        Weight
    ─────────────── ──────
    Endpoint         0.30
    Parameter        0.20
    Technology       0.15
    Validation state 0.15
    Severity         0.10
    CWE              0.05
    OWASP            0.05

  If similarity ≥ SIMILARITY_THRESHOLD (default 0.75) the findings are
  merged.  To keep the algorithm O(n) the similarity check uses a
  pre-built bucket index (vuln_type → list of candidates) so only
  same-type findings are compared.

Phase 3 — Evidence merging
  All raw detections that collapse into one Finding are stored as Evidence
  objects.  The grouped Finding accumulates payloads, response snippets,
  status codes, headers, and timestamps without losing any forensic detail.

Phase 4 — Confidence recalculation
  Confidence is recomputed from the evidence set rather than averaged:

    base          = weighted average of raw confidences
    +5            per additional unique payload beyond the first
    +10           if any evidence has validation_reason == "Confirmed"
    +5            if technology/framework was matched
    −20           if best validation state is "Rejected"
    cap           = 100

Phase 5 — Knowledge Base enrichment (optional)
  If a KnowledgeBase instance is provided, each grouped Finding is enriched
  with description, recommendation, references, business_impact, CWE, OWASP,
  CAPEC, and CVSS from the KB.

SIMILARITY ALGORITHM
--------------------
    sim(A, B) = Σ weight_i × score_i(A, B)

  score_i is 1.0 for exact match, 0.5 for partial match, 0.0 otherwise,
  with endpoint similarity using sequence-ratio on normalised paths.

COMPATIBILITY
-------------
All existing public APIs are preserved:
    group_findings(findings)            → list[dict]  (unchanged contract)
    filter_by_severity(grouped, sev)    → list[dict]
    filter_by_confidence(grouped, min)  → list[dict]
    summarize(grouped)                  → dict
    top_findings(grouped, n)            → list[dict]

New public APIs added:
    aggregate_findings(findings, kb, verbose)  → AggregationResult
    get_grouping_stats(result)                 → dict
"""

from __future__ import annotations

import hashlib
import logging
import re
import time
import uuid as _uuid_mod
from collections import defaultdict
from dataclasses import dataclass, field
from difflib import SequenceMatcher
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse, parse_qs, urlencode

# ──────────────────────────────────────────────────────────────────────────────
# LOGGING
# ──────────────────────────────────────────────────────────────────────────────

log = logging.getLogger(__name__)

# ──────────────────────────────────────────────────────────────────────────────
# CONSTANTS
# ──────────────────────────────────────────────────────────────────────────────

SEVERITY_RANK: Dict[str, int] = {
    "Critical": 4,
    "High":     3,
    "Medium":   2,
    "Low":      1,
    "Info":     0,
    "Unknown":  0,
}

VALIDATION_RANK: Dict[str, int] = {
    "Confirmed":     3,
    "Likely":        2,
    "Manual Review": 1,
    "Rejected":      0,
}

# Similarity grouping threshold (0–1).  Tune per deployment.
SIMILARITY_THRESHOLD: float = 0.75

# Similarity dimension weights (must sum to 1.0)
_SIM_WEIGHTS: Dict[str, float] = {
    "endpoint":   0.30,
    "parameter":  0.20,
    "technology": 0.15,
    "validation": 0.15,
    "severity":   0.10,
    "cwe":        0.05,
    "owasp":      0.05,
}

# ──────────────────────────────────────────────────────────────────────────────
# COMPILED REGEXES  (compiled once at import time for O(1) reuse)
# ──────────────────────────────────────────────────────────────────────────────

_RE_NUMERIC_SEGMENT    = re.compile(r'(?<=/)\d+(?=/|$)')
_RE_UUID_SEGMENT       = re.compile(
    r'(?<=/)[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}'
    r'-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}(?=/|$)'
)
_RE_HASH_SEGMENT       = re.compile(r'(?<=/)[0-9a-fA-F]{32,64}(?=/|$)')
_RE_DUPLICATE_SLASHES  = re.compile(r'/{2,}')

# Parameter name aliases for normalisation
_PARAM_ALIAS_GROUPS: List[List[str]] = [
    ["id", "user_id", "userid", "uid", "user-id"],
    ["page", "p", "pg", "pageno", "page_no", "pagenum"],
    ["token", "access_token", "auth_token", "api_key", "apikey", "key"],
    ["q", "query", "search", "s", "keyword", "kw"],
    ["file", "filename", "filepath", "path"],
    ["url", "redirect", "redirect_url", "next", "return", "returnto"],
    ["order_id", "orderid", "order-id"],
    ["item_id", "itemid", "item-id"],
    ["product_id", "productid", "product-id"],
    ["session", "sessionid", "session_id", "sid"],
]

# Build canonical → alias mapping (all lowercase)
_PARAM_CANONICAL: Dict[str, str] = {}
for _group in _PARAM_ALIAS_GROUPS:
    _canonical = _group[0]
    for _alias in _group:
        _PARAM_CANONICAL[_alias.lower()] = _canonical

# Evidence hint fields consumed by risk_scoring._adjust_for_evidence().
# Defined once here; _init_finding_from_raw and _merge_raw_into_finding both import it.
EVIDENCE_HINT_FIELDS: tuple = (
    "xss_type", "sqli_type", "disclosure_type",
    "ssrf_egress", "lfi_rce_evidence", "idor_write",
    "oauth_redirect", "debug_authed", "admin_authed",
    "cors_credentials", "csrf_samesite_lax", "csrf_sensitive",
    "upload_exec", "jwt_alg_none", "jwt_weak_secret", "file_write",
)

# Severity ranking for string-typed hint fields (higher index = more severe)
_HINT_RANK: Dict[str, Dict[str, int]] = {
    "xss_type":       {"self": 0, "reflected": 1, "dom": 2, "stored": 3},
    "sqli_type":      {"error-based": 0, "blind": 1, "time-based": 1, "union": 2},
    "disclosure_type": {"version": 0, "stack_trace": 1, "source_code": 2, "credentials": 3},
}

# ──────────────────────────────────────────────────────────────────────────────
# DATACLASSES
# ──────────────────────────────────────────────────────────────────────────────

@dataclass(slots=True)
class Evidence:
    """
    A single piece of evidence collected during scanning.

    Each raw detection contributes one Evidence object to its parent Finding.
    Preserves full forensic detail: payload, response snippet, headers, timing.
    """
    payload:           str   = ""
    parameter:         str   = ""
    status_code:       int   = 0
    response_length:   int   = 0
    response_time:     float = 0.0
    validation_reason: str   = ""
    response_snippet:  str   = ""
    headers:           Dict  = field(default_factory=dict)
    timestamp:         float = field(default_factory=time.time)


@dataclass(slots=True)
class Finding:
    """
    An aggregated, de-duplicated vulnerability finding.

    Corresponds to one logical vulnerability observed at a normalised endpoint,
    potentially backed by many Evidence objects (payloads / raw detections).

    Fields mirror the internal dict schema used by existing callers so the
    Report Generator and Dashboard continue to work without modification.
    """
    # Identity
    id:                   str              = field(default_factory=lambda: str(_uuid_mod.uuid4()))
    title:                str              = ""
    severity:             str              = "Low"
    confidence:           int              = 0
    status:               str              = "Manual Review"

    # Location
    url:                  str              = ""
    normalized_url:       str              = ""
    parameter:            str              = ""
    normalized_parameter: str              = ""

    # Classification
    vulnerability_type:   str              = ""
    cwe:                  str              = ""
    owasp:                str              = ""
    capec:                str              = ""
    cvss:                 float            = 0.0
    technology:           str              = ""
    framework:            str              = ""

    # Evidence
    payloads:             List[str]        = field(default_factory=list)
    evidence:             List[Evidence]   = field(default_factory=list)
    validation_results:   List[str]        = field(default_factory=list)

    # Knowledge / reporting
    references:           List[str]        = field(default_factory=list)
    recommendation:       str              = ""
    business_impact:      str              = ""
    notes:                str              = ""

    # Raw source detections (preserved for audit)
    raw_findings:         List[Dict]       = field(default_factory=list)

    # ── Backward-compat fields consumed by existing Report Generator ──
    # These mirror the old grouped-dict schema.
    type:                 str              = ""   # alias for vulnerability_type
    count:                int              = 0
    examples:             List[str]        = field(default_factory=list)
    poc:                  str              = ""
    reason:               str              = ""

    def to_dict(self) -> Dict[str, Any]:
        """
        Serialise to a plain dict.

        The returned dict is backward-compatible with the old group_findings()
        schema so existing consumers (Report Generator, Dashboard,
        Vulnerability Engine) require no changes.
        """
        return {
            # New fields
            "id":                   self.id,
            "title":                self.title,
            "severity":             self.severity,
            "confidence":           self.confidence,
            "status":               self.status,
            "url":                  self.url,
            "normalized_url":       self.normalized_url,
            "parameter":            self.parameter,
            "normalized_parameter": self.normalized_parameter,
            "vulnerability_type":   self.vulnerability_type,
            "cwe":                  self.cwe,
            "owasp":                self.owasp,
            "capec":                self.capec,
            "cvss":                 self.cvss,
            "technology":           self.technology,
            "framework":            self.framework,
            "payloads":             self.payloads,
            "evidence":             [vars(e) for e in self.evidence],
            "validation_results":   self.validation_results,
            "references":           self.references,
            "recommendation":       self.recommendation,
            "business_impact":      self.business_impact,
            "notes":                self.notes,
            # Backward-compat
            "type":                 self.type or self.vulnerability_type,
            "count":                self.count,
            "examples":             self.examples,
            "poc":                  self.poc,
            "reason":               self.reason,
            # Evidence hint fields — parsed from notes by _init_finding_from_raw
            # and _merge_raw_into_finding; consumed by risk_scoring._adjust_for_evidence().
            **self._evidence_hints(),
        }

    def _evidence_hints(self) -> dict:
        """
        Parse evidence hint key=value pairs stored in self.notes.

        Tags are written by _init_finding_from_raw and _merge_raw_into_finding
        in the form "[key=value]".  Returns a plain dict for inclusion in
        to_dict() and for reading current values during merges.

        Uses the module-level ``re`` import (already compiled at import time).
        """
        import ast as _ast
        hints: dict = {}
        if not self.notes:
            return hints
        for match in re.finditer(r"\[([^=\]]+)=([^\]]+)\]", self.notes):
            key, raw_val = match.group(1), match.group(2).strip()
            try:
                hints[key] = _ast.literal_eval(raw_val)
            except (ValueError, SyntaxError):
                hints[key] = raw_val
        return hints


@dataclass(slots=True)
class FindingFingerprint:
    """
    Deterministic fingerprint that uniquely identifies a logical vulnerability.

    Two detections with the same fingerprint represent the same vulnerability
    observed with different payloads and are always merged.

    Fields
    ------
    endpoint        Normalised URL path (IDs replaced with placeholders)
    vuln_type       Vulnerability type string
    parameter       Canonical parameter name
    cwe             CWE identifier (may be empty)
    validation      Best validation state seen so far
    technology      Technology string (may be empty)
    framework       Framework string (may be empty)
    """
    endpoint:   str
    vuln_type:  str
    parameter:  str
    cwe:        str
    validation: str
    technology: str
    framework:  str

    def digest(self) -> str:
        """Return a stable hex digest of this fingerprint."""
        raw = "|".join([
            self.endpoint,
            self.vuln_type.lower(),
            self.parameter.lower(),
            self.cwe.lower(),
            self.validation.lower(),
            self.technology.lower(),
            self.framework.lower(),
        ])
        return hashlib.sha256(raw.encode()).hexdigest()


@dataclass(slots=True)
class AggregationResult:
    """
    Output of aggregate_findings().

    Contains the grouped Finding list plus statistics for reporting and
    logging.
    """
    findings:          List[Finding]
    raw_count:         int
    grouped_count:     int
    duplicates_removed: int
    evidence_merged:   int
    average_confidence: float
    confirmed_count:   int
    likely_count:      int
    manual_review_count: int
    rejected_count:    int


# ──────────────────────────────────────────────────────────────────────────────
# NORMALISATION HELPERS
# ──────────────────────────────────────────────────────────────────────────────

def _normalise_url_path(url: str) -> str:
    """
    Return a normalised URL path suitable for fingerprinting.

    Transformations applied (in order):
      1. Lowercase scheme and host
      2. Remove fragments (#…)
      3. Collapse duplicate slashes
      4. Replace UUID path segments with {uuid}
      5. Replace hex-hash path segments (32–64 chars) with {hash}
      6. Replace numeric path segments with {id}
      7. Sort query parameters for stable ordering
      8. Strip trailing slash

    Returns '<scheme>://<host><normalised_path>[?<sorted_qs>]'
    """
    try:
        p = urlparse(url)
        scheme = (p.scheme or "https").lower()
        host   = (p.netloc or "").lower()
        path   = p.path or "/"

        # Collapse double slashes
        path = _RE_DUPLICATE_SLASHES.sub("/", path)

        # Substitute dynamic segments
        path = _RE_UUID_SEGMENT.sub("{uuid}", path)
        path = _RE_HASH_SEGMENT.sub("{hash}", path)
        path = _RE_NUMERIC_SEGMENT.sub("{id}", path)

        # Normalise and sort query string
        qs = ""
        if p.query:
            params = parse_qs(p.query, keep_blank_values=True)
            # Sort keys, sort values within each key
            sorted_qs = sorted(
                (k, sorted(v)) for k, v in params.items()
            )
            qs = "?" + urlencode(
                [(k, vi) for k, vs in sorted_qs for vi in vs],
                doseq=False,
            )

        return f"{scheme}://{host}{path.rstrip('/')}{qs}"
    except Exception:
        return url.lower()


def _normalise_parameter(param: str) -> str:
    """
    Return the canonical parameter name.

    Known aliases (e.g. user_id, userid, uid) are mapped to a shared
    canonical form.  Unknown parameters are returned lowercased.
    """
    if not param:
        return ""
    lower = param.lower().strip()
    return _PARAM_CANONICAL.get(lower, lower)


# Cache for URL normalisation — avoids re-processing identical URLs
_url_norm_cache: Dict[str, str] = {}


def _cached_normalise_url(url: str) -> str:
    """Normalise url with a process-lifetime cache."""
    if url not in _url_norm_cache:
        _url_norm_cache[url] = _normalise_url_path(url)
    return _url_norm_cache[url]


# ──────────────────────────────────────────────────────────────────────────────
# LEGACY HELPERS  (preserved for backward compat)
# ──────────────────────────────────────────────────────────────────────────────

def _clean_url(url: str) -> str:
    """Strip query string and fragment — keep scheme + host + path only."""
    try:
        p = urlparse(url)
        return f"{p.scheme}://{p.netloc}{p.path}".rstrip("/")
    except Exception:
        return url


def _higher_severity(a: str, b: str) -> str:
    """Return whichever severity string ranks higher."""
    return a if SEVERITY_RANK.get(a, 0) >= SEVERITY_RANK.get(b, 0) else b


def _higher_validation(a: str, b: str) -> str:
    """Return whichever validation state ranks higher."""
    return a if VALIDATION_RANK.get(a, 0) >= VALIDATION_RANK.get(b, 0) else b


# ──────────────────────────────────────────────────────────────────────────────
# FINGERPRINT BUILDER
# ──────────────────────────────────────────────────────────────────────────────

def _build_fingerprint(raw: Dict[str, Any]) -> FindingFingerprint:
    """
    Construct a FindingFingerprint from a raw detection dict.

    Reads the following keys (all optional, defaults to empty string):
        url, type, parameter, cwe, validation_state, technology, framework

    Returns a FindingFingerprint whose .digest() is the grouping key.
    """
    url        = raw.get("url", "")
    norm_path  = _cached_normalise_url(url)
    # Fingerprint on path only (strip query) to merge same endpoint, diff params
    try:
        fp_path = urlparse(norm_path).scheme + "://" + \
                  urlparse(norm_path).netloc + \
                  urlparse(norm_path).path
    except Exception:
        fp_path = norm_path

    return FindingFingerprint(
        endpoint   = fp_path,
        vuln_type  = raw.get("type", "Unknown"),
        parameter  = _normalise_parameter(raw.get("parameter", "")),
        cwe        = raw.get("cwe", ""),
        validation = raw.get("validation_state", raw.get("status", "")),
        technology = raw.get("technology", ""),
        framework  = raw.get("framework", ""),
    )


# ──────────────────────────────────────────────────────────────────────────────
# SIMILARITY SCORING
# ──────────────────────────────────────────────────────────────────────────────

def _endpoint_similarity(a: str, b: str) -> float:
    """Sequence-ratio similarity between two normalised endpoint strings."""
    if a == b:
        return 1.0
    return SequenceMatcher(None, a, b).ratio()


def _exact_or_zero(a: str, b: str) -> float:
    """Return 1.0 if strings match (case-insensitive), else 0.0."""
    if not a or not b:
        return 0.0
    return 1.0 if a.lower() == b.lower() else 0.0


def similarity_score(fp_a: FindingFingerprint, fp_b: FindingFingerprint) -> float:
    """
    Compute weighted similarity between two fingerprints.

    Returns a float in [0.0, 1.0].  Values ≥ SIMILARITY_THRESHOLD should
    be considered the same logical vulnerability.

    Dimension scores:
        endpoint   — SequenceMatcher ratio on normalised paths
        parameter  — exact match on canonical parameter name
        technology — exact match
        validation — exact match on validation state
        severity   — not used here (used at Finding level post-fingerprint)
        cwe        — exact match
        owasp      — exact match (not in fingerprint; skipped if empty)
    """
    scores = {
        "endpoint":   _endpoint_similarity(fp_a.endpoint, fp_b.endpoint),
        "parameter":  _exact_or_zero(fp_a.parameter, fp_b.parameter),
        "technology": _exact_or_zero(fp_a.technology, fp_b.technology),
        "validation": _exact_or_zero(fp_a.validation, fp_b.validation),
        "severity":   0.0,   # not in fingerprint
        "cwe":        _exact_or_zero(fp_a.cwe, fp_b.cwe),
        "owasp":      0.0,   # not in fingerprint; handled during KB enrichment
    }
    return sum(_SIM_WEIGHTS[k] * scores[k] for k in _SIM_WEIGHTS)


# ──────────────────────────────────────────────────────────────────────────────
# CONFIDENCE RECALCULATION
# ──────────────────────────────────────────────────────────────────────────────

def _recalculate_confidence(finding: Finding) -> int:
    """
    Recompute confidence from accumulated evidence.

    Algorithm
    ---------
    1. Weighted average of raw_findings' confidence values.
    2. +5 per additional unique payload beyond the first (max +20).
    3. +10 if any evidence is Confirmed.
    4. +5  if technology or framework is populated.
    5. −20 if the best validation state is Rejected.
    6. Clamp to [0, 100].
    """
    if not finding.raw_findings:
        return finding.confidence

    raw_confs = [f.get("confidence", 0) for f in finding.raw_findings if isinstance(f, dict)]
    base = round(sum(raw_confs) / len(raw_confs)) if raw_confs else 0

    # Bonus: additional unique payloads
    unique_payloads = len(set(finding.payloads))
    payload_bonus   = min((unique_payloads - 1) * 5, 20) if unique_payloads > 1 else 0

    # Bonus: confirmed evidence
    confirmed_bonus = 10 if any(
        e.validation_reason == "Confirmed" for e in finding.evidence
    ) else 0

    # Bonus: technology match
    tech_bonus = 5 if (finding.technology or finding.framework) else 0

    # Penalty: best state is Rejected
    best_val = finding.status
    reject_penalty = -20 if best_val == "Rejected" else 0

    total = base + payload_bonus + confirmed_bonus + tech_bonus + reject_penalty
    return max(0, min(100, total))


# ──────────────────────────────────────────────────────────────────────────────
# EVIDENCE BUILDER
# ──────────────────────────────────────────────────────────────────────────────

def _raw_to_evidence(raw: Dict[str, Any]) -> Evidence:
    """Convert a raw detection dict to an Evidence object."""
    return Evidence(
        payload           = raw.get("payload", raw.get("poc", "")),
        parameter         = raw.get("parameter", ""),
        status_code       = raw.get("status_code", 0),
        response_length   = raw.get("response_length", 0),
        response_time     = raw.get("response_time", 0.0),
        validation_reason = raw.get("validation_state", raw.get("status", "")),
        response_snippet  = raw.get("response_snippet", raw.get("reason", "")),
        headers           = raw.get("headers", {}),
        timestamp         = raw.get("timestamp", time.time()),
    )


# ──────────────────────────────────────────────────────────────────────────────
# FINDING INITIALISER
# ──────────────────────────────────────────────────────────────────────────────

def _init_finding_from_raw(raw: Dict[str, Any]) -> Finding:
    """Create an initial Finding from the first raw detection in a group."""
    url   = raw.get("url", "")
    param = raw.get("parameter", "")
    vtype = raw.get("type", "Unknown")

    f = Finding(
        title                = raw.get("title", f"{vtype} — {_clean_url(url)}"),
        severity             = raw.get("severity", "Low"),
        confidence           = raw.get("confidence", 0),
        status               = raw.get("validation_state", raw.get("status", "Manual Review")),
        url                  = _clean_url(url),
        normalized_url       = _cached_normalise_url(url),
        parameter            = param,
        normalized_parameter = _normalise_parameter(param),
        vulnerability_type   = vtype,
        type                 = vtype,              # backward compat
        cwe                  = raw.get("cwe", ""),
        owasp                = raw.get("owasp", ""),
        capec                = raw.get("capec", ""),
        cvss                 = raw.get("cvss", 0.0),
        technology           = raw.get("technology", ""),
        framework            = raw.get("framework", ""),
        recommendation       = raw.get("recommendation", ""),
        business_impact      = raw.get("business_impact", ""),
        notes                = raw.get("notes", ""),
        poc                  = raw.get("poc", ""),         # backward compat
        reason               = raw.get("reason", ""),     # backward compat
        count                = 1,
    )

    ev = _raw_to_evidence(raw)
    f.evidence.append(ev)
    if ev.payload:
        f.payloads.append(ev.payload)
    if url != f.url:
        f.examples.append(url)
    f.validation_results.append(f.status)
    f.raw_findings.append(raw)

    # Carry evidence hint fields into the finding dict so to_dict() exposes
    # them for risk_scoring._adjust_for_evidence(). Store in notes as tagged
    # key=value pairs parsed by the dict consumer, and also propagate any
    # known keys directly into the raw dict reference kept in raw_findings[0].
    hint_parts = [f"{hf}={raw[hf]}" for hf in EVIDENCE_HINT_FIELDS if hf in raw]
    if hint_parts:
        f.notes = (f.notes + " " + " ".join(f"[{p}]" for p in hint_parts)).strip()

    return f


def _merge_raw_into_finding(finding: Finding, raw: Dict[str, Any]) -> None:
    """
    Merge a single raw detection into an existing Finding (mutates in place).

    Rules
    -----
    • severity          → keep highest
    • cvss              → keep highest
    • status            → keep highest-ranked validation state
    • evidence          → append new Evidence object
    • payloads          → append if unique, cap at 50
    • examples          → up to 5 unique full URLs
    • poc / reason      → prefer non-empty values
    • raw_findings      → always append (audit trail)
    """
    url   = raw.get("url", "")
    ev    = _raw_to_evidence(raw)

    # Severity
    finding.severity = _higher_severity(finding.severity, raw.get("severity", "Low"))

    # CVSS
    new_cvss = raw.get("cvss", 0.0)
    if new_cvss and new_cvss > finding.cvss:
        finding.cvss = new_cvss

    # Validation / status
    new_val = raw.get("validation_state", raw.get("status", ""))
    if new_val:
        finding.status = _higher_validation(finding.status, new_val)
        finding.validation_results.append(new_val)

    # Technology / framework
    if not finding.technology and raw.get("technology"):
        finding.technology = raw["technology"]
    if not finding.framework and raw.get("framework"):
        finding.framework = raw["framework"]

    # Evidence-hint fields used by risk_scoring._adjust_for_evidence().
    # Precedence: for each hint field, the more-severe value wins.
    # Current values are read from the already-parsed notes (since hint fields
    # are not dataclass slots — getattr would always return None).
    # Idempotency: a tag is written to notes only when its value changes.
    current_hints = finding._evidence_hints()   # parse existing notes once

    for field_name in EVIDENCE_HINT_FIELDS:
        incoming_val = raw.get(field_name)
        if incoming_val is None:
            continue

        current_val = current_hints.get(field_name)  # None if not yet set

        should_update = False
        if isinstance(incoming_val, bool):
            # debug_authed / admin_authed: False = unauthenticated = more severe
            if field_name in ("debug_authed", "admin_authed"):
                should_update = current_val is None or (not incoming_val and current_val)
            else:
                # All other bools: True = more severe
                should_update = incoming_val and not current_val
        elif isinstance(incoming_val, str):
            rank_map = _HINT_RANK.get(field_name)
            if rank_map:
                should_update = (
                    current_val is None or
                    rank_map.get(incoming_val, -1) > rank_map.get(str(current_val), -1)
                )

        if should_update:
            # Remove stale tag for this field if present (idempotency)
            if current_val is not None:
                finding.notes = re.sub(
                    rf"\[{re.escape(field_name)}=[^\]]*\]", "", finding.notes
                ).strip()
            finding.notes = (finding.notes + f" [{field_name}={incoming_val}]").strip()

    # Evidence
    finding.evidence.append(ev)

    # Payloads
    p = ev.payload
    if p and p not in finding.payloads and len(finding.payloads) < 50:
        finding.payloads.append(p)

    # Examples (backward compat)
    base = finding.url
    if url and url != base and url not in finding.examples and len(finding.examples) < 5:
        finding.examples.append(url)

    # PoC / reason (backward compat)
    if not finding.poc and raw.get("poc"):
        finding.poc = raw["poc"]
    if not finding.reason and raw.get("reason"):
        finding.reason = raw["reason"]

    finding.count += 1
    finding.raw_findings.append(raw)


# ──────────────────────────────────────────────────────────────────────────────
# KNOWLEDGE BASE ENRICHMENT  (optional)
# ──────────────────────────────────────────────────────────────────────────────

def _enrich_from_kb(finding: Finding, kb: Any) -> None:
    """
    Populate KB-sourced fields on a Finding if a KnowledgeBase is available.

    The KnowledgeBase is accessed duck-typed: any object with a
    .get_vulnerability_info(vuln_type) method that returns a dict will work.

    Populates (only if currently empty):
        description, recommendation, references, business_impact,
        cwe, owasp, capec, cvss (only if 0)
    """
    if kb is None:
        return
    try:
        info = kb.get_vulnerability_info(finding.vulnerability_type)
        if not info:
            return
        if not finding.recommendation:
            finding.recommendation = info.get("recommendation", "")
        if not finding.business_impact:
            finding.business_impact = info.get("business_impact", "")
        if not finding.references:
            refs = info.get("references", [])
            if isinstance(refs, list):
                finding.references = refs
        if not finding.cwe:
            finding.cwe = info.get("cwe", "")
        if not finding.owasp:
            finding.owasp = info.get("owasp", "")
        if not finding.capec:
            finding.capec = info.get("capec", "")
        if not finding.cvss:
            finding.cvss = info.get("cvss", 0.0)
        if not finding.title or finding.title.startswith(finding.vulnerability_type + " —"):
            kb_title = info.get("title", "")
            if kb_title:
                finding.title = kb_title
    except Exception as exc:
        log.debug("KB enrichment failed for %s: %s", finding.vulnerability_type, exc)


# ──────────────────────────────────────────────────────────────────────────────
# CORE AGGREGATION ENGINE
# ──────────────────────────────────────────────────────────────────────────────

def aggregate_findings(
    findings:  List[Dict[str, Any]],
    kb:        Any  = None,
    verbose:   bool = False,
) -> AggregationResult:
    """
    Aggregate raw detections into de-duplicated, evidence-rich Findings.

    Parameters
    ----------
    findings : list of raw detection dicts
        Each dict should contain at minimum: 'type', 'url', 'severity',
        'confidence'.  All other keys are optional.
    kb : KnowledgeBase, optional
        Any object with get_vulnerability_info(vuln_type) → dict.
        Used for post-grouping enrichment.
    verbose : bool
        If True, emit INFO-level log lines summarising grouping progress.

    Returns
    -------
    AggregationResult
        Contains the aggregated Finding list plus statistics.

    Algorithm
    ---------
    See module docstring for the full five-phase description.

    Complexity
    ----------
    O(n) for fingerprint-based grouping (dict lookup).
    O(n × b) for similarity grouping where b = average bucket size.
    In practice b << n because only same-type findings are compared.
    """
    raw_count = 0

    # Phase 1 — fingerprint-based grouping (primary, O(n))
    # key: fingerprint digest → Finding
    fp_index: Dict[str, Finding] = {}

    # Bucket index for secondary similarity pass
    # key: vuln_type → list of (fingerprint, Finding)
    bucket: Dict[str, List] = defaultdict(list)

    for raw in findings:
        if not isinstance(raw, dict):
            continue
        if not raw.get("url"):
            continue

        raw_count += 1
        fp = _build_fingerprint(raw)
        digest = fp.digest()

        if digest in fp_index:
            # Exact fingerprint match → merge directly
            _merge_raw_into_finding(fp_index[digest], raw)
        else:
            # Phase 2 — similarity check within same vuln_type bucket
            candidates = bucket[fp.vuln_type]
            merged = False
            for (cand_fp, cand_finding) in candidates:
                if similarity_score(fp, cand_fp) >= SIMILARITY_THRESHOLD:
                    _merge_raw_into_finding(cand_finding, raw)
                    # Register this digest as an alias so future exact hits land here
                    fp_index[digest] = cand_finding
                    merged = True
                    break

            if not merged:
                # New unique finding
                new_finding = _init_finding_from_raw(raw)
                fp_index[digest] = new_finding
                candidates.append((fp, new_finding))

    # Deduplicate the Finding objects (multiple digests may reference the same object)
    seen_ids: set  = set()
    unique_findings: List[Finding] = []
    for finding in fp_index.values():
        if finding.id not in seen_ids:
            seen_ids.add(finding.id)
            unique_findings.append(finding)

    # Phase 3 already done inline (evidence appended during merge)

    # Phase 4 — confidence recalculation
    for finding in unique_findings:
        finding.confidence = _recalculate_confidence(finding)

    # Phase 5 — Knowledge Base enrichment
    if kb is not None:
        for finding in unique_findings:
            _enrich_from_kb(finding, kb)

    # Sort: severity desc → confidence desc
    unique_findings.sort(key=lambda f: (
        -SEVERITY_RANK.get(f.severity, 0),
        -f.confidence,
    ))

    # Statistics
    confirmed_count     = sum(1 for f in unique_findings if f.status == "Confirmed")
    likely_count        = sum(1 for f in unique_findings if f.status == "Likely")
    manual_review_count = sum(1 for f in unique_findings if f.status == "Manual Review")
    rejected_count      = sum(1 for f in unique_findings if f.status == "Rejected")
    grouped_count       = len(unique_findings)
    duplicates_removed  = raw_count - grouped_count
    evidence_merged     = sum(len(f.evidence) for f in unique_findings)
    avg_conf            = (
        round(sum(f.confidence for f in unique_findings) / grouped_count, 1)
        if grouped_count else 0.0
    )

    if verbose:
        log.info(
            "[GROUP] Raw: %d | Grouped: %d | Duplicates removed: %d | "
            "Evidence merged: %d | Avg confidence: %.1f | "
            "Confirmed: %d | Likely: %d | Manual Review: %d | Rejected: %d",
            raw_count, grouped_count, duplicates_removed, evidence_merged,
            avg_conf, confirmed_count, likely_count, manual_review_count, rejected_count,
        )

    return AggregationResult(
        findings            = unique_findings,
        raw_count           = raw_count,
        grouped_count       = grouped_count,
        duplicates_removed  = duplicates_removed,
        evidence_merged     = evidence_merged,
        average_confidence  = avg_conf,
        confirmed_count     = confirmed_count,
        likely_count        = likely_count,
        manual_review_count = manual_review_count,
        rejected_count      = rejected_count,
    )


def get_grouping_stats(result: AggregationResult) -> Dict[str, Any]:
    """
    Return a plain-dict summary of an AggregationResult.

    Suitable for logging, API responses, or dashboard widgets.

    Keys
    ----
    raw_detections, grouped_findings, duplicates_removed, evidence_merged,
    average_confidence, confirmed, likely, manual_review, rejected,
    reduction_ratio
    """
    ratio = (
        round(1 - result.grouped_count / result.raw_count, 4)
        if result.raw_count else 0.0
    )
    return {
        "raw_detections":    result.raw_count,
        "grouped_findings":  result.grouped_count,
        "duplicates_removed": result.duplicates_removed,
        "evidence_merged":   result.evidence_merged,
        "average_confidence": result.average_confidence,
        "confirmed":         result.confirmed_count,
        "likely":            result.likely_count,
        "manual_review":     result.manual_review_count,
        "rejected":          result.rejected_count,
        "reduction_ratio":   ratio,
    }


# ──────────────────────────────────────────────────────────────────────────────
# LEGACY PUBLIC API  (preserved — all callers continue working unchanged)
# ──────────────────────────────────────────────────────────────────────────────

def group_findings(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Group findings by (vuln_type, base_url), merging duplicates.

    This is the original public API.  Behaviour is fully preserved.

    Internally, the call now routes through the new aggregation engine and
    converts Finding objects back to the original dict schema so downstream
    consumers (Report Generator, Dashboard, Vulnerability Engine) require no
    changes.

    Merging rules (same as original):
    - severity   → keep the highest seen across all instances
    - confidence → now recalculated from evidence (was: running average)
    - cvss       → keep the highest seen
    - examples   → up to 5 unique full URLs (with params)
    - count      → total instances merged

    Args:
        findings: list of finding dicts

    Returns:
        list of grouped finding dicts, sorted by severity then confidence
    """
    result = aggregate_findings(findings)
    return [f.to_dict() for f in result.findings]


def filter_by_severity(
    grouped: List[Dict[str, Any]],
    severity: str,
) -> List[Dict[str, Any]]:
    """Return findings matching a specific severity."""
    return [f for f in grouped if f.get("severity") == severity]


def filter_by_confidence(
    grouped: List[Dict[str, Any]],
    min_confidence: int = 70,
) -> List[Dict[str, Any]]:
    """Return findings at or above a confidence threshold."""
    return [f for f in grouped if f.get("confidence", 0) >= min_confidence]


def summarize(grouped: List[Dict[str, Any]]) -> Dict[str, int]:
    """
    Return a summary dict with counts per severity and total.

    Example:
        {"Critical": 2, "High": 5, "Medium": 3, "Low": 1, "total": 11}
    """
    summary: Dict[str, int] = defaultdict(int)
    for f in grouped:
        summary[f.get("severity", "Unknown")] += 1
    summary["total"] = len(grouped)
    return dict(summary)


def top_findings(
    grouped: List[Dict[str, Any]],
    n: int = 10,
) -> List[Dict[str, Any]]:
    """Return the top N findings by severity + confidence."""
    return grouped[:n]


# ──────────────────────────────────────────────────────────────────────────────
# SELF-TEST
# ──────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(message)s")

    test_findings = [
        # Same type + base URL, different params — should merge
        {"type": "XSS", "url": "https://example.com/search?q=<script>",      "severity": "High",     "confidence": 85, "cvss": 6.1, "payload": "<script>alert(1)</script>",  "validation_state": "Confirmed"},
        {"type": "XSS", "url": "https://example.com/search?q=test&lang=en",  "severity": "Medium",   "confidence": 55, "cvss": 5.4, "payload": "<img src=x onerror=alert(1)>","validation_state": "Likely"},
        {"type": "XSS", "url": "https://example.com/search?s=<svg>",         "severity": "High",     "confidence": 70, "cvss": 6.1, "payload": "<svg onload=alert(1)>",       "validation_state": "Likely"},

        # IDOR — same endpoint, numeric IDs — normalised endpoint should match
        {"type": "IDOR", "url": "https://example.com/profile/1",             "severity": "High",     "confidence": 60, "cvss": 7.5, "parameter": "user_id", "validation_state": "Likely"},
        {"type": "IDOR", "url": "https://example.com/profile/2",             "severity": "High",     "confidence": 65, "cvss": 7.5, "parameter": "userid",  "validation_state": "Likely"},
        {"type": "IDOR", "url": "https://example.com/profile/99",            "severity": "High",     "confidence": 70, "cvss": 7.5, "parameter": "uid",     "validation_state": "Confirmed"},

        # IDOR on different base — should NOT merge with above
        {"type": "IDOR", "url": "https://example.com/orders?order_id=9",     "severity": "High",     "confidence": 50, "cvss": 7.5, "validation_state": "Manual Review"},

        # Critical finding
        {"type": "SSTI", "url": "https://example.com/render?template={{7*7}}","severity": "Critical", "confidence": 90, "cvss": 9.8, "payload": "{{7*7}}",  "validation_state": "Confirmed"},

        # Low severity
        {"type": "Info", "url": "https://example.com/debug",                 "severity": "Low",      "confidence": 40, "cvss": 2.0, "validation_state": "Manual Review"},

        # UUID path — should normalise and merge if same type hit again
        {"type": "IDOR", "url": "https://example.com/profile/550e8400-e29b-41d4-a716-446655440000",
                                                                              "severity": "High",     "confidence": 75, "cvss": 7.5, "parameter": "id",     "validation_state": "Confirmed"},
    ]

    print("=" * 60)
    print("LEGACY API  group_findings()")
    print("=" * 60)
    grouped = group_findings(test_findings)
    print(f"Raw: {len(test_findings)}  →  Grouped: {len(grouped)}\n")
    for g in grouped:
        print(
            f"  [{g['severity']:8s}] {g['type']:6s} | "
            f"count={g['count']:2d} | "
            f"conf={g['confidence']:3d}% | "
            f"cvss={g['cvss']:.1f} | "
            f"status={g.get('status','?'):15s} | "
            f"{g['url']}"
        )
        for ex in g["examples"]:
            print(f"    ↳ {ex}")
    print("\nSummary:", summarize(grouped))
    print("Top 3:", [f["type"] for f in top_findings(grouped, 3)])

    print()
    print("=" * 60)
    print("NEW API  aggregate_findings(verbose=True)")
    print("=" * 60)
    result = aggregate_findings(test_findings, verbose=True)
    stats  = get_grouping_stats(result)
    print("\nGrouping stats:")
    for k, v in stats.items():
        print(f"  {k:25s}: {v}")

    print("\nDetailed findings:")
    for f in result.findings:
        print(
            f"  [{f.severity:8s}] {f.vulnerability_type:6s} | "
            f"evidence={len(f.evidence):2d} | "
            f"payloads={len(f.payloads):2d} | "
            f"conf={f.confidence:3d}% | "
            f"status={f.status:15s} | "
            f"{f.normalized_url}"
        )
