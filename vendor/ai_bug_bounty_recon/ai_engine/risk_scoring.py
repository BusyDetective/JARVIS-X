"""
Risk Scoring Engine v2.1 — CVSS v3.1 / OWASP Risk Rating Audit

SEVERITY CONTRACT
-----------------
``compute_finding_risk_score()`` is the ONE place severity is calculated.
It writes the result into the canonical field ``severity``.
All downstream consumers MUST read ``severity`` and MUST NOT recompute it.

CVSS ANCHORING
--------------
Every vulnerability type now carries a ``cvss_base`` value anchored to
NVD/FIRST CVSS v3.1 guidance for the worst-case instance of that class,
with AV:N/AC:L/PR:N/UI:N/S:C as the upper bound.  Where severity depends on
runtime evidence (stored vs reflected, unauthenticated vs authenticated,
etc.) ``_adjust_for_evidence()`` applies documented up/down adjustments
before the composite scoring formula runs.

EVIDENCE-BASED ADJUSTMENTS
---------------------------
The following vuln types receive runtime evidence adjustments:
  XSS             stored → +1.5 CVSS, DOM-based → +0.5, self-XSS → −2.0
  SQLI            blind/time-based → −1.0, error-based → −0.5
  SSRF            internal-only (no egress) → −2.0
  LFI             RCE evidence (proc/etc/passwd read) → +2.0
  IDOR            write/delete (not read-only) → +1.0
  OPEN_REDIRECT   used in OAuth flow → +2.0
  INFO_DISCLOSURE stack trace → +1.0, version only → −1.0
  DEBUG           unauthenticated access → +2.0, auth-required → −1.5
  ADMIN_PANEL     unauthenticated → +3.0, auth-required → −2.0
  CORS            allow-credentials=true → +2.0, without credentials → −1.5
  CSRF            SameSite=Lax already → −2.0, sensitive action → +1.0
  FILE_UPLOAD     execution possible → +2.5, stored only → no change
  SSTI            confirmed RCE via template → already Critical
  JWT             alg=none → +2.0, weak secret → +1.0
  SUBDOMAIN_TAKEOVER  claimed → already Critical, unclaimed → no change

In debug mode (env DEBUG=1) every finding dict returned here is wrapped
in a _FrozenSeverityDict that raises AssertionError if any code later
tries to change the ``severity`` or ``cvss`` keys.
"""

import os as _os
import re

from ai_engine.cvss import calculate_cvss

_DEBUG = _os.environ.get("DEBUG", "0") == "1"


class _FrozenSeverityDict(dict):
    """
    Dict subclass that prevents post-creation mutation of severity / cvss.
    Active only when DEBUG=1.  Zero overhead in production.
    """
    _FROZEN_KEYS = frozenset({"severity", "cvss"})

    def __setitem__(self, key, value):
        if key in self._FROZEN_KEYS:
            existing = self.get(key)
            assert existing is None or existing == value, (
                f"[SEVERITY ASSERTION] Attempt to change '{key}' "
                f"from {existing!r} to {value!r}. "
                "Severity must be set exactly once by compute_finding_risk_score()."
            )
        super().__setitem__(key, value)

    def update(self, *args, **kwargs):
        patch = dict(*args, **kwargs)
        for k, v in patch.items():
            self[k] = v


# =========================
# ENDPOINT SENSITIVITY WEIGHTS
# How dangerous is the endpoint itself, regardless of vuln type.
# These values are correct and unchanged.
# =========================

ENDPOINT_SENSITIVITY = {
    # Critical endpoints — compromise = game over
    "admin":      10,
    "superuser":  10,
    "root":       10,
    "debug":       9,
    "internal":    9,
    "staging":     8,
    "dev":         8,
    "backup":      8,

    # High value — auth, payments, data
    "auth":        7,
    "login":       7,
    "oauth":       7,
    "token":       7,
    "payment":     7,
    "billing":     7,
    "checkout":    7,
    "stripe":      7,
    "password":    7,
    "reset":       7,

    # Medium value — user data, APIs
    "api":         5,
    "user":        5,
    "account":     5,
    "profile":     5,
    "upload":      6,
    "file":        5,
    "export":      6,
    "download":    5,

    # Lower value — informational
    "search":      3,
    "contact":     2,
    "about":       1,
    "static":      0,
    "assets":      0,
}


# =========================
# CVSS v3.1 BASE SCORES  (anchored to NVD/FIRST guidance)
# These represent the WORST-CASE instance of each vulnerability class.
# Evidence-based adjustments in _adjust_for_evidence() tune per-instance.
#
# Rationale for each is documented inline and in the audit report.
# =========================

VULN_CVSS_BASE = {
    # ── Critical (9.0–10.0) ────────────────────────────────────────────────
    # RCE: AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H = 10.0
    "RCE":                    10.0,

    # SQLI: AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H = 9.8
    "SQLI":                    9.8,
    "SQL INJECTION":           9.8,

    # SSTI (worst case = RCE): AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H = 10.0
    "SSTI":                   10.0,

    # Subdomain takeover: full origin control → 9.8
    "SUBDOMAIN_TAKEOVER":      9.8,

    # ── High (7.0–8.9) ────────────────────────────────────────────────────
    # XXE: AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:L = 8.6
    "XXE":                     8.6,

    # RFI (arbitrary remote code via include): AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H
    # File inclusion leading to RCE = 9.8, but default (no RCE evidence) = 8.8
    "RFI":                     8.8,

    # Auth bypass: AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N = 9.1
    "AUTH_BYPASS":             9.1,

    # SSRF: AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:L/A:N = 9.3 worst-case (egress to internal)
    # Default: 8.6 (internal pivot confirmed); adjusted down if no egress
    "SSRF":                    8.6,

    # LFI: AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N = 7.5
    # Can reach Critical if /proc/self/environ → RCE chain
    "LFI":                     7.5,

    # PATH_TRAVERSAL: same as LFI family = 7.5
    "PATH_TRAVERSAL":          7.5,

    # IDOR: AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N = 6.5 read-only
    # Write/delete bumps to 8.1 (I:H). Default = 6.5 (conservative)
    "IDOR":                    6.5,

    # Broken access control: AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N = 8.1
    "BROKEN_ACCESS_CONTROL":   8.1,

    # Stored XSS: AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N = 5.4
    # But with session hijack impact → 8.0. Default = 8.0 (persistent impact)
    "STORED_XSS":              8.0,

    # File upload (if execution possible): AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H = 9.9
    # Default without execution evidence: 6.5 (stored only)
    "FILE_UPLOAD":             6.5,

    # Deserialization: AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H = 9.8
    "DESERIALIZATION":         9.8,

    # JWT alg:none: AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N = 9.1
    # Default (weak secret, not alg:none): 7.5
    "JWT":                     7.5,

    # ── Medium (4.0–6.9) ──────────────────────────────────────────────────
    # XSS (reflected, default): AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N = 6.1
    "XSS":                     6.1,

    # Sensitive data exposure: AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N = 7.5
    # But depends heavily on what data. Default = 6.5 (partial exposure)
    "SENSITIVE DATA EXPOSURE":  6.5,

    # CORS (allow-credentials): AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N = 8.2
    # Default (no credentials): 5.4
    "CORS":                    5.4,

    # CSRF: AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N = 6.5
    # Drops if SameSite=Lax present (most modern browsers block it)
    "CSRF":                    6.5,

    # Open redirect: AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N = 6.1
    # Rises to 8.2 if used in OAuth flow (account takeover vector)
    "OPEN_REDIRECT":           6.1,
    "OPEN REDIRECT":           6.1,

    # ── Low (0.1–3.9) ────────────────────────────────────────────────────
    # Information disclosure: AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N = 5.3
    # Stack trace with tech details = 5.3; version only = 3.7
    "INFORMATION DISCLOSURE":  5.3,

    # Debug endpoint (authenticated): AV:N/AC:L/PR:H/UI:N/S:U/C:L/I:N/A:N = 2.7
    # Unauthenticated debug: AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N = 6.5
    "DEBUG":                   2.7,

    # Misconfiguration: highly variable. Conservative default = 5.0
    "MISCONFIGURATION":        5.0,

    # Clickjacking: AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N = 4.3
    "CLICKJACKING":            4.3,

    # Host header injection: AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N = 6.1
    "HOST_HEADER_INJECTION":   6.1,
}

DEFAULT_VULN_CVSS = 4.0   # Conservative default for unknown vuln types

# Severity ranking — used by severity floor logic in compute_finding_risk_score()
SEVERITY_RANK: dict = {
    "Critical": 4,
    "High":     3,
    "Medium":   2,
    "Low":      1,
    "Info":     0,
    "Unknown":  0,
}


# =========================
# VULNERABILITY SEVERITY BASE SCORES
# Pure exploitability weight (0–100), independent of CVSS.
# Revised to align with CVSS v3.1 ordering above.
# =========================

VULN_BASE_WEIGHT = {
    # Critical — direct code execution or full system compromise
    "RCE":                    100,
    "SSTI":                   100,
    "DESERIALIZATION":         98,
    "SUBDOMAIN_TAKEOVER":      97,
    "SQLI":                    95,
    "SQL INJECTION":           95,

    # High — privilege escalation, data exfiltration, auth bypass
    "AUTH_BYPASS":             92,
    "RFI":                     90,
    "XXE":                     88,
    "SSRF":                    82,
    "FILE_UPLOAD":             78,
    "BROKEN_ACCESS_CONTROL":   78,
    "JWT":                     76,
    "LFI":                     75,
    "PATH_TRAVERSAL":          75,
    "IDOR":                    68,
    "STORED_XSS":              70,

    # Medium — user-impacting, requires interaction or partial conditions
    "SENSITIVE DATA EXPOSURE": 65,
    "CORS":                    55,
    "XSS":                     55,
    "CSRF":                    50,
    "OPEN_REDIRECT":           42,
    "OPEN REDIRECT":           42,
    "HOST_HEADER_INJECTION":   40,
    "CLICKJACKING":            35,

    # Low — informational, configuration issues
    "INFORMATION DISCLOSURE":  35,
    "MISCONFIGURATION":        30,
    "DEBUG":                   28,
}

DEFAULT_VULN_WEIGHT = 20


# =========================
# SEVERITY THRESHOLDS
# Composite score (0–100) → severity label.
# Thresholds tightened at top end to reduce Critical over-reporting.
# =========================

SEVERITY_THRESHOLDS = {
    "Critical": 80,  # was 85 — aligns with CVSS 9.0+ reaching this naturally
    "High":     55,  # was 60 — CVSS 7.0–8.9 range
    "Medium":   30,  # was 35 — CVSS 4.0–6.9 range
    "Low":       0,
}


# =========================
# EVIDENCE-BASED CVSS ADJUSTMENTS
# Applied in compute_finding_risk_score() before composite scoring.
# Each function returns a float delta to add to the base CVSS score.
# =========================

def _adjust_for_evidence(vuln_type: str, finding: dict) -> float:
    """
    Return a CVSS delta based on runtime evidence in the finding.

    The delta is added to VULN_CVSS_BASE[vuln_type] before scoring.
    Clipping to [0.1, 10.0] is applied in the caller.

    Evidence fields examined (all optional):
        xss_type          : "stored" | "reflected" | "dom" | "self"
        sqli_type         : "blind" | "time-based" | "error-based" | "union"
        ssrf_egress       : bool — can reach external hosts
        lfi_rce_evidence  : bool — /proc/self/environ or similar read
        idor_write        : bool — write or delete, not read-only
        oauth_redirect    : bool — redirect param used in OAuth flow
        disclosure_type   : "stack_trace" | "version" | "credentials" | "source_code"
        debug_authed      : bool — requires authentication to reach
        admin_authed      : bool — admin panel requires authentication
        cors_credentials  : bool — Access-Control-Allow-Credentials: true
        csrf_samesite_lax : bool — SameSite=Lax or Strict already set
        csrf_sensitive    : bool — action changes password/email/payment
        upload_exec       : bool — uploaded file can be executed
        jwt_alg_none      : bool — algorithm confusion / alg:none
        jwt_weak_secret   : bool — secret cracked / short
        file_write        : bool — traversal can write (not read-only)
    """
    vt = vuln_type.upper().strip()
    delta = 0.0

    if "XSS" in vt or vt == "XSS":
        xss_type = finding.get("xss_type", "").lower()
        if xss_type == "stored":
            delta += 1.5   # persistent, no URL needed: closer to Stored XSS CVSS 8.0
        elif xss_type == "dom":
            delta += 0.5   # requires JS execution context
        elif xss_type == "self":
            delta -= 2.0   # self-XSS: no cross-user impact

    if vt in ("SQLI", "SQL INJECTION"):
        sqli_type = finding.get("sqli_type", "").lower()
        if "blind" in sqli_type or "time" in sqli_type:
            delta -= 1.0   # slower exploitation, AC:H applies
        elif "error" in sqli_type:
            delta -= 0.5   # error-based: confirms vuln but limited exfil

    if vt == "SSRF":
        if not finding.get("ssrf_egress", True):
            delta -= 2.0   # no external egress → internal pivot only, lower impact

    if vt == "LFI":
        if finding.get("lfi_rce_evidence", False):
            delta += 2.0   # log poisoning / proc environ read → RCE chain

    if vt == "PATH_TRAVERSAL":
        if finding.get("file_write", False):
            delta += 1.5   # write-capable traversal is substantially worse

    if vt == "IDOR":
        if finding.get("idor_write", False):
            delta += 1.5   # write/delete: I:H applies (AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H = 8.1)

    if vt in ("OPEN_REDIRECT", "OPEN REDIRECT"):
        if finding.get("oauth_redirect", False):
            delta += 2.0   # redirect_uri in OAuth → account takeover: CVSS ~8.1

    if vt == "INFORMATION DISCLOSURE":
        dtype = finding.get("disclosure_type", "").lower()
        if dtype == "credentials":
            delta += 2.5   # hardcoded credentials: C:H → severity jumps
        elif dtype == "source_code":
            delta += 1.5   # source code disclosure
        elif dtype == "stack_trace":
            delta += 1.0   # tech stack / path information
        elif dtype == "version":
            delta -= 1.0   # version banner only: 3.7 range

    if vt == "DEBUG":
        if not finding.get("debug_authed", True):
            delta += 3.0   # unauthenticated debug endpoint: PR:N → CVSS 6.5+
        else:
            delta -= 0.5   # auth required: PR:H stays

    if vt == "ADMIN_PANEL" or (vt == "MISCONFIGURATION" and "admin" in finding.get("url", "").lower()):
        if not finding.get("admin_authed", True):
            delta += 3.0   # unauthenticated admin: AV:N/PR:N → 9.8 territory
        else:
            delta -= 2.0   # behind auth: much lower risk

    if vt == "CORS":
        if finding.get("cors_credentials", False):
            delta += 2.5   # credentials=true → cross-origin session theft: CVSS 8.2
        else:
            delta -= 1.5   # wildcard without credentials: limited impact

    if vt == "CSRF":
        if finding.get("csrf_samesite_lax", False):
            delta -= 2.0   # SameSite=Lax blocks most CSRF in modern browsers
        if finding.get("csrf_sensitive", False):
            delta += 1.0   # password-change / payment action: I:H

    if vt == "FILE_UPLOAD":
        if finding.get("upload_exec", False):
            delta += 2.5   # execution possible → RCE risk: CVSS 9.9

    if vt == "JWT":
        if finding.get("jwt_alg_none", False):
            delta += 2.0   # alg:none → auth bypass: CVSS 9.1
        elif finding.get("jwt_weak_secret", False):
            delta += 1.0   # crackable HMAC secret

    return delta


# =========================
# HELPER FUNCTIONS
# =========================

def _get_endpoint_score(url: str) -> int:
    """Score how sensitive an endpoint is based on its URL path."""
    url_lower = url.lower()
    score = 0

    for keyword, weight in ENDPOINT_SENSITIVITY.items():
        if keyword in url_lower:
            score = max(score, weight)

    if "?" in url and "=" in url:
        score += 2

    if re.search(r"/v\d+/", url_lower):
        score += 2

    return min(score, 10)


def _get_vuln_weight(vuln_type: str) -> int:
    """Get base weight for a vulnerability type."""
    vuln_upper = vuln_type.strip().upper()

    if vuln_upper in VULN_BASE_WEIGHT:
        return VULN_BASE_WEIGHT[vuln_upper]

    for key, weight in VULN_BASE_WEIGHT.items():
        if key in vuln_upper or vuln_upper in key:
            return weight

    return DEFAULT_VULN_WEIGHT


def _get_vuln_cvss_base(vuln_type: str) -> float:
    """
    Return the CVSS v3.1 base score for a vulnerability class.

    Used when the finding dict does not carry an explicit cvss value.
    This replaces the call to calculate_cvss() for known types, providing
    audited scores rather than AI-estimated ones.
    """
    vuln_upper = vuln_type.strip().upper()

    if vuln_upper in VULN_CVSS_BASE:
        return VULN_CVSS_BASE[vuln_upper]

    for key, score in VULN_CVSS_BASE.items():
        if key in vuln_upper or vuln_upper in key:
            return score

    # Unknown type — fall back to the AI engine
    try:
        result = calculate_cvss(vuln_type)
        return float(result.get("score", DEFAULT_VULN_CVSS))
    except Exception:
        return DEFAULT_VULN_CVSS


def _confidence_multiplier(confidence: int) -> float:
    """
    Convert confidence percentage to a score multiplier.
    Validated findings (90%) carry full weight.
    Unvalidated (50%) carry reduced weight.
    """
    if confidence >= 90:
        return 1.0
    elif confidence >= 75:
        return 0.85
    elif confidence >= 60:
        return 0.70
    elif confidence >= 50:
        return 0.55
    else:
        return 0.40


def _cvss_to_weight(cvss_score: float) -> float:
    """Normalize CVSS score (0–10) into a 0–100 weight."""
    return cvss_score * 10


# =========================
# COMPOSITE RISK SCORER
# =========================

def compute_finding_risk_score(finding: dict) -> dict:
    """
    Compute a composite risk score for a single finding.

    CVSS resolution order:
      1. Explicit ``cvss`` value in the finding dict (scanner-provided)
      2. VULN_CVSS_BASE[vuln_type]  (audited default for this class)
      3. calculate_cvss(vuln_type) from ai_engine  (AI fallback)
      4. DEFAULT_VULN_CVSS = 4.0

    Evidence-based adjustments are applied to the resolved CVSS base
    before it enters the composite formula. Explicit scanner CVSS values
    are NOT adjusted (they already reflect the specific instance).

    Effective type substitution: when evidence changes the logical class
    (e.g. xss_type=stored → STORED_XSS), the weight lookup uses the
    more specific type so the vuln_component reflects actual severity.

    Factors (weighted):
      - CVSS base score + evidence adjustment  (35%)
      - Vulnerability type base weight         (30%)
      - Endpoint sensitivity                   (20%)
      - Validation confidence multiplier       (15%)

    Severity floors (applied after composite):
      - CVSS >= 9.0 and confidence >= 75  → minimum Critical
      - CVSS >= 9.0 and confidence >= 50  → minimum High
      - CVSS >= 7.0 and confidence >= 75  → minimum High
      - Specific class floors: SSTI and SUBDOMAIN_TAKEOVER ≥ conf 50 → Critical
      - CORS with credentials ≥ conf 60 → High

    Returns the finding dict with added keys:
      severity, cvss (effective), risk_score, risk_severity (alias),
      risk_breakdown (includes evidence_delta, effective_type, floor_applied)
    """
    vuln_type  = finding.get("type", "Unknown")
    url        = finding.get("url", "")
    confidence = finding.get("confidence", 50)

    # ── CVSS resolution ────────────────────────────────────────────────────
    explicit_cvss = finding.get("cvss")
    if explicit_cvss:
        cvss_score     = float(explicit_cvss)
        evidence_delta = 0.0
    else:
        cvss_base      = _get_vuln_cvss_base(vuln_type)
        evidence_delta = _adjust_for_evidence(vuln_type, finding)
        cvss_score     = max(0.1, min(10.0, cvss_base + evidence_delta))

    # ── Effective type for weight lookup ───────────────────────────────────
    # When evidence changes the logical class, look up the more specific weight.
    # This ensures the vuln_component reflects the actual exploitability, not
    # just the generic parent type.
    effective_type = vuln_type
    vt_upper = vuln_type.upper().strip()
    xss_type = finding.get("xss_type", "").lower()
    if "XSS" in vt_upper and xss_type == "stored" and vt_upper != "STORED_XSS":
        effective_type = "STORED_XSS"
    elif vt_upper == "FILE_UPLOAD" and finding.get("upload_exec", False):
        # Execution-capable upload is functionally closer to RCE weight-wise
        effective_type = "RCE"
    elif vt_upper == "LFI" and finding.get("lfi_rce_evidence", False):
        effective_type = "RCE"

    # ── Component scores (each 0–100) ─────────────────────────────────────
    cvss_component     = _cvss_to_weight(cvss_score)
    vuln_component     = _get_vuln_weight(effective_type)
    endpoint_component = _get_endpoint_score(url) * 10
    confidence_mult_v  = _confidence_multiplier(confidence)

    # ── Weighted composite ─────────────────────────────────────────────────
    raw_score = (
        cvss_component     * 0.35 +
        vuln_component     * 0.30 +
        endpoint_component * 0.20
    ) * confidence_mult_v

    risk_score = round(min(raw_score, 100), 1)

    # ── Severity from composite ────────────────────────────────────────────
    risk_severity = "Low"
    for level, threshold in SEVERITY_THRESHOLDS.items():
        if risk_score >= threshold:
            risk_severity = level
            break

    # ── Severity floors (CVSS v3.1 / OWASP alignment) ─────────────────────
    # The composite formula can under-rate findings when confidence is low or
    # the endpoint is neutral, even for verifiable Critical-class vulns.
    # These floors prevent systematic under-classification.
    floor_applied = None

    # Class-specific floors — these vulnerability classes are definitionally
    # Critical when found (SSTI = confirmed RCE; subdomain = full origin takeover)
    if vt_upper in ("SSTI", "SUBDOMAIN_TAKEOVER") and confidence >= 50:
        if SEVERITY_RANK.get(risk_severity, 0) < SEVERITY_RANK.get("Critical", 4):
            risk_severity = "Critical"
            floor_applied = f"{vt_upper}_class_floor→Critical"

    # CVSS-based floors: NVD Critical = 9.0+, High = 7.0–8.9
    elif cvss_score >= 9.0:
        if confidence >= 75 and SEVERITY_RANK.get(risk_severity, 0) < SEVERITY_RANK.get("Critical", 4):
            risk_severity = "Critical"
            floor_applied = "cvss≥9.0+conf≥75→Critical"
        elif confidence >= 50 and SEVERITY_RANK.get(risk_severity, 0) < SEVERITY_RANK.get("High", 3):
            risk_severity = "High"
            floor_applied = "cvss≥9.0+conf≥50→High"
    elif cvss_score >= 7.0:
        if confidence >= 75 and SEVERITY_RANK.get(risk_severity, 0) < SEVERITY_RANK.get("High", 3):
            risk_severity = "High"
            floor_applied = "cvss≥7.0+conf≥75→High"

    # CORS with credentials: session theft possible regardless of endpoint neutrality
    if vt_upper == "CORS" and finding.get("cors_credentials", False) and confidence >= 60:
        if SEVERITY_RANK.get(risk_severity, 0) < SEVERITY_RANK.get("High", 3):
            risk_severity = "High"
            floor_applied = "cors_credentials→High"

    # Sync risk_score floor: never let a floored severity contradict the score
    # by a wide margin. Raise score to just above the new threshold if needed.
    floor_min_score = SEVERITY_THRESHOLDS.get(risk_severity, 0)
    if risk_score < floor_min_score:
        risk_score = float(floor_min_score)

    # Build result. ``severity`` is canonical; ``risk_severity`` is a
    # deprecated alias kept for backward compat (scheduled removal v3.0).
    base = {
        **finding,
        "severity":      risk_severity,
        "cvss":          round(cvss_score, 1),
        "risk_score":    risk_score,
        "risk_severity": risk_severity,   # deprecated alias
        "risk_breakdown": {
            "cvss_component":     round(cvss_component, 1),
            "vuln_component":     vuln_component,
            "endpoint_component": round(endpoint_component, 1),
            "confidence_mult":    confidence_mult_v,
            "raw_score":          round(raw_score, 1),
            "evidence_delta":     round(evidence_delta, 2),
            "effective_type":     effective_type,
            "floor_applied":      floor_applied,
        }
    }
    return _FrozenSeverityDict(base) if _DEBUG else base


# =========================
# MAIN PUBLIC FUNCTION
# =========================

def calculate_risk(endpoints: list, alive_hosts: list, findings: list) -> dict:
    """
    Score all findings and bucket them into Critical / High / Medium / Low.

    Args:
        endpoints:   list of endpoint dicts with 'url' key
        alive_hosts: list of live host dicts (used for exposure context)
        findings:    list of finding dicts from recon_core

    Returns:
        {
            "critical": [...urls],
            "high":     [...urls],
            "medium":   [...urls],
            "low":      [...urls],
            "scored_findings": [...full scored dicts],
            "summary": {
                "total", "critical", "high", "medium", "low",
                "top_risk_score", "overall_risk_level", "security_score"
            }
        }
    """
    critical_risk = []
    high_risk     = []
    medium_risk   = []
    low_risk      = []
    scored        = []
    seen_urls     = set()

    for finding in findings:
        if isinstance(finding, tuple):
            vuln_type, url = finding
            finding = {"type": vuln_type, "url": url, "confidence": 50}
        elif not isinstance(finding, dict):
            continue

        url = finding.get("url", "")
        if not url:
            continue

        scored_finding = compute_finding_risk_score(finding)
        scored.append(scored_finding)

        severity   = scored_finding["severity"]
        risk_score = scored_finding["risk_score"]

        dedup_key = (severity, url)
        if dedup_key in seen_urls:
            continue
        seen_urls.add(dedup_key)

        if severity == "Critical":
            critical_risk.append(url)
        elif severity == "High":
            high_risk.append(url)
        elif severity == "Medium":
            medium_risk.append(url)
        else:
            low_risk.append(url)

    scored.sort(key=lambda x: x.get("risk_score", 0), reverse=True)

    total     = len(scored)
    top_score = scored[0]["risk_score"] if scored else 0

    if critical_risk or top_score >= 80:
        overall_level = "CRITICAL"
    elif high_risk or top_score >= 55:
        overall_level = "HIGH"
    elif medium_risk or top_score >= 30:
        overall_level = "MEDIUM"
    else:
        overall_level = "LOW"

    # security_score computed here — single source; downstream reads summary
    _sec = 100
    _sec -= len(critical_risk) * 5
    _sec -= len(high_risk)     * 3
    _sec -= len(medium_risk)   * 1.5
    _sec -= len(low_risk)      * 0.5
    security_score = max(int(_sec), 0)

    summary = {
        "total":              total,
        "critical":           len(critical_risk),
        "high":               len(high_risk),
        "medium":             len(medium_risk),
        "low":                len(low_risk),
        "top_risk_score":     top_score,
        "overall_risk_level": overall_level,
        "security_score":     security_score,
    }

    print(f"\n{'='*50}")
    print(f"  RISK ASSESSMENT SUMMARY")
    print(f"{'='*50}")
    print(f"  Overall Level : {overall_level}")
    print(f"  Top Score     : {top_score}/100")
    print(f"  Critical      : {len(critical_risk)}")
    print(f"  High          : {len(high_risk)}")
    print(f"  Medium        : {len(medium_risk)}")
    print(f"  Low           : {len(low_risk)}")
    print(f"  Total Findings: {total}")
    print(f"{'='*50}\n")

    if scored:
        print("  Top 5 Findings by Risk Score:")
        for f in scored[:5]:
            print(
                f"  [{f['risk_score']:>5.1f}] "
                f"[{f['severity']:<8}] "
                f"{f.get('type', 'Unknown'):<25} "
                f"{f.get('url', '')[:60]}"
            )
        print()

    return {
        "critical":        critical_risk,
        "high":            high_risk,
        "medium":          medium_risk,
        "low":             low_risk,
        "scored_findings": scored,
        "summary":         summary,
    }


# =========================
# QUICK TEST
# =========================
if __name__ == "__main__":

    test_findings = [
        {
            "type": "SQLI",
            "url": "https://example.com/admin/users?id=1",
            "confidence": 90,
            "sqli_type": "union",
        },
        {
            "type": "XSS",
            "url": "https://example.com/search?q=test",
            "confidence": 75,
            "xss_type": "reflected",
        },
        {
            "type": "XSS",
            "url": "https://example.com/comments",
            "confidence": 85,
            "xss_type": "stored",
        },
        {
            "type": "OPEN_REDIRECT",
            "url": "https://example.com/oauth/callback?redirect=http://evil.com",
            "confidence": 90,
            "oauth_redirect": True,
        },
        {
            "type": "INFORMATION DISCLOSURE",
            "url": "https://example.com/about",
            "confidence": 50,
            "disclosure_type": "version",
        },
        {
            "type": "RCE",
            "url": "https://example.com/api/v2/admin/exec",
            "confidence": 50,
        },
        {
            "type": "DEBUG",
            "url": "https://example.com/debug",
            "confidence": 80,
            "debug_authed": False,
        },
        {
            "type": "CORS",
            "url": "https://example.com/api/user",
            "confidence": 75,
            "cors_credentials": True,
        },
    ]

    result = calculate_risk([], [], test_findings)

    print("Scored findings detail:")
    for f in result["scored_findings"]:
        bd = f["risk_breakdown"]
        print(
            f"\n  {f['type']} @ {f['url'][:50]}"
            f"\n    Severity   : {f['severity']}  CVSS={f['cvss']}"
            f"\n    Risk Score : {f['risk_score']}"
            f"\n    Breakdown  : CVSS={bd['cvss_component']} | "
            f"Vuln={bd['vuln_component']} | "
            f"Endpoint={bd['endpoint_component']} | "
            f"Conf={bd['confidence_mult']} | "
            f"EvidenceDelta={bd['evidence_delta']}"
        )
