"""
CVSS v3.1 Calculator
Real scoring based on attack vector, complexity, privileges, user interaction,
scope, and impact metrics — not a static dictionary.

Reference: https://www.first.org/cvss/v3.1/specification-document
"""

import math


# =========================
# CVSS v3.1 METRIC WEIGHTS
# =========================

ATTACK_VECTOR = {
    "NETWORK":   0.85,
    "ADJACENT":  0.62,
    "LOCAL":     0.55,
    "PHYSICAL":  0.20,
}

ATTACK_COMPLEXITY = {
    "LOW":  0.77,
    "HIGH": 0.44,
}

PRIVILEGES_REQUIRED_NO_SCOPE_CHANGE = {
    "NONE": 0.85,
    "LOW":  0.62,
    "HIGH": 0.27,
}

PRIVILEGES_REQUIRED_SCOPE_CHANGE = {
    "NONE": 0.85,
    "LOW":  0.50,
    "HIGH": 0.50,
}

USER_INTERACTION = {
    "NONE":     0.85,
    "REQUIRED": 0.62,
}

IMPACT = {
    "NONE":    0.00,
    "LOW":     0.22,
    "HIGH":    0.56,
}


# =========================
# VULNERABILITY PROFILES
# Each entry: (AV, AC, PR, UI, Scope, C, I, A)
# AV: Network/Adjacent/Local/Physical
# AC: Low/High
# PR: None/Low/High
# UI: None/Required
# S:  Changed/Unchanged
# C/I/A: None/Low/High (Confidentiality/Integrity/Availability)
# =========================

VULN_PROFILES = {
    "RCE": {
        "AV": "NETWORK", "AC": "LOW", "PR": "NONE",
        "UI": "NONE", "S": "CHANGED",
        "C": "HIGH", "I": "HIGH", "A": "HIGH",
        "description": "Remote Code Execution"
    },
    "SQLI": {
        "AV": "NETWORK", "AC": "LOW", "PR": "NONE",
        "UI": "NONE", "S": "UNCHANGED",
        "C": "HIGH", "I": "HIGH", "A": "LOW",
        "description": "SQL Injection"
    },
    "XSS": {
        "AV": "NETWORK", "AC": "LOW", "PR": "NONE",
        "UI": "REQUIRED", "S": "CHANGED",
        "C": "LOW", "I": "LOW", "A": "NONE",
        "description": "Cross-Site Scripting"
    },
    "STORED_XSS": {
        "AV": "NETWORK", "AC": "LOW", "PR": "LOW",
        "UI": "NONE", "S": "CHANGED",
        "C": "LOW", "I": "LOW", "A": "NONE",
        "description": "Stored XSS"
    },
    "OPEN_REDIRECT": {
        "AV": "NETWORK", "AC": "LOW", "PR": "NONE",
        "UI": "REQUIRED", "S": "UNCHANGED",
        "C": "LOW", "I": "LOW", "A": "NONE",
        "description": "Open Redirect"
    },
    "SSRF": {
        "AV": "NETWORK", "AC": "LOW", "PR": "LOW",
        "UI": "NONE", "S": "CHANGED",
        "C": "HIGH", "I": "LOW", "A": "NONE",
        "description": "Server-Side Request Forgery"
    },
    "LFI": {
        "AV": "NETWORK", "AC": "LOW", "PR": "NONE",
        "UI": "NONE", "S": "UNCHANGED",
        "C": "HIGH", "I": "NONE", "A": "NONE",
        "description": "Local File Inclusion"
    },
    "RFI": {
        "AV": "NETWORK", "AC": "LOW", "PR": "NONE",
        "UI": "NONE", "S": "CHANGED",
        "C": "HIGH", "I": "HIGH", "A": "HIGH",
        "description": "Remote File Inclusion"
    },
    "IDOR": {
        "AV": "NETWORK", "AC": "LOW", "PR": "LOW",
        "UI": "NONE", "S": "UNCHANGED",
        "C": "HIGH", "I": "LOW", "A": "NONE",
        "description": "Insecure Direct Object Reference"
    },
    "CSRF": {
        "AV": "NETWORK", "AC": "LOW", "PR": "NONE",
        "UI": "REQUIRED", "S": "UNCHANGED",
        "C": "NONE", "I": "LOW", "A": "NONE",
        "description": "Cross-Site Request Forgery"
    },
    "XXE": {
        "AV": "NETWORK", "AC": "LOW", "PR": "NONE",
        "UI": "NONE", "S": "UNCHANGED",
        "C": "HIGH", "I": "NONE", "A": "LOW",
        "description": "XML External Entity"
    },
    "PATH_TRAVERSAL": {
        "AV": "NETWORK", "AC": "LOW", "PR": "NONE",
        "UI": "NONE", "S": "UNCHANGED",
        "C": "HIGH", "I": "NONE", "A": "NONE",
        "description": "Path Traversal"
    },
    "INFORMATION DISCLOSURE": {
        "AV": "NETWORK", "AC": "LOW", "PR": "NONE",
        "UI": "NONE", "S": "UNCHANGED",
        "C": "LOW", "I": "NONE", "A": "NONE",
        "description": "Information Disclosure"
    },
    "DEBUG": {
        "AV": "NETWORK", "AC": "LOW", "PR": "NONE",
        "UI": "NONE", "S": "UNCHANGED",
        "C": "LOW", "I": "NONE", "A": "NONE",
        "description": "Debug/Dev Endpoint Exposed"
    },
    "SENSITIVE DATA EXPOSURE": {
        "AV": "NETWORK", "AC": "LOW", "PR": "NONE",
        "UI": "NONE", "S": "UNCHANGED",
        "C": "HIGH", "I": "NONE", "A": "NONE",
        "description": "Sensitive Data Exposure"
    },
    "AUTH_BYPASS": {
        "AV": "NETWORK", "AC": "LOW", "PR": "NONE",
        "UI": "NONE", "S": "UNCHANGED",
        "C": "HIGH", "I": "HIGH", "A": "NONE",
        "description": "Authentication Bypass"
    },
    "BROKEN_ACCESS_CONTROL": {
        "AV": "NETWORK", "AC": "LOW", "PR": "LOW",
        "UI": "NONE", "S": "UNCHANGED",
        "C": "HIGH", "I": "LOW", "A": "NONE",
        "description": "Broken Access Control"
    },
}

# Fallback for unknown vuln types
DEFAULT_PROFILE = {
    "AV": "NETWORK", "AC": "LOW", "PR": "NONE",
    "UI": "NONE", "S": "UNCHANGED",
    "C": "LOW", "I": "NONE", "A": "NONE",
    "description": "Unknown Vulnerability"
}


def _iss(c, i, a):
    """Impact Sub-Score"""
    return 1 - (1 - IMPACT[c]) * (1 - IMPACT[i]) * (1 - IMPACT[a])


def _compute_score(profile):
    """
    Compute CVSS v3.1 base score from a profile dict.
    Returns (score, severity, vector_string)
    """
    av = profile["AV"]
    ac = profile["AC"]
    pr = profile["PR"]
    ui = profile["UI"]
    s  = profile["S"]
    c  = profile["C"]
    i  = profile["I"]
    a  = profile["A"]

    # Scope affects PR weight
    if s == "CHANGED":
        pr_weight = PRIVILEGES_REQUIRED_SCOPE_CHANGE[pr]
    else:
        pr_weight = PRIVILEGES_REQUIRED_NO_SCOPE_CHANGE[pr]

    exploitability = (
        8.22
        * ATTACK_VECTOR[av]
        * ATTACK_COMPLEXITY[ac]
        * pr_weight
        * USER_INTERACTION[ui]
    )

    iss = _iss(c, i, a)

    if iss == 0:
        impact = 0.0
    elif s == "UNCHANGED":
        impact = 6.42 * iss
    else:
        impact = 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)

    if impact <= 0:
        base_score = 0.0
    else:
        raw = min(impact + exploitability, 10)
        # Round up to nearest 0.1
        base_score = math.ceil(raw * 10) / 10

    # Severity mapping (CVSS v3.1 spec)
    if base_score == 0.0:
        severity = "None"
    elif base_score < 4.0:
        severity = "Low"
    elif base_score < 7.0:
        severity = "Medium"
    elif base_score < 9.0:
        severity = "High"
    else:
        severity = "Critical"

    # Build vector string
    av_s  = av[0]          # N/A/L/P
    ac_s  = ac[0]          # L/H
    pr_s  = pr[0]          # N/L/H
    ui_s  = ui[0]          # N/R
    s_s   = s[0]           # U/C
    c_s   = c[0]           # N/L/H
    i_s   = i[0]
    a_s   = a[0]

    vector = (
        f"CVSS:3.1/AV:{av_s}/AC:{ac_s}/PR:{pr_s}"
        f"/UI:{ui_s}/S:{s_s}/C:{c_s}/I:{i_s}/A:{a_s}"
    )

    return base_score, severity, vector


def _match_profile(vuln_type: str) -> dict:
    """Find the best matching profile for a given vulnerability type string."""
    vuln_upper = vuln_type.strip().upper()

    # Exact match first
    if vuln_upper in VULN_PROFILES:
        return VULN_PROFILES[vuln_upper]

    # Partial match
    for key, profile in VULN_PROFILES.items():
        if key in vuln_upper or vuln_upper in key:
            return profile

    return DEFAULT_PROFILE


# =========================
# PUBLIC API
# =========================

def calculate_cvss(vuln_type: str) -> dict:
    """
    Calculate CVSS v3.1 score for a given vulnerability type.

    Returns:
        {
            "score":       float,   e.g. 8.8
            "severity":    str,     e.g. "High"
            "vector":      str,     e.g. "CVSS:3.1/AV:N/AC:L/..."
            "description": str,     human-readable vuln name
        }
    """
    profile = _match_profile(vuln_type)
    score, severity, vector = _compute_score(profile)

    return {
        "score":       score,
        "severity":    severity,
        "vector":      vector,
        "description": profile.get("description", vuln_type)
    }


def calculate_cvss_custom(
    av="NETWORK", ac="LOW", pr="NONE",
    ui="NONE", s="UNCHANGED",
    c="LOW", i="NONE", a="NONE"
) -> dict:
    """
    Calculate CVSS v3.1 from raw metric values directly.
    Useful for custom findings where you know the exact metrics.

    AV:  NETWORK | ADJACENT | LOCAL | PHYSICAL
    AC:  LOW | HIGH
    PR:  NONE | LOW | HIGH
    UI:  NONE | REQUIRED
    S:   UNCHANGED | CHANGED
    C/I/A: NONE | LOW | HIGH
    """
    profile = {
        "AV": av, "AC": ac, "PR": pr,
        "UI": ui, "S": s,
        "C": c, "I": i, "A": a,
        "description": "Custom"
    }
    score, severity, vector = _compute_score(profile)
    return {
        "score":       score,
        "severity":    severity,
        "vector":      vector,
        "description": "Custom"
    }


def get_all_scores() -> dict:
    """Returns CVSS scores for all known vulnerability types. Useful for reports."""
    return {
        name: calculate_cvss(name)
        for name in VULN_PROFILES
    }


# =========================
# QUICK TEST
# =========================
if __name__ == "__main__":
    test_vulns = [
        "RCE", "SQLI", "XSS", "SSRF",
        "OPEN_REDIRECT", "IDOR", "LFI",
        "INFORMATION DISCLOSURE", "DEBUG",
        "CSRF", "AUTH_BYPASS", "unknown_vuln"
    ]

    print(f"{'Vulnerability':<25} {'Score':>6}  {'Severity':<10}  Vector")
    print("-" * 90)

    for v in test_vulns:
        result = calculate_cvss(v)
        print(
            f"{v:<25} {result['score']:>6.1f}  "
            f"{result['severity']:<10}  {result['vector']}"
        )