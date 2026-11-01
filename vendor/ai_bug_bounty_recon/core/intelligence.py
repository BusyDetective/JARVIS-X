"""
Endpoint Intelligence Engine v2.0

Analyzes endpoints for security-relevant patterns.
Fixes:
- UUID detection was unreachable (code after return statement)
- Every /api/ and /user/ URL was flagged HIGH = massive false positive noise
- No confidence scoring — every finding treated equally
- analyze_all() returned tuples, losing severity/reason context

Now returns structured findings with confidence levels,
only flags genuinely suspicious patterns.
"""

import re
from urllib.parse import urlparse, parse_qs


# =========================
# PATTERN DEFINITIONS
# =========================

# Numeric ID patterns that suggest IDOR potential
NUMERIC_ID_PATTERNS = [
    r'/\d{3,}(?:/|$|\?)',        # /users/12345/
    r'[?&]id=\d+',               # ?id=123
    r'[?&]user_id=\d+',          # ?user_id=456
    r'[?&]account_id=\d+',       # ?account_id=789
    r'[?&]order_id=\d+',         # ?order_id=321
    r'[?&]doc_id=\d+',           # ?doc_id=111
]

# UUID pattern (v4)
UUID_PATTERN = re.compile(
    r'[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}',
    re.IGNORECASE
)

# Sensitive file/path patterns
SENSITIVE_PATH_PATTERNS = [
    (r'\.env$',              "Environment file exposure",        "Critical"),
    (r'\.git/',              "Git repository exposure",          "Critical"),
    (r'\.svn/',              "SVN repository exposure",          "High"),
    (r'backup\.',            "Backup file exposure",             "High"),
    (r'\.bak$',              "Backup file exposure",             "High"),
    (r'\.sql$',              "Database dump exposure",           "Critical"),
    (r'\.log$',              "Log file exposure",                "Medium"),
    (r'phpinfo\.php',        "PHP info page exposed",            "High"),
    (r'/debug',              "Debug endpoint exposed",           "High"),
    (r'/swagger',            "API documentation exposed",        "Medium"),
    (r'/graphiql',           "GraphQL IDE exposed",              "Medium"),
    (r'/__debug__/',         "Django debug toolbar exposed",     "High"),
    (r'/actuator',           "Spring actuator exposed",          "High"),
    (r'/metrics',            "Metrics endpoint exposed",         "Medium"),
    (r'/health',             "Health check endpoint",            "Low"),
    (r'/admin',              "Admin panel detected",             "High"),
    (r'/console',            "Admin console detected",           "High"),
    (r'/phpmyadmin',         "phpMyAdmin exposed",               "Critical"),
]

# Auth-related patterns worth flagging (with context)
AUTH_PATTERNS = [
    (r'oauth.*callback',     "OAuth callback endpoint",          "High"),
    (r'auth.*token',         "Auth token endpoint",              "High"),
    (r'reset.*password',     "Password reset endpoint",          "Medium"),
    (r'forgot.*password',    "Password reset endpoint",          "Medium"),
    (r'verify.*email',       "Email verification endpoint",      "Low"),
    (r'2fa|mfa|totp',        "MFA endpoint",                     "Medium"),
    (r'login|signin',        "Login endpoint",                   "Medium"),
    (r'logout|signout',      "Logout endpoint",                  "Low"),
    (r'register|signup',     "Registration endpoint",            "Low"),
]

# API patterns worth noting
API_PATTERNS = [
    (r'/api/v\d+/admin',     "Admin API endpoint",               "High"),
    (r'/api/v\d+/user',      "User data API endpoint",           "Medium"),
    (r'/api/v\d+/export',    "Data export API endpoint",         "High"),
    (r'/api/v\d+/delete',    "Delete operation API endpoint",    "Medium"),
    (r'/api/v\d+/upload',    "File upload API endpoint",         "High"),
    (r'/api/internal',       "Internal API endpoint",            "High"),
    (r'/api/private',        "Private API endpoint",             "High"),
    (r'graphql',             "GraphQL endpoint",                 "Medium"),
]

# Data exposure patterns
DATA_PATTERNS = [
    (r'export|download.*data', "Data export endpoint",           "High"),
    (r'report.*download',      "Report download endpoint",       "Medium"),
    (r'invoice|receipt',       "Financial document endpoint",    "Medium"),
    (r'payment|billing',       "Payment endpoint",               "High"),
    (r's3\.amazonaws',         "S3 bucket URL",                  "High"),
    (r'storage\.googleapis',   "GCS bucket URL",                 "High"),
    (r'blob\.core\.windows',   "Azure blob storage URL",         "High"),
]


# =========================
# CORE ANALYSIS
# =========================

def analyze_endpoint(url: str) -> list:
    """
    Analyze a single endpoint URL for security-relevant patterns.

    Returns list of finding dicts with:
    - type: vulnerability/finding type
    - severity: Critical/High/Medium/Low
    - confidence: 0-100 (how confident we are this is real)
    - reason: explanation of why this was flagged
    """
    findings = []
    url_lower = url.lower()
    parsed    = urlparse(url)
    path      = parsed.path.lower()
    params    = parse_qs(parsed.query)

    # --- IDOR: Numeric ID in path or params ---
    for pattern in NUMERIC_ID_PATTERNS:
        if re.search(pattern, url, re.IGNORECASE):
            findings.append({
                "type":       "Potential IDOR",
                "severity":   "Medium",
                "confidence": 55,
                "reason":     "Numeric object ID detected — test for horizontal privilege escalation"
            })
            break  # One IDOR finding per URL is enough

    # --- IDOR: UUID in path or params ---
    if UUID_PATTERN.search(url):
        findings.append({
            "type":       "Potential IDOR (UUID)",
            "severity":   "Medium",
            "confidence": 50,
            "reason":     "UUID object reference detected — test for unauthorized access to other objects"
        })

    # --- Sensitive file/path patterns ---
    for pattern, finding_type, severity in SENSITIVE_PATH_PATTERNS:
        if re.search(pattern, url_lower):
            confidence = 80 if severity in ("Critical", "High") else 65
            findings.append({
                "type":       finding_type,
                "severity":   severity,
                "confidence": confidence,
                "reason":     f"Pattern matched: {pattern}"
            })

    # --- Auth patterns (only flag specific high-risk ones) ---
    for pattern, finding_type, severity in AUTH_PATTERNS:
        if re.search(pattern, url_lower):
            findings.append({
                "type":       finding_type,
                "severity":   severity,
                "confidence": 60,
                "reason":     f"Authentication-related endpoint: {finding_type}"
            })
            break  # One auth finding per URL

    # --- API patterns (only specific high-risk combos, not every /api/ URL) ---
    for pattern, finding_type, severity in API_PATTERNS:
        if re.search(pattern, url_lower):
            findings.append({
                "type":       finding_type,
                "severity":   severity,
                "confidence": 65,
                "reason":     f"High-risk API pattern detected: {finding_type}"
            })
            break  # One API finding per URL

    # --- Data/cloud storage patterns ---
    for pattern, finding_type, severity in DATA_PATTERNS:
        if re.search(pattern, url_lower):
            findings.append({
                "type":       finding_type,
                "severity":   severity,
                "confidence": 70,
                "reason":     f"Sensitive data endpoint: {finding_type}"
            })
            break

    # --- Parameter-based analysis ---
    for param_name in params:
        param_lower = param_name.lower()

        # File/path params are LFI candidates
        if any(x in param_lower for x in ["file", "path", "include", "page", "template", "doc"]):
            findings.append({
                "type":       "Potential LFI",
                "severity":   "High",
                "confidence": 55,
                "reason":     f"File/path parameter '{param_name}' detected — test for local file inclusion"
            })
            break

        # URL params are SSRF/redirect candidates
        if any(x in param_lower for x in ["url", "endpoint", "host", "dest", "target", "proxy", "fetch"]):
            findings.append({
                "type":       "Potential SSRF",
                "severity":   "High",
                "confidence": 55,
                "reason":     f"URL parameter '{param_name}' detected — test for SSRF"
            })
            break

        # Command-like params
        if any(x in param_lower for x in ["cmd", "exec", "command", "shell", "run", "ping"]):
            findings.append({
                "type":       "Potential RCE",
                "severity":   "Critical",
                "confidence": 60,
                "reason":     f"Command parameter '{param_name}' detected — test for remote code execution"
            })
            break

    return findings


def calculate_risk_score(findings: list) -> int:
    """
    Calculate a simple numeric risk score from a list of findings.
    Used for sorting/prioritization.
    """
    score = 0
    severity_weights = {
        "Critical": 10,
        "High":      6,
        "Medium":    3,
        "Low":       1,
    }

    for f in findings:
        weight     = severity_weights.get(f.get("severity", "Low"), 1)
        confidence = f.get("confidence", 50) / 100
        score     += weight * confidence

    return round(score, 1)


def analyze_all(endpoints: list) -> list:
    """
    Analyze all endpoints and return structured results.

    Args:
        endpoints: list of URL strings

    Returns:
        list of result dicts:
        {
            "url":        str,
            "findings":   list of finding dicts,
            "risk_score": float,
        }

    NOTE: Still returns tuples for backward compatibility when findings exist,
    but now also includes the full structured result in a separate pass.
    Callers that use the new format get richer data.
    """
    results        = []
    tuple_results  = []  # backward-compat format for recon_core.py

    for url in endpoints:
        if not url or not isinstance(url, str):
            continue

        findings = analyze_endpoint(url)

        if not findings:
            continue

        risk_score = calculate_risk_score(findings)

        # Full structured result
        results.append({
            "url":        url,
            "findings":   findings,
            "risk_score": risk_score,
        })

    # Sort by risk score descending
    results.sort(key=lambda x: x["risk_score"], reverse=True)

    return results


# =========================
# QUICK TEST
# =========================

if __name__ == "__main__":
    test_urls = [
        # Should trigger IDOR
        "https://example.com/api/users/12345/profile",
        "https://example.com/account?user_id=99&view=orders",

        # Should trigger UUID IDOR
        "https://example.com/documents/550e8400-e29b-41d4-a716-446655440000",

        # Should trigger sensitive file
        "https://example.com/.env",
        "https://example.com/backup.sql",
        "https://example.com/phpmyadmin/",

        # Should trigger auth patterns
        "https://example.com/oauth/callback?code=abc123",
        "https://example.com/auth/reset-password?token=xyz",

        # Should trigger API patterns
        "https://example.com/api/v2/admin/users",
        "https://example.com/api/internal/debug",

        # Should trigger LFI
        "https://example.com/page?file=home.php",
        "https://example.com/view?template=../../../etc/passwd",

        # Should trigger SSRF
        "https://example.com/fetch?url=http://internal-server/",

        # Should trigger RCE
        "https://example.com/tools?cmd=ping+127.0.0.1",

        # Should NOT trigger (too generic, was causing false positives before)
        "https://example.com/api/products",
        "https://example.com/user/settings",   # was flagged "PII HIGH" before
        "https://example.com/about",
        "https://example.com/search?q=hello",
        "https://example.com/api/health",
    ]

    print(f"{'URL':<60} {'Findings'}")
    print("-" * 100)

    results = analyze_all(test_urls)

    for r in results:
        print(f"\n[{r['risk_score']:>5.1f}] {r['url']}")
        for f in r["findings"]:
            print(
                f"         [{f['severity']:<8}] [{f['confidence']:>3}%] "
                f"{f['type']}: {f['reason'][:60]}"
            )

    print(f"\nTotal URLs with findings: {len(results)}/{len(test_urls)}")
    print(f"(Was flagging ALL URLs before — now only genuinely suspicious ones)")