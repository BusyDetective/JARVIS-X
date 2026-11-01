from utils.logger import highlight
from urllib.parse import urlparse, parse_qs
import re

# ===============================================
# PATTERN DEFINITIONS
# ===============================================
# Each pattern has:
#   keywords   - URL substrings to match (params or path segments)
#   severity   - Critical / High / Medium / Low
#   confidence - Base confidence score (boosted by context)
#   reason     - Human-readable explanation for the finding

PATTERNS = {
    "IDOR": {
        "keywords": [
            "id=", "user_id=", "account_id=", "order_id=",
            "invoice_id=", "profile_id=", "uid=", "pid=",
            "record_id=", "doc_id=", "file_id=", "customer_id="
        ],
        "severity": "High",
        "confidence": 65,
        "reason": "Numeric/user-controlled ID parameter — test for insecure direct object access"
    },
    "SQLi": {
        "keywords": [
            "id=", "user_id=", "item=", "product=", "category=",
            "sort=", "order=", "filter=", "page=", "limit=",
            "offset=", "search=", "keyword=", "query="
        ],
        "severity": "High",
        "confidence": 55,
        "reason": "Parameter commonly injected in SQL queries — test with error and time-based payloads"
    },
    "Open Redirect": {
        "keywords": [
            "redirect=", "url=", "next=", "return=", "returnurl=",
            "goto=", "continue=", "destination=", "forward=",
            "redir=", "redirect_uri=", "callback="
        ],
        "severity": "Medium",
        "confidence": 70,
        "reason": "Redirect parameter — test for open redirect to external domain"
    },
    "LFI / Path Traversal": {
        "keywords": [
            "file=", "path=", "download=", "include=", "template=",
            "page=", "document=", "folder=", "root=", "pg=",
            "style=", "pdf=", "read=", "load="
        ],
        "severity": "High",
        "confidence": 68,
        "reason": "File/path parameter — test for local file inclusion and path traversal"
    },
    "SSRF": {
        "keywords": [
            "url=", "uri=", "endpoint=", "proxy=", "host=",
            "dest=", "target=", "site=", "html=", "source=",
            "fetch=", "request=", "webhook="
        ],
        "severity": "High",
        "confidence": 65,
        "reason": "URL/host parameter — test for server-side request forgery to internal services"
    },
    "XSS": {
        "keywords": [
            "q=", "search=", "query=", "keyword=", "s=",
            "term=", "input=", "text=", "message=", "comment=",
            "name=", "title=", "description=", "content=", "data="
        ],
        "severity": "Medium",
        "confidence": 55,
        "reason": "User-input parameter reflected in response — test for XSS"
    },
    "SSTI": {
        "keywords": [
            "template=", "render=", "view=", "layout=",
            "theme=", "format=", "lang=", "locale="
        ],
        "severity": "Critical",
        "confidence": 60,
        "reason": "Template/render parameter — test for server-side template injection"
    },
    "File Upload": {
        "keywords": [
            "upload", "fileupload", "file_upload", "attach",
            "import", "media", "avatar", "photo", "image",
            "attachment", "document"
        ],
        "severity": "High",
        "confidence": 72,
        "reason": "Upload endpoint — test for unrestricted file upload and RCE via webshell"
    },
    "Admin Panel": {
        "keywords": [
            "admin", "dashboard", "console", "manage", "manager",
            "control", "panel", "backend", "backoffice", "cp",
            "superuser", "staff", "moderator"
        ],
        "severity": "High",
        "confidence": 75,
        "reason": "Administrative endpoint — test for broken access control and auth bypass"
    },
    "Authentication": {
        "keywords": [
            "login", "logout", "signin", "signup", "register",
            "auth", "oauth", "sso", "token", "password",
            "reset", "forgot", "verify", "2fa", "mfa"
        ],
        "severity": "High",
        "confidence": 60,
        "reason": "Authentication endpoint — test for brute force, token leakage, and bypass"
    },
    "API Key / Secret Exposure": {
        "keywords": [
            "api_key=", "apikey=", "key=", "secret=", "token=",
            "access_token=", "auth_token=", "client_secret=",
            "password=", "passwd=", "pwd=", "credential="
        ],
        "severity": "Critical",
        "confidence": 80,
        "reason": "Sensitive credential in URL parameter — likely exposed in logs and referrer headers"
    },
    "Debug / Info Disclosure": {
        "keywords": [
            "debug", "test", "phpinfo", "info.php", ".env",
            "config", "backup", "trace", "log", "error",
            "stacktrace", "diagnostics", "status", "healthcheck"
        ],
        "severity": "Medium",
        "confidence": 70,
        "reason": "Debug/config endpoint — may expose sensitive environment or stack information"
    },
    "GraphQL": {
        "keywords": [
            "graphql", "gql", "__schema", "__type", "introspection"
        ],
        "severity": "Medium",
        "confidence": 65,
        "reason": "GraphQL endpoint — test for introspection, batching attacks, and broken object-level auth"
    },
    "WebSocket": {
        "keywords": [
            "ws://", "wss://", "websocket", "socket.io", "/ws", "/wss"
        ],
        "severity": "Medium",
        "confidence": 55,
        "reason": "WebSocket endpoint — test for hijacking, missing auth, and injection over WS"
    },
}

# Severity ordering for sorting
SEVERITY_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}


# ===============================================
# HELPERS
# ===============================================

def _extract_param_names(url):
    """Return set of lowercased parameter names from URL query string."""
    try:
        parsed = urlparse(url)
        return set(k.lower() for k in parse_qs(parsed.query).keys())
    except Exception:
        return set()


def _has_numeric_value(url, param):
    """Return True if the given param has a numeric value (IDOR signal)."""
    try:
        parsed = urlparse(url)
        qs = parse_qs(parsed.query)
        values = qs.get(param, [])
        return any(re.fullmatch(r'\d+', v) for v in values)
    except Exception:
        return False


def _boost_confidence(vuln_type, url, base_confidence):
    """Apply contextual boosts to confidence score."""
    boost = 0
    url_lower = url.lower()

    if vuln_type == "IDOR":
        # Numeric ID value is a strong IDOR signal
        params = _extract_param_names(url)
        for param in ["id", "user_id", "account_id", "uid"]:
            if param in params and _has_numeric_value(url, param):
                boost += 15
                break

    if vuln_type == "API Key / Secret Exposure":
        # Credentials in URLs are always critical regardless of context
        boost += 10

    if vuln_type in ("LFI / Path Traversal", "SSRF"):
        # Path traversal sequences in value are high signal
        if "../" in url or "%2e%2e" in url_lower or "%2f" in url_lower:
            boost += 20

    if vuln_type == "Admin Panel":
        # Deeper admin paths are more likely real panels
        path_depth = url.count("/")
        if path_depth >= 3:
            boost += 10

    if vuln_type == "File Upload":
        # Presence of multipart or upload in path is a strong signal
        if "multipart" in url_lower or "/upload" in url_lower:
            boost += 12

    return min(base_confidence + boost, 98)


# ===============================================
# CORE DETECTOR
# ===============================================

def detect_vuln_patterns(endpoints):
    """
    Analyze a list of endpoint URLs for vulnerability patterns.

    Args:
        endpoints: list of URL strings, or list of dicts with a 'url' key

    Returns:
        list of finding dicts sorted by severity then confidence
    """
    print(f"\n[+] Analyzing {len(endpoints)} endpoints for vulnerability patterns...\n")

    findings = []
    seen = set()  # (vuln_type, url) deduplication

    for item in endpoints:
        # Accept both raw URL strings and endpoint dicts
        url = item["url"] if isinstance(item, dict) else item

        if not url:
            continue

        url_lower = url.lower()

        for vuln_type, meta in PATTERNS.items():
            for keyword in meta["keywords"]:
                if keyword in url_lower:
                    key = (vuln_type, url)
                    if key in seen:
                        break  # Already recorded this combo, move to next pattern

                    seen.add(key)

                    confidence = _boost_confidence(
                        vuln_type, url, meta["confidence"]
                    )

                    finding = {
                        "type": vuln_type,
                        "url": url,
                        "severity": meta["severity"],
                        "confidence": confidence,
                        "matched_keyword": keyword,
                        "reason": meta["reason"]
                    }

                    findings.append(finding)

                    label = f"[{meta['severity']}] {vuln_type} ({confidence}%) → {url}"
                    highlight(label)
                    break  # One match per pattern per URL is enough

    # Sort: severity first, then confidence descending
    findings.sort(key=lambda f: (
        SEVERITY_ORDER.get(f["severity"], 99),
        -f["confidence"]
    ))

    # Summary
    if findings:
        from collections import Counter
        by_severity = Counter(f["severity"] for f in findings)
        print(f"\n[+] Pattern scan complete: {len(findings)} findings")
        for sev in ["Critical", "High", "Medium", "Low"]:
            if by_severity.get(sev):
                print(f"    {sev}: {by_severity[sev]}")
    else:
        print("[-] No vulnerability patterns detected")

    return findings


# ===============================================
# FILTER HELPERS (for use in report/results)
# ===============================================

def filter_by_severity(findings, severity):
    """Return findings matching a given severity level."""
    return [f for f in findings if f.get("severity") == severity]


def filter_confirmed(findings, min_confidence=70):
    """Return findings above a confidence threshold."""
    return [f for f in findings if f.get("confidence", 0) >= min_confidence]


def summarize(findings):
    """Return a dict with counts per severity."""
    summary = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    for f in findings:
        sev = f.get("severity", "Low")
        if sev in summary:
            summary[sev] += 1
    return summary


# ===============================================
# SELF-TEST
# ===============================================

if __name__ == "__main__":
    test_urls = [
        "https://example.com/profile?user_id=1042",
        "https://example.com/search?q=<script>",
        "https://example.com/redirect?url=https://evil.com",
        "https://example.com/admin/dashboard",
        "https://example.com/api/v1/export?file=../etc/passwd",
        "https://example.com/graphql?query=__schema",
        "https://example.com/upload/avatar",
        "https://example.com/login",
        "https://example.com/debug/phpinfo.php",
        "https://example.com/fetch?url=http://169.254.169.254/metadata",
        "https://example.com/render?template={{7*7}}",
        "https://example.com/api/data?api_key=abc123secret",
    ]

    results = detect_vuln_patterns(test_urls)

    print("\n===== FINDINGS =====")
    for r in results:
        print(
            f"  [{r['severity']}] {r['type']} | "
            f"{r['confidence']}% | "
            f"matched: {r['matched_keyword']} | "
            f"{r['url']}"
        )

    print("\n===== SUMMARY =====")
    print(summarize(results))