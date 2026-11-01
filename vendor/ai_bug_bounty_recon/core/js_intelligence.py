import requests
import re
import urllib3
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Lock

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/120.0.0.0 Safari/537.36"
    )
}

# ===============================================
# PATTERN LIBRARY
# Each entry: (pattern, severity, reason)
# ===============================================

PATTERNS = {
    # ── Secrets & Credentials ─────────────────
    "AWS Access Key": (
        r'(?<![A-Z0-9])(AKIA[0-9A-Z]{16})(?![A-Z0-9])',
        "Critical",
        "AWS access key ID — immediately rotatable"
    ),
    "AWS Secret Key": (
        r'(?i)aws[_\-\s]?secret[_\-\s]?(?:access[_\-\s]?)?key[\'"\s:=]+([A-Za-z0-9/+=]{40})',
        "Critical",
        "AWS secret access key"
    ),
    "Google API Key": (
        r'AIza[0-9A-Za-z\-_]{35}',
        "Critical",
        "Google API key"
    ),
    "Generic API Key": (
        r'(?i)(?:api[_\-]?key|apikey)[\'"\s:=]+[\'"]([A-Za-z0-9_\-]{16,64})[\'"]',
        "High",
        "Generic API key in source"
    ),
    "Bearer Token": (
        r'(?i)bearer\s+([A-Za-z0-9\-\._~\+\/]{20,}=*)',
        "Critical",
        "Bearer token hardcoded in JS"
    ),
    "JWT Token": (
        r'eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+',
        "Critical",
        "JWT token found in JS source"
    ),
    "Private Key": (
        r'-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----',
        "Critical",
        "Private key embedded in JS"
    ),
    "Generic Secret": (
        r'(?i)(?:secret|client_secret|app_secret)[\'"\s:=]+[\'"]([A-Za-z0-9_\-]{16,})[\'"]',
        "High",
        "Hardcoded secret value"
    ),
    "Password in Source": (
        r'(?i)(?:password|passwd|pwd)[\'"\s:=]+[\'"]([^\'"\s]{6,})[\'"]',
        "High",
        "Hardcoded password"
    ),
    "Slack Token": (
        r'xox[baprs]-[0-9A-Za-z\-]{10,48}',
        "Critical",
        "Slack API token"
    ),
    "GitHub Token": (
        r'gh[pousr]_[A-Za-z0-9]{36,}',
        "Critical",
        "GitHub personal access token"
    ),
    "Stripe Key": (
        r'(?:sk|pk)_(?:live|test)_[A-Za-z0-9]{24,}',
        "Critical",
        "Stripe API key"
    ),
    "SendGrid Key": (
        r'SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}',
        "Critical",
        "SendGrid API key"
    ),
    "Twilio Key": (
        r'SK[0-9a-fA-F]{32}',
        "High",
        "Twilio API key"
    ),
    "Firebase URL": (
        r'https://[a-z0-9\-]+\.firebaseio\.com',
        "High",
        "Firebase database URL — test for open access"
    ),
    "S3 Bucket": (
        r's3\.amazonaws\.com/([A-Za-z0-9_\-\.]+)',
        "High",
        "S3 bucket reference — test for public access"
    ),

    # ── Endpoints & URLs ──────────────────────
    "API Endpoint": (
        r'[\'"`](\/?api\/v?[0-9]*\/[A-Za-z0-9_\-\/?=&\.]+)[\'"`]',
        "Medium",
        "Internal API endpoint"
    ),
    "GraphQL Endpoint": (
        r'[\'"`](\/graphql[A-Za-z0-9_\-\/?=&\.]*)[\'"`]',
        "High",
        "GraphQL endpoint — test for introspection"
    ),
    "Internal Path": (
        r'[\'"`](\/(?:admin|internal|dashboard|private|secret|backend|superuser)[A-Za-z0-9_\-\/]*)[\'"`]',
        "High",
        "Sensitive internal path"
    ),
    "Hardcoded URL": (
        r'(?:https?:\/\/)[a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,}(?:\/[A-Za-z0-9_\-\/?=&\.#]*)?',
        "Low",
        "Hardcoded URL reference"
    ),
    "WebSocket URL": (
        r'wss?:\/\/[^\'">\s]+',
        "Medium",
        "WebSocket endpoint"
    ),

    # ── HTTP Calls ────────────────────────────
    "Fetch Call": (
        r'fetch\(\s*[\'"`]([^\'"` ]+)[\'"`]',
        "Medium",
        "fetch() call — discovered endpoint"
    ),
    "Axios Call": (
        r'axios\.(?:get|post|put|patch|delete)\(\s*[\'"`]([^\'"` ]+)[\'"`]',
        "Medium",
        "Axios HTTP call — discovered endpoint"
    ),
    "XHR Call": (
        r'\.open\(\s*[\'"`](?:GET|POST|PUT|DELETE|PATCH)[\'"`]\s*,\s*[\'"`]([^\'"` ]+)[\'"`]',
        "Medium",
        "XHR call — discovered endpoint"
    ),
    "jQuery AJAX": (
        r'\$\.(?:ajax|get|post)\(\s*[\'"`]([^\'"` ]+)[\'"`]',
        "Medium",
        "jQuery AJAX call — discovered endpoint"
    ),

    # ── Debug / Info Disclosure ───────────────
    "Console Log Leak": (
        r'console\.(?:log|warn|error|debug)\s*\(\s*[\'"`]([^\'"` ]{20,})[\'"`]',
        "Low",
        "console.log with potentially sensitive string"
    ),
    "Hardcoded IP": (
        r'\b(?:10\.|192\.168\.|172\.(?:1[6-9]|2[0-9]|3[01])\.|127\.)\d{1,3}\.\d{1,3}\b',
        "Medium",
        "Private/internal IP address hardcoded"
    ),
    "Debug Flag": (
        r'(?i)(?:debug|debugMode|isDev|isDebug|devMode)\s*[:=]\s*true',
        "Medium",
        "Debug mode enabled in source"
    ),
    "TODO / FIXME": (
        r'(?i)(?:TODO|FIXME|HACK|XXX|BUG)\s*:?\s*(.{10,80})',
        "Low",
        "Developer comment with TODO/FIXME"
    ),
    "Source Map": (
        r'\/\/[#@]\s*sourceMappingURL\s*=\s*([^\s]+\.map)',
        "Low",
        "Source map reference — may expose original source"
    ),

    # ── Dangerous Patterns ────────────────────
    "eval() Usage": (
        r'\beval\s*\(',
        "High",
        "eval() usage — potential XSS / code injection vector"
    ),
    "document.write": (
        r'document\.write\s*\(',
        "Medium",
        "document.write() — potential DOM XSS"
    ),
    "innerHTML Assignment": (
        r'\.innerHTML\s*=\s*(?!["\'`]\s*["\'`])',
        "Medium",
        "innerHTML assignment — potential DOM XSS"
    ),
    "postMessage": (
        r'postMessage\s*\(',
        "Medium",
        "postMessage usage — test for cross-origin data leakage"
    ),
    "localStorage Secret": (
        r'localStorage\.setItem\s*\(\s*[\'"`]([^\'"` ]*(?:token|key|secret|auth|pass)[^\'"` ]*)[\'"`]',
        "High",
        "Sensitive data stored in localStorage"
    ),
    "CORS Wildcard": (
        r'[\'"`]\*[\'"`]\s*,?\s*(?:Access-Control|CORS|origin)',
        "High",
        "CORS wildcard origin detected"
    ),
}

# Values to skip — too generic to be useful
NOISE_VALUES = {
    "", "/", "//", "http://", "https://",
    "null", "undefined", "true", "false",
    "/api/", "/api/v1/", "/api/v2/",
}

# Min length for a match to be worth reporting
MIN_VALUE_LEN = 4

# Severity ordering
SEVERITY_RANK = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1}


# ===============================================
# HELPERS
# ===============================================

def _get_context(content, match_str, window=60):
    """Return a short snippet of surrounding source code for context."""
    try:
        idx = content.find(match_str)
        if idx == -1:
            return ""
        start = max(0, idx - window)
        end   = min(len(content), idx + len(match_str) + window)
        snippet = content[start:end].replace("\n", " ").replace("\r", "").strip()
        return snippet[:200]
    except Exception:
        return ""


def _is_noise(value):
    """Return True if the matched value is too generic to report."""
    v = value.strip().strip("'\"/`")
    if not v or len(v) < MIN_VALUE_LEN:
        return True
    if v in NOISE_VALUES:
        return True
    # Skip pure numeric strings
    if v.isdigit():
        return True
    # Skip very common framework internals
    if v.startswith("//") and "." not in v:
        return True
    return False


# ===============================================
# SINGLE FILE ANALYZER
# ===============================================

def _analyze(js_url, global_seen, seen_lock):
    """
    Download and analyze a single JS file.
    Returns list of finding dicts.
    """
    local_results = []

    try:
        res = requests.get(js_url, headers=HEADERS, timeout=8, verify=False)

        if res.status_code != 200:
            return local_results

        content_type = res.headers.get("Content-Type", "")
        if "html" in content_type and "<html" in res.text[:500].lower():
            return local_results  # Got an HTML page, not a JS file

        content = res.text

        for pattern_name, (pattern, severity, reason) in PATTERNS.items():
            try:
                matches = re.findall(pattern, content, re.IGNORECASE)

                for match in matches:
                    # Flatten tuple matches
                    value = match if isinstance(match, str) else (match[0] if match else "")
                    value = value.strip()

                    if _is_noise(value):
                        continue

                    # Thread-safe global deduplication
                    key = (pattern_name, value)
                    with seen_lock:
                        if key in global_seen:
                            continue
                        global_seen.add(key)

                    context = _get_context(content, value)

                    local_results.append({
                        "type":     pattern_name,
                        "value":    value,
                        "severity": severity,
                        "reason":   reason,
                        "source":   js_url,
                        "context":  context,
                    })

            except re.error:
                continue

    except requests.exceptions.Timeout:
        pass
    except Exception:
        pass

    return local_results


# ===============================================
# MAIN ENTRY POINT
# ===============================================

def analyze_js_files(js_files, max_workers=20, limit=100):
    """
    Analyze JavaScript files for secrets, endpoints, and dangerous patterns.

    Args:
        js_files:    list of JS URLs to analyze
        max_workers: thread pool size
        limit:       max number of JS files to process

    Returns:
        list of finding dicts sorted by severity descending
    """
    if not js_files:
        return []

    targets = list(dict.fromkeys(js_files))[:limit]  # Dedupe + cap
    print(f"[+] Analyzing {len(targets)} JavaScript files ({len(PATTERNS)} patterns)...")

    global_seen = set()
    seen_lock   = Lock()
    all_results = []

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {
            executor.submit(_analyze, js_url, global_seen, seen_lock): js_url
            for js_url in targets
        }

        for future in as_completed(futures):
            try:
                results = future.result()
                all_results.extend(results)
            except Exception as e:
                print(f"[-] JS analysis error: {e}")

    # Sort: severity descending
    all_results.sort(key=lambda r: -SEVERITY_RANK.get(r.get("severity", "Low"), 0))

    # Summary
    from collections import Counter
    by_severity = Counter(r["severity"] for r in all_results)
    by_type     = Counter(r["type"] for r in all_results)

    print(f"[+] JS Intelligence: {len(all_results)} findings")
    for sev in ["Critical", "High", "Medium", "Low"]:
        if by_severity.get(sev):
            print(f"    {sev}: {by_severity[sev]}")

    return all_results


# ===============================================
# FILTER HELPERS
# ===============================================

def filter_secrets(findings):
    """Return only secret/credential findings."""
    secret_types = {
        "AWS Access Key", "AWS Secret Key", "Google API Key", "Generic API Key",
        "Bearer Token", "JWT Token", "Private Key", "Generic Secret",
        "Password in Source", "Slack Token", "GitHub Token", "Stripe Key",
        "SendGrid Key", "Twilio Key"
    }
    return [f for f in findings if f["type"] in secret_types]


def filter_endpoints(findings):
    """Return only endpoint/URL findings."""
    endpoint_types = {
        "API Endpoint", "GraphQL Endpoint", "Internal Path",
        "Fetch Call", "Axios Call", "XHR Call", "jQuery AJAX",
        "WebSocket URL", "Hardcoded URL"
    }
    return [f for f in findings if f["type"] in endpoint_types]


def filter_by_severity(findings, severity):
    """Return findings matching a specific severity."""
    return [f for f in findings if f.get("severity") == severity]


# ===============================================
# SELF-TEST
# ===============================================

if __name__ == "__main__":
    test_files = [
        "https://cdnjs.cloudflare.com/ajax/libs/jquery/3.7.1/jquery.min.js",
    ]

    results = analyze_js_files(test_files)

    print("\n===== FINDINGS =====")
    for r in results[:20]:
        print(
            f"  [{r['severity']}] {r['type']}\n"
            f"    Value:   {r['value'][:80]}\n"
            f"    Reason:  {r['reason']}\n"
            f"    Source:  {r['source']}\n"
            f"    Context: {r['context'][:100]}\n"
        )