import requests
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import re

HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/120.0.0.0 Safari/537.36"
    )
}

# XSS payloads to look for in response
XSS_SIGNATURES = [
    "<script>alert(1)</script>",
    "<svg/onload=alert(1)>",
    "'\"><svg/onload=alert(1)>",
    "<img src=x onerror=alert(1)>",
    "javascript:alert(1)"
]

# SQLi error signatures
SQLI_ERRORS = [
    "sql syntax", "mysql_fetch", "syntax error", "unclosed quotation",
    "ora-01756", "pg_query", "sqlite_", "database error", "odbc driver",
    "warning: mysql", "you have an error in your sql"
]

# Info disclosure signatures
INFO_DISCLOSURE_SIGS = [
    "exception", "traceback", "stack trace", "fatal error",
    "php warning", "undefined variable", "at line", "debug info"
]

# SSRF confirmation indicators
SSRF_SIGS = [
    "169.254.", "127.0.0.1", "localhost", "internal server",
    "connection refused", "ec2.internal", "metadata"
]


def _make_request(url, method="GET", allow_redirects=False, timeout=8):
    """Shared request helper with consistent headers and error handling."""
    try:
        response = requests.request(
            method,
            url,
            headers=HEADERS,
            timeout=timeout,
            allow_redirects=allow_redirects,
            verify=False
        )
        return response
    except requests.exceptions.Timeout:
        return None
    except requests.exceptions.ConnectionError:
        return None
    except Exception:
        return None


def _base_result(exploit):
    """Build a base result dict from an exploit entry."""
    return {
        "type": exploit.get("type", "Unknown"),
        "url": exploit.get("poc", exploit.get("url", "")),
        "payload": exploit.get("payload", ""),
        "status": "UNVERIFIED",
        "confidence": 0,
        "evidence": ""
    }


# ===============================================
# PER-TYPE VALIDATORS
# ===============================================

def _validate_open_redirect(exploit, result):
    response = _make_request(result["url"], allow_redirects=False)
    if response is None:
        return result

    location = response.headers.get("Location", "")

    if "evil.com" in location or "attacker.com" in location:
        result["status"] = "CONFIRMED"
        result["confidence"] = 95
        result["evidence"] = f"Redirects to: {location}"
    elif response.status_code in (301, 302) and location.startswith("http"):
        result["status"] = "POSSIBLE"
        result["confidence"] = 60
        result["evidence"] = f"External redirect to: {location}"

    return result


def _validate_xss(exploit, result):
    response = _make_request(result["url"], allow_redirects=True)
    if response is None:
        return result

    content_type = response.headers.get("Content-Type", "")
    if "text/html" not in content_type:
        return result

    body = response.text
    for sig in XSS_SIGNATURES:
        if sig.lower() in body.lower():
            result["status"] = "CONFIRMED"
            result["confidence"] = 92
            result["evidence"] = f"Payload reflected: {sig}"
            return result

    # Check for encoded reflection (partial signal)
    payload = exploit.get("payload", "")
    if payload and payload[:10].lower() in body.lower():
        result["status"] = "POSSIBLE"
        result["confidence"] = 55
        result["evidence"] = "Partial payload reflection detected"

    return result


def _validate_sqli(exploit, result):
    response = _make_request(result["url"], allow_redirects=True)
    if response is None:
        return result

    body = response.text.lower()
    for sig in SQLI_ERRORS:
        if sig in body:
            result["status"] = "CONFIRMED"
            result["confidence"] = 88
            result["evidence"] = f"SQL error signature: {sig}"
            return result

    # Time-based: compare response time against baseline
    # (basic heuristic — proper time-based needs baseline subtraction)
    if response.elapsed.total_seconds() > 8:
        result["status"] = "POSSIBLE"
        result["confidence"] = 50
        result["evidence"] = f"Slow response: {response.elapsed.total_seconds():.1f}s (possible time-based SQLi)"

    return result


def _validate_ssrf(exploit, result):
    response = _make_request(result["url"], allow_redirects=True)
    if response is None:
        return result

    body = response.text.lower()
    for sig in SSRF_SIGS:
        if sig in body:
            result["status"] = "CONFIRMED"
            result["confidence"] = 85
            result["evidence"] = f"Internal resource indicator: {sig}"
            return result

    if response.status_code in (200, 500):
        result["status"] = "POSSIBLE"
        result["confidence"] = 40
        result["evidence"] = f"Status {response.status_code} on SSRF candidate"

    return result


def _validate_lfi(exploit, result):
    response = _make_request(result["url"], allow_redirects=True)
    if response is None:
        return result

    body = response.text
    lfi_sigs = [
        "root:x:0:0", "[boot loader]", "for 16-bit app support",
        "daemon:x:", "/bin/bash", "<?php", "Warning: include"
    ]
    for sig in lfi_sigs:
        if sig in body:
            result["status"] = "CONFIRMED"
            result["confidence"] = 90
            result["evidence"] = f"File content signature: {sig[:40]}"
            return result

    if len(body) > 500:
        result["status"] = "POSSIBLE"
        result["confidence"] = 35
        result["evidence"] = "Non-empty response on LFI candidate"

    return result


def _validate_ssti(exploit, result):
    response = _make_request(result["url"], allow_redirects=True)
    if response is None:
        return result

    body = response.text
    # SSTI payloads like {{7*7}} should return 49
    ssti_confirms = ["49", "7777777", "[[7*7]]"]
    for sig in ssti_confirms:
        if sig in body:
            result["status"] = "CONFIRMED"
            result["confidence"] = 87
            result["evidence"] = f"Template evaluation result: {sig}"
            return result

    return result


def _validate_idor(exploit, result):
    response = _make_request(result["url"], allow_redirects=True)
    if response is None:
        return result

    if response.status_code == 200 and len(response.text) > 100:
        # Heuristic: look for data-like content
        data_sigs = ['"id"', '"email"', '"username"', '"user_id"', '"account"']
        body = response.text.lower()
        for sig in data_sigs:
            if sig in body:
                result["status"] = "POSSIBLE"
                result["confidence"] = 55
                result["evidence"] = f"Sensitive field in response: {sig}"
                return result

        result["status"] = "POSSIBLE"
        result["confidence"] = 35
        result["evidence"] = "200 OK with non-empty body on IDOR candidate"

    elif response.status_code == 403:
        result["status"] = "POSSIBLE"
        result["confidence"] = 45
        result["evidence"] = "403 Forbidden — access control exists, test with auth bypass"

    return result


def _validate_info_disclosure(exploit, result):
    response = _make_request(result["url"], allow_redirects=True)
    if response is None:
        return result

    body = response.text.lower()
    for sig in INFO_DISCLOSURE_SIGS:
        if sig in body:
            result["status"] = "CONFIRMED"
            result["confidence"] = 80
            result["evidence"] = f"Disclosure signature: {sig}"
            return result

    if response.status_code == 200 and len(response.text) > 200:
        result["status"] = "POSSIBLE"
        result["confidence"] = 40
        result["evidence"] = "Accessible endpoint with content"

    return result


def _validate_header_injection(exploit, result):
    response = _make_request(result["url"], allow_redirects=False)
    if response is None:
        return result

    # Look for injected header values reflected in response headers
    payload = exploit.get("payload", "")
    for header_val in response.headers.values():
        if payload and payload[:10] in header_val:
            result["status"] = "CONFIRMED"
            result["confidence"] = 85
            result["evidence"] = f"Payload reflected in response header"
            return result

    if response.status_code in (200, 301, 302):
        result["status"] = "POSSIBLE"
        result["confidence"] = 30
        result["evidence"] = "Header injection candidate responded"

    return result


# ===============================================
# DISPATCH TABLE
# ===============================================

VALIDATORS = {
    "open redirect":       _validate_open_redirect,
    "xss":                 _validate_xss,
    "cross-site":          _validate_xss,
    "sqli":                _validate_sqli,
    "sql injection":       _validate_sqli,
    "ssrf":                _validate_ssrf,
    "server-side request": _validate_ssrf,
    "lfi":                 _validate_lfi,
    "local file":          _validate_lfi,
    "ssti":                _validate_ssti,
    "template injection":  _validate_ssti,
    "idor":                _validate_idor,
    "insecure direct":     _validate_idor,
    "information":         _validate_info_disclosure,
    "exposure":            _validate_info_disclosure,
    "header injection":    _validate_header_injection,
}


def validate_exploit(exploit):
    """
    Validate a single exploit by making a real HTTP request and checking
    the response for confirmation signatures.

    Args:
        exploit: dict with keys: type, poc, payload

    Returns:
        dict with status (CONFIRMED / POSSIBLE / UNVERIFIED / FAILED),
        confidence (0-100), and evidence string
    """
    if not exploit:
        return None

    result = _base_result(exploit)

    if not result["url"]:
        return result

    # Dispatch to the right validator based on vuln type
    vuln_type = exploit.get("type", "").lower()
    validator = None

    for keyword, fn in VALIDATORS.items():
        if keyword in vuln_type:
            validator = fn
            break

    try:
        if validator:
            result = validator(exploit, result)
        else:
            # Generic fallback: just check if the URL is reachable
            response = _make_request(result["url"])
            if response and response.status_code == 200:
                result["status"] = "POSSIBLE"
                result["confidence"] = 25
                result["evidence"] = "Endpoint reachable (no specific validator)"

    except Exception as e:
        result["status"] = "FAILED"
        result["evidence"] = f"Validation error: {str(e)}"

    return result


# ===============================================
# BATCH VALIDATOR
# ===============================================

def validate_all(exploits):
    """
    Validate a list of exploits in parallel.

    Args:
        exploits: list of exploit dicts

    Returns:
        list of validated result dicts (only non-None results)
    """
    if not exploits:
        return []

    results = []

    with ThreadPoolExecutor(max_workers=15) as executor:
        futures = {executor.submit(validate_exploit, exp): exp for exp in exploits}

        for future in as_completed(futures):
            try:
                result = future.result()
                if result:
                    results.append(result)
            except Exception as e:
                print(f"[-] Validation thread error: {e}")

    # Sort: CONFIRMED first, then POSSIBLE, then others
    order = {"CONFIRMED": 0, "POSSIBLE": 1, "UNVERIFIED": 2, "FAILED": 3}
    results.sort(key=lambda r: order.get(r.get("status", "FAILED"), 3))

    confirmed = sum(1 for r in results if r["status"] == "CONFIRMED")
    possible = sum(1 for r in results if r["status"] == "POSSIBLE")
    print(f"[+] Validation complete: {confirmed} confirmed, {possible} possible")

    return results


# ===============================================
# SELF-TEST
# ===============================================

if __name__ == "__main__":
    test_exploits = [
        {
            "type": "Open Redirect",
            "poc": "https://httpbin.org/redirect-to?url=https://evil.com",
            "payload": "https://evil.com"
        },
        {
            "type": "XSS",
            "poc": "https://httpbin.org/get?q=<script>alert(1)</script>",
            "payload": "<script>alert(1)</script>"
        },
        {
            "type": "SQLi",
            "poc": "https://httpbin.org/get?id=1'+OR+'1'='1",
            "payload": "' OR '1'='1"
        }
    ]

    print("[*] Running self-test...")
    results = validate_all(test_exploits)
    for r in results:
        print(f"  [{r['status']}] {r['type']} | confidence={r['confidence']} | {r['evidence']}")