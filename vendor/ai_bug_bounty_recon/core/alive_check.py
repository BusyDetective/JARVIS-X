"""
alive_check.py — Production-grade host availability engine.

Responsibilities:
  - Determine whether hosts are reachable
  - Collect lightweight reconnaissance metadata (status, title, headers, WAF, IP, timing)

NOT responsible for: technology fingerprinting, vulnerability detection.

Public API (backwards-compatible):
  check_alive(subdomains) -> list[dict]  # {url, status, title}

Architecture:
  HostResult dataclass (slots=True) used internally.
  Converted to dict before returning — callers (recon_core.py) unchanged.
"""

from __future__ import annotations

import json
import random
import re
import shutil
import socket
import subprocess
import time
import urllib3
import urllib3.util.connection as _urllib3_cn
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field, asdict
from functools import lru_cache
from threading import Lock
from typing import Optional
from urllib.parse import urlparse

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from utils.logger import success

# ===============================================
# SUPPRESS TLS WARNINGS
# ===============================================

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ===============================================
# FORCE IPV4
# ===============================================

def force_ipv4() -> None:
    """Patch urllib3 to use IPv4 only."""
    def _ipv4_only():
        return socket.AF_INET
    _urllib3_cn.allowed_gai_family = _ipv4_only

force_ipv4()

# ===============================================
# CONSTANTS
# ===============================================

USER_AGENTS: list[str] = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/119.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
]

HTTPX_CANDIDATES: list[str] = [
    "httpx",
    "/home/detective/go/bin/httpx",
    "/usr/local/bin/httpx",
    "/usr/bin/httpx",
    "/root/go/bin/httpx",
    "/home/user/go/bin/httpx",
]

# Status codes we treat as ALIVE
ALIVE_STATUS_CODES: frozenset[int] = frozenset({
    200, 201, 202, 204, 206,
    301, 302, 303, 307, 308,
    401, 403, 405, 407, 429,
    500, 501, 502, 503, 504,
})

# Statuses that warrant a retry
RETRY_STATUS_CODES: frozenset[int] = frozenset({429, 500, 502, 503})

# Lightweight header intelligence keys
INTEL_HEADERS: list[str] = [
    "server",
    "x-powered-by",
    "via",
    "cf-ray",
    "x-generator",
    "x-aspnet-version",
    "x-backend",
]

# WAF fingerprints: (header_key, value_substring) → WAF name
_WAF_SIGNATURES: list[tuple[str, str, str]] = [
    ("server",              "cloudflare",        "Cloudflare"),
    ("cf-ray",              "",                  "Cloudflare"),
    ("x-cdn",               "cloudflare",        "Cloudflare"),
    ("server",              "akamaighost",       "Akamai"),
    ("x-akamai-transformed","",                  "Akamai"),
    ("x-check-cacheable",   "",                  "Akamai"),
    ("x-iinfo",             "",                  "Imperva/Incapsula"),
    ("x-cdn",               "incapsula",         "Imperva/Incapsula"),
    ("set-cookie",          "incap_ses",         "Imperva/Incapsula"),
    ("x-powered-by",        "fastly",            "Fastly"),
    ("fastly-restarts",     "",                  "Fastly"),
    ("x-amz-cf-id",         "",                  "AWS WAF / CloudFront"),
    ("x-amz-request-id",    "",                  "AWS WAF"),
    ("x-azure-ref",         "",                  "Azure Front Door"),
    ("x-fd-healthprobe",    "",                  "Azure Front Door"),
    ("x-sucuri-id",         "",                  "Sucuri"),
    ("server",              "sucuri",            "Sucuri"),
    ("x-sucuri-cache",      "",                  "Sucuri"),
    ("server",              "big-ip",            "F5 BIG-IP"),
    ("x-wa-info",           "",                  "F5 BIG-IP"),
]

# Compile title regex once
_TITLE_RE: re.Pattern = re.compile(
    r"<title[^>]*>(.*?)</title>",
    re.IGNORECASE | re.DOTALL,
)

# ===============================================
# HOST RESULT DATACLASS
# ===============================================

@dataclass(slots=True)
class HostResult:
    """Internal representation of a host probe result."""
    url:             str
    hostname:        str        = ""
    scheme:          str        = ""
    alive:           bool       = False
    status:          int | str  = ""
    title:           str        = ""
    headers:         dict       = field(default_factory=dict)
    server:          str        = ""
    powered_by:      str        = ""
    redirect_target: str        = ""
    response_time_ms:float      = 0.0
    content_length:  int        = 0
    content_type:    str        = ""
    waf:             str        = ""
    ip_address:      str        = ""
    source:          str        = ""   # "httpx" | "manual"
    error:           str        = ""

    def to_dict(self) -> dict:
        """Convert to plain dict for backwards-compatible return."""
        return {
            "url":             self.url,
            "status":          self.status,
            "title":           self.title,
            # Extended fields (ignored by existing callers, useful for new ones)
            "hostname":        self.hostname,
            "scheme":          self.scheme,
            "alive":           self.alive,
            "headers":         self.headers,
            "server":          self.server,
            "powered_by":      self.powered_by,
            "redirect_target": self.redirect_target,
            "response_time_ms":self.response_time_ms,
            "content_length":  self.content_length,
            "content_type":    self.content_type,
            "waf":             self.waf,
            "ip_address":      self.ip_address,
            "source":          self.source,
            "error":           self.error,
        }

# ===============================================
# SHARED SESSION (connection pooling)
# ===============================================

def _build_session() -> requests.Session:
    """
    Build a shared requests.Session with:
    - Connection pooling (HTTPAdapter)
    - Retry only on transient HTTP errors (429, 5xx) and connection issues
    - Exponential backoff with jitter
    - NO retry on DNS failures or invalid hostnames
    """
    session = requests.Session()

    retry = Retry(
        total=3,
        backoff_factor=0.5,           # 0.5s, 1s, 2s base
        backoff_jitter=0.3,           # ±30% random jitter
        status_forcelist=list(RETRY_STATUS_CODES),
        allowed_methods={"GET", "HEAD"},
        raise_on_status=False,
        # Do NOT retry on: CONNECT, NAME_RESOLUTION errors
        raise_on_redirect=False,
    )

    adapter = HTTPAdapter(
        max_retries=retry,
        pool_connections=20,
        pool_maxsize=100,
        pool_block=False,
    )

    session.mount("https://", adapter)
    session.mount("http://",  adapter)
    return session


# Module-level shared session — created once, reused everywhere
_SESSION: requests.Session = _build_session()
_SESSION_LOCK: Lock = Lock()

# ===============================================
# DNS CACHE
# ===============================================

_dns_cache: dict[str, str] = {}
_dns_lock: Lock = Lock()


def _resolve_ip(hostname: str) -> str:
    """
    Resolve hostname → IPv4 string.
    Caches results per scan. Returns "" on failure (does not raise).
    """
    with _dns_lock:
        if hostname in _dns_cache:
            return _dns_cache[hostname]

    try:
        ip = socket.gethostbyname(hostname)
    except (socket.gaierror, socket.herror):
        ip = ""

    with _dns_lock:
        _dns_cache[hostname] = ip

    return ip


def _clear_dns_cache() -> None:
    """Clear DNS cache between scans."""
    with _dns_lock:
        _dns_cache.clear()

# ===============================================
# URL CACHE
# ===============================================

@lru_cache(maxsize=2048)
def _parse_url(url: str) -> tuple[str, str]:
    """Return (scheme, hostname) for a URL. Cached."""
    parsed = urlparse(url)
    return parsed.scheme, parsed.hostname or ""

# ===============================================
# HELPERS
# ===============================================

def _find_httpx() -> Optional[str]:
    """Return the first working httpx binary path, or None."""
    found = shutil.which("httpx")
    if found:
        return found

    for candidate in HTTPX_CANDIDATES:
        try:
            result = subprocess.run(
                [candidate, "-version"],
                capture_output=True,
                timeout=5,
            )
            if result.returncode == 0:
                return candidate
        except (FileNotFoundError, subprocess.TimeoutExpired):
            continue

    return None


def _extract_title(html: str) -> str:
    """Extract <title> text from HTML. Supports multi-word and multi-line titles."""
    try:
        m = _TITLE_RE.search(html)
        if m:
            return " ".join(m.group(1).split())[:120]
    except Exception:
        pass
    return ""


def _detect_waf(headers: dict) -> str:
    """
    Detect WAF from response headers only.
    Returns WAF name string or "".
    Headers dict keys must be lowercase.
    """
    lower = {k.lower(): v.lower() for k, v in headers.items()}

    for hdr, substring, waf_name in _WAF_SIGNATURES:
        val = lower.get(hdr, "")
        if val and (not substring or substring in val):
            return waf_name

    return ""


def _extract_intel(headers: dict) -> dict[str, str]:
    """Extract lightweight header intelligence. Returns {header: value}."""
    lower = {k.lower(): v for k, v in headers.items()}
    return {h: lower[h] for h in INTEL_HEADERS if h in lower}


def _dedupe(hosts: list[dict]) -> list[dict]:
    """Deduplicate host list by URL, preserving order."""
    seen: set[str] = set()
    clean: list[dict] = []
    for h in hosts:
        url = h["url"]
        if url not in seen:
            seen.add(url)
            clean.append(h)
    return clean


def _is_alive_status(code: int) -> bool:
    return code in ALIVE_STATUS_CODES

# ===============================================
# SAFE REQUEST (uses shared session)
# ===============================================

def _safe_request(url: str, headers: dict) -> Optional[requests.Response]:
    """
    GET via shared session.
    Returns response or None.

    Only marks dead on:
    - DNS failure (gaierror)
    - TCP connection refused / timeout
    - TLS failure (SSLError)
    """
    try:
        return _SESSION.get(
            url,
            timeout=(4, 8),          # (connect_timeout, read_timeout)
            headers=headers,
            allow_redirects=True,
            verify=False,
        )
    except requests.exceptions.SSLError:
        return None
    except requests.exceptions.ConnectionError:
        return None
    except requests.exceptions.Timeout:
        return None
    except Exception:
        return None

# ===============================================
# MANUAL FALLBACK (single host)
# ===============================================

def _check_single_host(sub: str) -> Optional[HostResult]:
    """
    Try https:// then http:// on a subdomain.
    Returns HostResult on first successful response, or None.
    Uses shared session. Prefers HTTPS.
    """
    headers = {"User-Agent": random.choice(USER_AGENTS)}
    sub = sub.strip()

    for scheme in ("https://", "http://"):
        url = scheme + sub
        scheme_str = scheme.rstrip("://")

        t0  = time.perf_counter()
        res = _safe_request(url, headers)
        elapsed_ms = (time.perf_counter() - t0) * 1000

        if res is None:
            continue

        # Any response (even 5xx) means host is reachable
        parsed_scheme, hostname = _parse_url(url)
        ip  = _resolve_ip(hostname)
        hdrs_dict = dict(res.headers)
        intel = _extract_intel(hdrs_dict)
        waf   = _detect_waf(hdrs_dict)

        redirect_target = ""
        if res.history:
            redirect_target = res.url

        title = _extract_title(res.text)

        ct = res.headers.get("content-type", "").split(";")[0].strip()
        cl_str = res.headers.get("content-length", "0")
        try:
            cl = int(cl_str)
        except (ValueError, TypeError):
            cl = len(res.content)

        host_result = HostResult(
            url             = url,
            hostname        = hostname,
            scheme          = scheme_str,
            alive           = True,
            status          = res.status_code,
            title           = title,
            headers         = hdrs_dict,
            server          = intel.get("server", ""),
            powered_by      = intel.get("x-powered-by", ""),
            redirect_target = redirect_target,
            response_time_ms= round(elapsed_ms, 2),
            content_length  = cl,
            content_type    = ct,
            waf             = waf,
            ip_address      = ip,
            source          = "manual",
            error           = "",
        )

        _log_result(host_result)
        return host_result

    return None


def _manual_check(subdomains: list[str], max_workers: int = 30) -> list[HostResult]:
    """Run threaded manual alive check. Returns list of HostResult objects."""
    print("[+] Running manual alive check...")
    alive: list[HostResult] = []

    # Skip duplicates at this level too
    seen: set[str] = set()
    unique = [s for s in subdomains if s not in seen and not seen.add(s)]  # type: ignore[func-returns-value]

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(_check_single_host, sub): sub for sub in unique}

        for future in as_completed(futures):
            try:
                result = future.result()
                if result:
                    alive.append(result)
            except Exception as e:
                print(f"[-] Manual check error: {e}")

    return alive

# ===============================================
# HTTPX PARSER
# ===============================================

def _httpx_supports_json(httpx_bin: str) -> bool:
    """Check if this httpx build supports -json output."""
    try:
        r = subprocess.run(
            [httpx_bin, "-help"],
            capture_output=True, text=True, timeout=5,
        )
        return "-json" in r.stdout or "-json" in r.stderr
    except Exception:
        return False


def _parse_httpx_json_line(line: str) -> Optional[HostResult]:
    """Parse a single httpx JSON output line into HostResult."""
    try:
        obj = json.loads(line)
    except json.JSONDecodeError:
        return None

    url      = obj.get("url", "")
    if not url:
        return None

    parsed_scheme, hostname = _parse_url(url)
    status   = obj.get("status-code", obj.get("status_code", ""))
    title    = obj.get("title", "")
    server   = obj.get("webserver", "")
    tech     = obj.get("tech", [])
    ip       = obj.get("host", "")
    redir    = obj.get("final-url", "")
    rt_str   = obj.get("response-time", "0ms").replace("ms", "")
    try:
        rt = float(rt_str)
    except (ValueError, TypeError):
        rt = 0.0

    return HostResult(
        url             = url,
        hostname        = hostname,
        scheme          = parsed_scheme,
        alive           = True,
        status          = int(status) if str(status).isdigit() else status,
        title           = title,
        headers         = {},
        server          = server,
        powered_by      = "",
        redirect_target = redir if redir != url else "",
        response_time_ms= round(rt, 2),
        content_length  = 0,
        content_type    = "",
        waf             = "",
        ip_address      = ip,
        source          = "httpx",
        error           = "",
    )


def _parse_httpx_text_line(line: str) -> Optional[HostResult]:
    """
    Parse httpx text output line robustly.
    Format: <url> [status] [Title with possible spaces]
    Example: https://sub.example.com [200] [My Page Title]
    """
    line = line.strip()
    if not line:
        return None

    # Extract URL (first token)
    space_idx = line.find(" ")
    if space_idx == -1:
        url = line
        rest = ""
    else:
        url  = line[:space_idx]
        rest = line[space_idx:].strip()

    if not url.startswith(("http://", "https://")):
        return None

    parsed_scheme, hostname = _parse_url(url)
    status: int | str = "alive"
    title  = ""

    # Extract all [...] tokens from rest
    # Handles: [200] [Title With Spaces] or [200] [Title]
    bracket_re = re.compile(r"\[([^\]]*)\]")
    brackets   = bracket_re.findall(rest)

    title_parts: list[str] = []

    for tok in brackets:
        if tok.isdigit():
            status = int(tok)
        else:
            title_parts.append(tok)

    if title_parts:
        title = " ".join(title_parts)[:120]

    return HostResult(
        url             = url,
        hostname        = hostname,
        scheme          = parsed_scheme,
        alive           = True,
        status          = status,
        title           = title,
        headers         = {},
        server          = "",
        powered_by      = "",
        redirect_target = "",
        response_time_ms= 0.0,
        content_length  = 0,
        content_type    = "",
        waf             = "",
        ip_address      = "",
        source          = "httpx",
        error           = "",
    )

# ===============================================
# HTTPX CHECK
# ===============================================

def _httpx_check(subdomains: list[str], httpx_bin: str) -> list[HostResult]:
    """
    Run httpx on subdomain list. Returns list of HostResult objects.
    Uses JSON output when supported; falls back to robust text parser.
    """
    print(f"[+] Running httpx ({httpx_bin})...")
    alive: list[HostResult] = []

    use_json = _httpx_supports_json(httpx_bin)

    try:
        input_data = "\n".join(subdomains)

        cmd = [
            httpx_bin,
            "-silent",
            "-follow-redirects",
            "-status-code",
            "-title",
            "-timeout", "10",
            "-threads", "50",
        ]

        if use_json:
            cmd += ["-json"]

        result = subprocess.run(
            cmd,
            input=input_data,
            capture_output=True,
            text=True,
            timeout=300,
        )

        for line in result.stdout.splitlines():
            line = line.strip()
            if not line:
                continue

            host_result: Optional[HostResult] = None

            if use_json:
                host_result = _parse_httpx_json_line(line)
            else:
                host_result = _parse_httpx_text_line(line)

            if host_result:
                alive.append(host_result)
                success(f"[ALIVE] {host_result.url} | {host_result.status}")

        print(f"[+] httpx found {len(alive)} alive hosts")

    except subprocess.TimeoutExpired:
        print("[-] httpx timed out")
    except Exception as e:
        print(f"[-] httpx error: {e}")

    return alive

# ===============================================
# LOGGING
# ===============================================

def _log_result(r: HostResult) -> None:
    """Structured log line for a single host result."""
    parts = [f"[ALIVE] {r.url}"]
    if r.status:
        parts.append(f"status={r.status}")
    if r.response_time_ms:
        parts.append(f"rt={r.response_time_ms:.0f}ms")
    if r.ip_address:
        parts.append(f"ip={r.ip_address}")
    if r.server:
        parts.append(f"server={r.server}")
    if r.waf:
        parts.append(f"waf={r.waf}")
    if r.title:
        parts.append(f"title={r.title!r}")
    success(" | ".join(parts))

# ===============================================
# STATISTICS
# ===============================================

def _print_stats(all_hosts: list[str], alive: list[HostResult]) -> None:
    """Print scan summary statistics."""
    total   = len(all_hosts)
    n_alive = len(alive)
    n_dead  = total - n_alive

    times = [r.response_time_ms for r in alive if r.response_time_ms > 0]
    avg_rt = sum(times) / len(times) if times else 0.0
    fastest = min(times) if times else 0.0
    slowest = max(times) if times else 0.0

    waf_count      = sum(1 for r in alive if r.waf)
    redirect_count = sum(1 for r in alive if r.redirect_target)

    print("\n" + "=" * 50)
    print("  SCAN STATISTICS")
    print("=" * 50)
    print(f"  Hosts checked    : {total}")
    print(f"  Alive            : {n_alive}")
    print(f"  Dead / unreachable: {n_dead}")
    if times:
        print(f"  Avg response time: {avg_rt:.0f} ms")
        print(f"  Fastest          : {fastest:.0f} ms")
        print(f"  Slowest          : {slowest:.0f} ms")
    print(f"  WAF detected     : {waf_count}")
    print(f"  Redirects        : {redirect_count}")
    print("=" * 50 + "\n")

# ===============================================
# MAIN ENTRY POINT  (backwards-compatible)
# ===============================================

def check_alive(subdomains: list[str]) -> list[dict]:
    """
    Check which subdomains are alive.
    Tries httpx first (fast, feature-rich), falls back to manual threading.

    Args:
        subdomains: list of subdomain strings (no protocol)

    Returns:
        list of dicts: {url, status, title, ...}
        Core keys (url, status, title) are always present for backwards compat.
        Extended keys are also present for new consumers.
    """
    if not subdomains:
        return []

    # Reset DNS cache for this scan
    _clear_dns_cache()

    # Normalize — strip protocols if accidentally included
    cleaned: list[str] = [
        s.replace("https://", "").replace("http://", "").strip()
        for s in subdomains
        if s and s.strip()
    ]
    cleaned = list(dict.fromkeys(cleaned))  # Dedupe while preserving order

    print(f"\n[+] Checking {len(cleaned)} hosts for alive status...\n")

    alive_results: list[HostResult] = []

    # ── Try httpx first ───────────────────────────
    httpx_bin = _find_httpx()

    if httpx_bin:
        alive_results = _httpx_check(cleaned, httpx_bin)
    else:
        print("[!] httpx not found — using manual checker")

    # ── Fall back to manual if httpx returned nothing ─
    if not alive_results:
        print("[!] httpx returned 0 results — falling back to manual check")
        alive_results = _manual_check(cleaned)

    # ── Deduplicate by URL ─────────────────────────
    seen_urls: set[str] = set()
    deduped: list[HostResult] = []
    for r in alive_results:
        if r.url not in seen_urls:
            seen_urls.add(r.url)
            deduped.append(r)
    alive_results = deduped

    # ── Statistics ────────────────────────────────
    _print_stats(cleaned, alive_results)

    # ── Summary table ─────────────────────────────
    if alive_results:
        print("===== ALIVE HOSTS =====")
        for r in alive_results:
            status_str = f" [{r.status}]" if r.status else ""
            title_str  = f" {r.title}"    if r.title  else ""
            print(f"  {r.url}{status_str}{title_str}")
        print("=======================\n")

    # ── Convert to dicts (backwards-compatible return) ────
    return [r.to_dict() for r in alive_results]

# ===============================================
# SELF-TEST
# ===============================================

if __name__ == "__main__":
    test_subs = [
        "example.com",
        "www.example.com",
        "api.example.com",
        "nonexistent-sub-xyzabc.example.com",
    ]

    results = check_alive(test_subs)
    print(f"\nAlive: {len(results)}")
    for r in results:
        print(f"  {r}")
