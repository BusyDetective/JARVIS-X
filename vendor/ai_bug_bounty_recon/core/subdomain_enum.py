"""
subdomain_enum.py
-----------------
Production-grade passive subdomain enumeration engine.
Fully backwards-compatible with the original public API.

Sources:
    crt.sh | AlienVault OTX | RapidDNS | AnubisDB |
    BufferOver | URLScan | Wayback CDX | HackerTarget

Author: AI Bug Bounty Recon Platform
"""

from __future__ import annotations

import random
import re
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Callable, Dict, List, Optional, Set, Tuple

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# ===============================================
# CONSTANTS & COMPILED REGEXES
# ===============================================

_HOSTNAME_RE = re.compile(r'^[a-z0-9]([a-z0-9\-\.]*[a-z0-9])?$')
_ANSI_RE     = re.compile(r'\x1b\[[0-9;]*m')
_URL_HOST_RE = re.compile(r'https?://([^/:?#]+)')

_NOISE_KEYWORDS = frozenset([
    "test intermediate", "certificate", "issuer",
    "subject", "san:", "common name",
])

_DEFAULT_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/120.0.0.0 Safari/537.36"
    )
}

# Retry config
_DEFAULT_RETRIES    = 3
_BACKOFF_BASE       = 2.0   # seconds
_JITTER_MAX         = 0.5   # seconds
_MAX_WORKERS        = 8     # thread pool ceiling

# HTTP status codes worth retrying
_RETRYABLE_STATUS   = {429, 500, 502, 503, 504}

# ===============================================
# ENUMS
# ===============================================

class SourceStatus(Enum):
    SUCCESS  = auto()
    PARTIAL  = auto()   # returned data but with errors / fewer retries left
    FAILED   = auto()
    SKIPPED  = auto()   # cache hit, ran via another path


# ===============================================
# DATACLASSES
# ===============================================

@dataclass(slots=True)
class SourceResult:
    source_name:  str
    subdomains:   Set[str]          = field(default_factory=set)
    request_time: float             = 0.0          # seconds
    status:       SourceStatus      = SourceStatus.FAILED
    error:        Optional[str]     = None
    retry_count:  int               = 0


@dataclass(slots=True)
class ScanStats:
    total_sources:     int
    successful:        int
    failed:            int
    total_unique:      int
    per_source:        Dict[str, int]          # source → subdomain count
    response_times:    Dict[str, float]        # source → seconds
    source_statuses:   Dict[str, SourceStatus]


# ===============================================
# SESSION FACTORY
# ===============================================

def _make_session(retries: int = 0) -> requests.Session:
    """
    Create a requests.Session with connection pooling and
    optional urllib3-level retry for connection-layer failures.
    Application-level retries (with backoff) are handled separately.
    """
    session = requests.Session()
    session.headers.update(_DEFAULT_HEADERS)

    adapter = HTTPAdapter(
        max_retries=Retry(
            total=retries,
            backoff_factor=0.3,
            status_forcelist=[],          # handled at app level
            allowed_methods={"GET"},
            raise_on_status=False,
        ),
        pool_connections=10,
        pool_maxsize=20,
    )
    session.mount("https://", adapter)
    session.mount("http://", adapter)
    return session


# One shared session per scan (thread-safe for reads)
_SESSION: Optional[requests.Session] = None


def _get_session() -> requests.Session:
    global _SESSION
    if _SESSION is None:
        _SESSION = _make_session()
    return _SESSION


# ===============================================
# VALIDATION & NORMALISATION
# ===============================================

def _clean(sub: str) -> str:
    """Strip ANSI codes, trailing dots, and whitespace; lowercase."""
    sub = _ANSI_RE.sub('', sub).strip().lower()
    return sub.rstrip('.')


def _is_valid_subdomain(sub: str, domain: str) -> bool:
    """
    Return True if *sub* is a syntactically valid subdomain of *domain*.
    Filters wildcards, emails, garbage cert entries, and unrelated domains.
    """
    if not sub or not isinstance(sub, str):
        return False

    sub = sub.strip().lower().rstrip('.')

    if sub != domain and not sub.endswith("." + domain):
        return False

    if any(c in sub for c in ("*", "@", " ", "\x1b", "/")):
        return False

    if any(kw in sub for kw in _NOISE_KEYWORDS):
        return False

    if not _HOSTNAME_RE.match(sub):
        return False

    return True


# ===============================================
# RETRY HELPER
# ===============================================

def _with_retry(
    fn:          Callable[[], Tuple[Set[str], bool]],
    source_name: str,
    max_retries: int = _DEFAULT_RETRIES,
) -> SourceResult:
    """
    Execute *fn* with exponential backoff + jitter.

    *fn* must return (subdomains: Set[str], retryable: bool).
    Raises are treated as retryable unless they set retryable=False.
    """
    result = SourceResult(source_name=source_name)
    t_start = time.perf_counter()

    for attempt in range(1, max_retries + 1):
        try:
            subs, retryable = fn()
            result.subdomains   = subs
            result.status       = SourceStatus.SUCCESS
            result.retry_count  = attempt - 1
            break

        except _NonRetryableError as exc:
            result.error       = str(exc)
            result.status      = SourceStatus.FAILED
            result.retry_count = attempt - 1
            break

        except Exception as exc:
            result.error       = str(exc)
            result.retry_count = attempt - 1

            if attempt == max_retries:
                result.status = SourceStatus.FAILED
                break

            delay = _BACKOFF_BASE * (2 ** (attempt - 1)) + random.uniform(0, _JITTER_MAX)
            _log(source_name, f"attempt {attempt}/{max_retries} failed — retry in {delay:.1f}s")
            time.sleep(delay)

    result.request_time = time.perf_counter() - t_start
    return result


class _NonRetryableError(Exception):
    """Raised inside source functions to skip remaining retries."""


# ===============================================
# LOGGING
# ===============================================

def _log(source: str, msg: str) -> None:
    print(f"  [{source}] {msg}")


def _log_result(r: SourceResult) -> None:
    status_str = r.status.name
    print(
        f"  [{'SOURCE':^6}] "
        f"name={r.source_name:<15} "
        f"elapsed={r.request_time:5.2f}s  "
        f"found={len(r.subdomains):<5} "
        f"retries={r.retry_count}  "
        f"status={status_str}"
        + (f"  error={r.error}" if r.error else "")
    )


# ===============================================
# IN-SCAN CACHE
# ===============================================

_CACHE: Dict[str, SourceResult] = {}


def _cached(source_name: str, fn: Callable[[], SourceResult]) -> SourceResult:
    """Return cached result if present; otherwise call *fn* and cache it."""
    if source_name in _CACHE:
        cached = _CACHE[source_name]
        _log(source_name, "cache hit — skipping request")
        skipped = SourceResult(
            source_name  = source_name,
            subdomains   = cached.subdomains,
            request_time = 0.0,
            status       = SourceStatus.SKIPPED,
            retry_count  = 0,
        )
        return skipped
    result = fn()
    _CACHE[source_name] = result
    return result


# ===============================================
# SOURCE: crt.sh
# ===============================================

def _from_crtsh(domain: str, max_retries: int = _DEFAULT_RETRIES) -> SourceResult:
    url     = f"https://crt.sh/?q=%25.{domain}&output=json"
    session = _get_session()

    def _fetch() -> Tuple[Set[str], bool]:
        res = session.get(url, timeout=15)

        if res.status_code in _RETRYABLE_STATUS:
            raise Exception(f"HTTP {res.status_code}")

        if res.status_code != 200:
            raise _NonRetryableError(f"HTTP {res.status_code}")

        try:
            data = res.json()
        except Exception:
            raise _NonRetryableError("invalid JSON")

        subs: Set[str] = set()
        for entry in data:
            for raw in entry.get("name_value", "").split("\n"):
                sub = _clean(raw)
                if _is_valid_subdomain(sub, domain):
                    subs.add(sub)
        return subs, True

    return _cached("crt.sh", lambda: _with_retry(_fetch, "crt.sh", max_retries))


# ===============================================
# SOURCE: HackerTarget
# ===============================================

def _from_hackertarget(domain: str, max_retries: int = _DEFAULT_RETRIES) -> SourceResult:
    url     = f"https://api.hackertarget.com/hostsearch/?q={domain}"
    session = _get_session()

    def _fetch() -> Tuple[Set[str], bool]:
        res = session.get(url, timeout=12)

        if res.status_code in _RETRYABLE_STATUS:
            raise Exception(f"HTTP {res.status_code}")

        text = res.text
        if "API count exceeded" in text or "error" in text.lower()[:50]:
            raise _NonRetryableError("rate limited or API error")

        subs: Set[str] = set()
        for line in text.splitlines():
            parts = line.split(",")
            if parts:
                sub = _clean(parts[0])
                if _is_valid_subdomain(sub, domain):
                    subs.add(sub)
        return subs, True

    return _cached("HackerTarget", lambda: _with_retry(_fetch, "HackerTarget", max_retries))


# ===============================================
# SOURCE: RapidDNS
# ===============================================

def _from_rapiddns(domain: str, max_retries: int = _DEFAULT_RETRIES) -> SourceResult:
    url     = f"https://rapiddns.io/subdomain/{domain}?full=1"
    session = _get_session()
    pattern = re.compile(
        r'<td>([a-z0-9][a-z0-9\-\.]*\.' + re.escape(domain) + r')</td>'
    )

    def _fetch() -> Tuple[Set[str], bool]:
        res = session.get(url, timeout=12)

        if res.status_code in _RETRYABLE_STATUS:
            raise Exception(f"HTTP {res.status_code}")

        subs: Set[str] = set()
        for raw in pattern.findall(res.text.lower()):
            sub = _clean(raw)
            if _is_valid_subdomain(sub, domain):
                subs.add(sub)
        return subs, True

    return _cached("RapidDNS", lambda: _with_retry(_fetch, "RapidDNS", max_retries))


# ===============================================
# SOURCE: AlienVault OTX
# ===============================================

def _from_alienvault(domain: str, max_retries: int = _DEFAULT_RETRIES) -> SourceResult:
    url     = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"
    session = _get_session()

    def _fetch() -> Tuple[Set[str], bool]:
        res = session.get(url, timeout=12)

        if res.status_code in _RETRYABLE_STATUS:
            raise Exception(f"HTTP {res.status_code}")

        if res.status_code != 200:
            raise _NonRetryableError(f"HTTP {res.status_code}")

        try:
            data = res.json()
        except Exception:
            raise _NonRetryableError("invalid JSON")

        subs: Set[str] = set()
        for entry in data.get("passive_dns", []):
            sub = _clean(entry.get("hostname", ""))
            if _is_valid_subdomain(sub, domain):
                subs.add(sub)
        return subs, True

    return _cached("AlienVault", lambda: _with_retry(_fetch, "AlienVault", max_retries))


# ===============================================
# SOURCE: Wayback CDX
# ===============================================

def _from_wayback(domain: str, max_retries: int = _DEFAULT_RETRIES) -> SourceResult:
    url = (
        f"https://web.archive.org/cdx/search/cdx"
        f"?url=*.{domain}&output=text&fl=original&collapse=urlkey&limit=500"
    )
    session = _get_session()

    def _fetch() -> Tuple[Set[str], bool]:
        res = session.get(url, timeout=15)

        if res.status_code in _RETRYABLE_STATUS:
            raise Exception(f"HTTP {res.status_code}")

        subs: Set[str] = set()
        for line in res.text.splitlines():
            m = _URL_HOST_RE.match(line.strip())
            if m:
                sub = _clean(m.group(1))
                if _is_valid_subdomain(sub, domain):
                    subs.add(sub)
        return subs, True

    return _cached("Wayback", lambda: _with_retry(_fetch, "Wayback", max_retries))


# ===============================================
# SOURCE: AnubisDB
# ===============================================

def _from_anubisdb(domain: str, max_retries: int = _DEFAULT_RETRIES) -> SourceResult:
    url     = f"https://jldc.me/anubis/subdomains/{domain}"
    session = _get_session()

    def _fetch() -> Tuple[Set[str], bool]:
        res = session.get(url, timeout=12)

        if res.status_code in _RETRYABLE_STATUS:
            raise Exception(f"HTTP {res.status_code}")

        if res.status_code != 200:
            raise _NonRetryableError(f"HTTP {res.status_code}")

        try:
            data = res.json()
        except Exception:
            raise _NonRetryableError("invalid JSON")

        subs: Set[str] = set()
        for raw in data:
            sub = _clean(str(raw))
            if _is_valid_subdomain(sub, domain):
                subs.add(sub)
        return subs, True

    return _cached("AnubisDB", lambda: _with_retry(_fetch, "AnubisDB", max_retries))


# ===============================================
# SOURCE: BufferOver
# ===============================================

def _from_bufferover(domain: str, max_retries: int = _DEFAULT_RETRIES) -> SourceResult:
    url     = f"https://dns.bufferover.run/dns?q=.{domain}"
    session = _get_session()

    def _fetch() -> Tuple[Set[str], bool]:
        res = session.get(url, timeout=12)

        if res.status_code in _RETRYABLE_STATUS:
            raise Exception(f"HTTP {res.status_code}")

        if res.status_code != 200:
            raise _NonRetryableError(f"HTTP {res.status_code}")

        try:
            data = res.json()
        except Exception:
            raise _NonRetryableError("invalid JSON")

        subs: Set[str] = set()
        # BufferOver returns FDNS_A and RDNS lists in "ip,hostname" format
        for key in ("FDNS_A", "RDNS"):
            for entry in data.get(key) or []:
                parts = entry.split(",")
                if len(parts) >= 2:
                    sub = _clean(parts[-1])
                    if _is_valid_subdomain(sub, domain):
                        subs.add(sub)
        return subs, True

    return _cached("BufferOver", lambda: _with_retry(_fetch, "BufferOver", max_retries))


# ===============================================
# SOURCE: URLScan
# ===============================================

def _from_urlscan(domain: str, max_retries: int = _DEFAULT_RETRIES) -> SourceResult:
    url     = f"https://urlscan.io/api/v1/search/?q=domain:{domain}&size=200"
    session = _get_session()

    def _fetch() -> Tuple[Set[str], bool]:
        res = session.get(url, timeout=15)

        if res.status_code == 429:
            raise Exception("rate limited (429)")

        if res.status_code in _RETRYABLE_STATUS:
            raise Exception(f"HTTP {res.status_code}")

        if res.status_code != 200:
            raise _NonRetryableError(f"HTTP {res.status_code}")

        try:
            data = res.json()
        except Exception:
            raise _NonRetryableError("invalid JSON")

        subs: Set[str] = set()
        for result in data.get("results", []):
            # page.domain field
            sub = _clean(result.get("page", {}).get("domain", ""))
            if _is_valid_subdomain(sub, domain):
                subs.add(sub)
            # task.domain field
            sub = _clean(result.get("task", {}).get("domain", ""))
            if _is_valid_subdomain(sub, domain):
                subs.add(sub)
        return subs, True

    return _cached("URLScan", lambda: _with_retry(_fetch, "URLScan", max_retries))


# ===============================================
# SOURCE REGISTRY
# ===============================================

# Maps source name → callable(domain, max_retries) → SourceResult
SOURCES: Dict[str, Callable[..., SourceResult]] = {
    "crt.sh":       _from_crtsh,
    "HackerTarget": _from_hackertarget,
    "RapidDNS":     _from_rapiddns,
    "AlienVault":   _from_alienvault,
    "Wayback":      _from_wayback,
    "AnubisDB":     _from_anubisdb,
    "BufferOver":   _from_bufferover,
    "URLScan":      _from_urlscan,
}


# ===============================================
# MAIN ENUMERATOR  (backwards-compatible API)
# ===============================================

def enumerate_subdomains(
    domain:      str,
    sources:     Optional[List[str]] = None,
    max_retries: int                 = _DEFAULT_RETRIES,
    return_stats: bool               = False,
) -> List[str] | Tuple[List[str], ScanStats]:
    """
    Enumerate subdomains using multiple passive sources in parallel.

    Args:
        domain:       Target domain (e.g. "example.com").
        sources:      Optional list of source names to query.
                      Defaults to all available sources.
        max_retries:  Per-source retry limit (exponential backoff + jitter).
        return_stats: If True, return (subdomains, ScanStats) tuple.
                      If False (default), return plain sorted list —
                      fully backwards-compatible.

    Returns:
        Sorted list of unique subdomain strings (no protocols),
        OR (list, ScanStats) if return_stats=True.
    """
    global _CACHE, _SESSION
    _CACHE   = {}          # clear per-scan cache
    _SESSION = _make_session()   # fresh session per scan

    # Normalise domain
    domain = (
        domain.strip().lower()
        .replace("https://", "")
        .replace("http://", "")
        .split("/")[0]
    )

    active_sources: Dict[str, Callable] = {
        k: v for k, v in SOURCES.items()
        if sources is None or k in sources
    }

    print(f"\n[+] Enumerating subdomains for: {domain}")
    print(f"[+] Active sources ({len(active_sources)}): {list(active_sources.keys())}\n")

    all_subs: Set[str] = set()
    source_results: List[SourceResult] = []

    workers = min(_MAX_WORKERS, len(active_sources))
    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {
            executor.submit(fn, domain, max_retries): name
            for name, fn in active_sources.items()
        }

        for future in as_completed(futures):
            source_name = futures[future]
            try:
                result: SourceResult = future.result()
            except Exception as exc:
                result = SourceResult(
                    source_name = source_name,
                    status      = SourceStatus.FAILED,
                    error       = str(exc),
                )

            source_results.append(result)
            all_subs.update(result.subdomains)
            _log_result(result)

    # Always include root domain
    all_subs.add(domain)
    final = sorted(all_subs)

    # ── Summary ──────────────────────────────────────────────
    successful = sum(1 for r in source_results if r.status == SourceStatus.SUCCESS)
    failed     = sum(1 for r in source_results if r.status == SourceStatus.FAILED)

    print(f"\n[+] Subdomain enumeration complete")
    print(f"    {'Source':<16} {'Found':<8} {'Time':>7}  {'Retries':>7}  Status")
    print(f"    {'-'*58}")
    for r in sorted(source_results, key=lambda x: x.source_name):
        print(
            f"    {r.source_name:<16} {len(r.subdomains):<8} "
            f"{r.request_time:>6.2f}s  {r.retry_count:>7}  {r.status.name}"
        )
    print(f"    {'-'*58}")
    print(f"    {'TOTAL':<16} {len(final):<8}  sources={len(active_sources)}  "
          f"ok={successful}  fail={failed}\n")

    if not return_stats:
        return final

    stats = ScanStats(
        total_sources   = len(active_sources),
        successful      = successful,
        failed          = failed,
        total_unique    = len(final),
        per_source      = {r.source_name: len(r.subdomains) for r in source_results},
        response_times  = {r.source_name: r.request_time   for r in source_results},
        source_statuses = {r.source_name: r.status         for r in source_results},
    )
    return final, stats


# ===============================================
# SELF-TEST
# ===============================================

if __name__ == "__main__":
    target = input("Enter domain to enumerate: ").strip()
    results, stats = enumerate_subdomains(target, return_stats=True)   # type: ignore[misc]

    print(f"\n===== SUBDOMAINS ({len(results)}) =====")
    for sub in results:
        print(f"  {sub}")

    print(f"\n===== SCAN STATS =====")
    print(f"  Total sources : {stats.total_sources}")
    print(f"  Successful    : {stats.successful}")
    print(f"  Failed        : {stats.failed}")
    print(f"  Unique subs   : {stats.total_unique}")
