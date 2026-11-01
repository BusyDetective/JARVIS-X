import requests
import os
import urllib3
from concurrent.futures import ThreadPoolExecutor, as_completed
from utils.logger import warning

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/120.0.0.0 Safari/537.36"
    )
}

# Extensions to skip entirely
SKIP_EXTENSIONS = {
    ".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg",
    ".woff", ".woff2", ".ttf", ".ico", ".pdf", ".mp4", ".mp3",
    ".webp", ".map", ".eot"
}

# Status codes worth reporting
INTERESTING_CODES = {200, 201, 204, 301, 302, 307, 308, 401, 403, 405, 500}

# Built-in wordlist used when wordlist.txt is missing
BUILTIN_WORDLIST = [
    # Admin / Control
    "admin", "admin/login", "admin/dashboard", "administrator",
    "dashboard", "panel", "console", "backend", "manage", "superadmin",
    "cp", "staff", "moderator",

    # Auth
    "login", "logout", "signin", "signup", "register",
    "auth", "oauth", "sso", "2fa", "mfa",
    "forgot-password", "reset-password", "verify",

    # API
    "api", "api/v1", "api/v2", "api/v3",
    "api/users", "api/admin", "api/internal", "api/export",
    "graphql", "graphiql", "swagger", "swagger-ui",
    "swagger.json", "openapi.json", "api-docs",

    # User / Account
    "profile", "account", "user", "users", "settings",
    "me", "members", "customer",

    # File / Upload
    "upload", "uploads", "download", "downloads",
    "export", "import", "files", "media",
    "documents", "attachments", "reports",

    # Payment
    "payment", "checkout", "billing", "invoice",
    "orders", "subscriptions",

    # Sensitive files
    ".env", ".env.local", ".env.production",
    ".git", ".git/config", ".git/HEAD",
    "config", "config.php", "config.json",
    "web.config", "app.config", "settings.py",
    "backup", "backups", "backup.zip", "db.sql",
    "database.sql", "dump.sql",

    # Debug / Info
    "debug", "test", "dev", "staging", "phpinfo.php",
    "info.php", "health", "healthcheck", "status",
    "metrics", "actuator", "actuator/env",
    "server-status", ".htaccess", "robots.txt",
    "sitemap.xml", "crossdomain.xml",

    # Search
    "search", "find", "query", "filter",

    # Misc
    "internal", "private", "secret", "webhook",
    "callback", "redirect", "proxy", "fetch",
    "cron", "batch", "jobs", "migrate", "setup", "install",

    # Framework-specific
    "wp-admin", "wp-login.php", "wp-json/wp/v2/users",
    "phpmyadmin", "pma", "adminer.php",
    "telescope", "horizon", "django-admin",
    "jenkins", "kibana", "grafana", "portainer",
]


# ===============================================
# HELPERS
# ===============================================

def _load_wordlist(limit=500):
    """
    Load words from wordlist.txt relative to this file's parent directory.
    Falls back to BUILTIN_WORDLIST if the file is missing or empty.
    """
    try:
        base_dir      = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
        wordlist_path = os.path.join(base_dir, "wordlist.txt")

        with open(wordlist_path, "r", encoding="utf-8", errors="ignore") as f:
            words = [line.strip() for line in f if line.strip()]

        if words:
            print(f"[+] Loaded {len(words)} words from wordlist.txt")
            return words[:limit]

    except FileNotFoundError:
        pass
    except Exception as e:
        print(f"[!] wordlist.txt error: {e}")

    print("[!] wordlist.txt not found — using built-in wordlist")
    return BUILTIN_WORDLIST[:limit]


def _is_static(url):
    """Return True if the URL points to a static asset."""
    path = url.split("?")[0].lower()
    return any(path.endswith(ext) for ext in SKIP_EXTENSIONS)


def _get_baseline(base_url):
    """
    Fetch a known-nonexistent path to establish soft-404 fingerprint.
    Returns (status_code, body_length).
    """
    probe = f"{base_url.rstrip('/')}/____probe_xyz_does_not_exist____"
    try:
        res = requests.get(
            probe,
            headers=HEADERS,
            timeout=6,
            allow_redirects=True,
            verify=False
        )
        return res.status_code, len(res.text)
    except Exception:
        return 404, 0


def _extract_title(html):
    """Extract page title from HTML."""
    try:
        lower = html.lower()
        s = lower.find("<title>")
        e = lower.find("</title>")
        if s != -1 and e != -1:
            return html[s + 7:e].strip()[:100]
    except Exception:
        pass
    return ""


# ===============================================
# SINGLE ENDPOINT SCANNER
# ===============================================

def scan_endpoint(base_url, word, baseline_status, baseline_len):
    """
    Probe a single path on a base URL.

    Returns a finding dict or None.
    """
    word = word.strip().lstrip("/")

    if not word:
        return None

    url = f"{base_url.rstrip('/')}/{word}"

    if _is_static(url):
        return None

    try:
        res = requests.get(
            url,
            headers=HEADERS,
            timeout=5,
            allow_redirects=False,
            verify=False
        )

        code = res.status_code

        if code not in INTERESTING_CODES:
            return None

        # Soft-404 filter: skip if status and length match baseline
        if code == baseline_status and abs(len(res.text) - baseline_len) < 50:
            return None

        redirect_to = res.headers.get("Location", "") if code in (301, 302, 307, 308) else ""
        title       = _extract_title(res.text)
        note        = "Auth-protected" if code in (401, 403) else ""

        return {
            "url":         url,
            "word":        word,
            "status":      code,
            "length":      len(res.text),
            "title":       title,
            "redirect_to": redirect_to,
            "note":        note,
        }

    except requests.exceptions.Timeout:
        return None
    except Exception:
        return None


# ===============================================
# MAIN ENTRY POINT
# ===============================================

def find_endpoints(alive_hosts, max_words=500, max_workers=30):
    """
    Discover endpoints on all live hosts by probing a wordlist.

    Args:
        alive_hosts:  list of host dicts with 'url' key, or URL strings
        max_words:    cap on wordlist size
        max_workers:  thread pool size

    Returns:
        list of endpoint dicts: {url, status, title, redirect_to, note}
    """
    if not alive_hosts:
        return []

    words = _load_wordlist(limit=max_words)

    print(f"\n[+] Endpoint discovery: {len(alive_hosts)} host(s) × {len(words)} words "
          f"= {len(alive_hosts) * len(words)} probes\n")

    all_endpoints = []
    seen_urls     = set()

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {}

        for host in alive_hosts:
            base_url = host["url"] if isinstance(host, dict) else host

            # Get soft-404 baseline per host
            baseline_status, baseline_len = _get_baseline(base_url)

            for word in words:
                # Pre-filter obvious static paths from wordlist
                if any(word.lower().endswith(ext) for ext in SKIP_EXTENSIONS):
                    continue

                future = executor.submit(
                    scan_endpoint,
                    base_url,
                    word,
                    baseline_status,
                    baseline_len
                )
                futures[future] = base_url

        for future in as_completed(futures):
            try:
                result = future.result()

                if result and result["url"] not in seen_urls:
                    seen_urls.add(result["url"])
                    all_endpoints.append(result)

                    label = (
                        f"[{result['status']}] {result['url']}"
                        + (f" → {result['redirect_to']}" if result.get("redirect_to") else "")
                        + (f" [{result['note']}]"        if result.get("note")         else "")
                        + (f" | {result['title']}"       if result.get("title")        else "")
                    )
                    warning(label)

            except Exception as e:
                print(f"[-] Endpoint scan error: {e}")

    # Sort: auth/error codes first, then 200s
    priority = {200: 2, 201: 2, 403: 1, 401: 1, 500: 1, 301: 3, 302: 3}
    all_endpoints.sort(key=lambda r: priority.get(r["status"], 5))

    print(f"\n[+] Endpoint discovery complete: {len(all_endpoints)} endpoints found\n")

    return all_endpoints


# ===============================================
# SELF-TEST
# ===============================================

if __name__ == "__main__":
    test_hosts = [
        {"url": "https://httpbin.org"},
    ]

    results = find_endpoints(test_hosts, max_words=50)

    print("\n===== ENDPOINTS =====")
    for r in results:
        print(
            f"  [{r['status']}] {r['url']}"
            + (f" → {r['redirect_to']}" if r.get("redirect_to") else "")
            + (f" | {r['title']}"       if r.get("title")        else "")
        )