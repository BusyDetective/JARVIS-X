import requests
import urllib3
from concurrent.futures import ThreadPoolExecutor, as_completed

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/120.0.0.0 Safari/537.36"
    )
}

# ===============================================
# WORDLIST
# Each entry: (path, severity, reason)
# ===============================================

WORDLIST = [
    # Admin / Control panels
    ("admin",                   "High",     "Admin panel"),
    ("admin/login",             "High",     "Admin login"),
    ("admin/dashboard",         "High",     "Admin dashboard"),
    ("administrator",           "High",     "Administrator panel"),
    ("dashboard",               "Medium",   "Dashboard"),
    ("panel",                   "Medium",   "Control panel"),
    ("cp",                      "Medium",   "Control panel"),
    ("superadmin",              "High",     "Superadmin panel"),
    ("manager",                 "Medium",   "Manager panel"),
    ("manage",                  "Medium",   "Manage endpoint"),
    ("console",                 "High",     "Console endpoint"),
    ("backend",                 "High",     "Backend endpoint"),

    # Authentication
    ("login",                   "Medium",   "Login page"),
    ("signin",                  "Medium",   "Sign-in page"),
    ("signup",                  "Medium",   "Sign-up page"),
    ("register",                "Medium",   "Registration page"),
    ("logout",                  "Low",      "Logout endpoint"),
    ("auth",                    "Medium",   "Auth endpoint"),
    ("oauth",                   "Medium",   "OAuth endpoint"),
    ("sso",                     "Medium",   "SSO endpoint"),
    ("forgot-password",         "Medium",   "Password reset"),
    ("reset-password",          "Medium",   "Password reset"),

    # APIs
    ("api",                     "Medium",   "API root"),
    ("api/v1",                  "Medium",   "API v1"),
    ("api/v2",                  "Medium",   "API v2"),
    ("api/v3",                  "Medium",   "API v3"),
    ("api/admin",               "High",     "Admin API"),
    ("api/internal",            "High",     "Internal API"),
    ("api/users",               "High",     "Users API"),
    ("api/export",              "High",     "Export API"),
    ("graphql",                 "High",     "GraphQL endpoint"),
    ("swagger",                 "Medium",   "Swagger docs"),
    ("swagger-ui",              "Medium",   "Swagger UI"),
    ("swagger.json",            "Medium",   "Swagger JSON"),
    ("openapi.json",            "Medium",   "OpenAPI spec"),
    ("api-docs",                "Medium",   "API docs"),

    # Sensitive files
    (".env",                    "Critical", "Environment file"),
    (".env.local",              "Critical", "Local env file"),
    (".env.production",         "Critical", "Production env file"),
    (".git",                    "Critical", "Git repository"),
    (".git/config",             "Critical", "Git config"),
    (".git/HEAD",               "Critical", "Git HEAD"),
    ("config",                  "High",     "Config endpoint"),
    ("config.php",              "Critical", "PHP config"),
    ("config.json",             "High",     "JSON config"),
    ("configuration",           "High",     "Configuration"),
    ("settings",                "Medium",   "Settings"),
    ("web.config",              "Critical", "Web.config"),
    ("app.config",              "High",     "App config"),

    # Backup / Debug
    ("backup",                  "High",     "Backup directory"),
    ("backups",                 "High",     "Backups directory"),
    ("backup.zip",              "Critical", "Backup archive"),
    ("backup.tar.gz",           "Critical", "Backup archive"),
    ("db.sql",                  "Critical", "Database dump"),
    ("database.sql",            "Critical", "Database dump"),
    ("dump.sql",                "Critical", "Database dump"),
    ("debug",                   "High",     "Debug endpoint"),
    ("test",                    "Medium",   "Test endpoint"),
    ("dev",                     "Medium",   "Dev endpoint"),
    ("staging",                 "Medium",   "Staging endpoint"),
    ("phpinfo.php",             "High",     "PHP info"),
    ("info.php",                "High",     "PHP info"),
    ("php-info.php",            "High",     "PHP info"),

    # Uploads / Files
    ("uploads",                 "Medium",   "Upload directory"),
    ("upload",                  "Medium",   "Upload endpoint"),
    ("files",                   "Medium",   "Files directory"),
    ("media",                   "Low",      "Media directory"),
    ("static",                  "Low",      "Static files"),
    ("assets",                  "Low",      "Assets directory"),
    ("images",                  "Low",      "Images directory"),
    ("documents",               "Medium",   "Documents directory"),
    ("attachments",             "Medium",   "Attachments"),

    # Internal / Infra
    ("internal",                "High",     "Internal endpoint"),
    ("private",                 "High",     "Private endpoint"),
    ("health",                  "Low",      "Health check"),
    ("healthcheck",             "Low",      "Health check"),
    ("status",                  "Low",      "Status endpoint"),
    ("metrics",                 "Medium",   "Metrics endpoint"),
    ("actuator",                "High",     "Spring Boot actuator"),
    ("actuator/env",            "Critical", "Actuator env dump"),
    ("actuator/health",         "Medium",   "Actuator health"),
    ("actuator/mappings",       "High",     "Actuator mappings"),
    ("server-status",           "Medium",   "Apache server status"),
    ("server-info",             "Medium",   "Apache server info"),
    (".htaccess",               "High",     "Apache htaccess"),
    ("robots.txt",              "Low",      "Robots.txt"),
    ("sitemap.xml",             "Low",      "Sitemap"),
    ("crossdomain.xml",         "Low",      "Crossdomain policy"),
    ("security.txt",            "Low",      "Security.txt"),
    (".well-known/security.txt","Low",      "Security.txt"),

    # Common frameworks
    ("wp-admin",                "High",     "WordPress admin"),
    ("wp-login.php",            "High",     "WordPress login"),
    ("wp-config.php",           "Critical", "WordPress config"),
    ("wp-json/wp/v2/users",     "High",     "WordPress users API"),
    ("phpmyadmin",              "Critical", "phpMyAdmin"),
    ("pma",                     "Critical", "phpMyAdmin"),
    ("adminer.php",             "Critical", "Adminer DB tool"),
    ("laravel",                 "Low",      "Laravel framework"),
    ("telescope",               "High",     "Laravel Telescope"),
    ("horizon",                 "High",     "Laravel Horizon"),
    ("django-admin",            "High",     "Django admin"),
    ("admin/",                  "High",     "Admin trailing slash"),
    ("jenkins",                 "High",     "Jenkins CI"),
    ("jira",                    "Medium",   "Jira"),
    ("confluence",              "Medium",   "Confluence"),
    ("kibana",                  "High",     "Kibana dashboard"),
    ("grafana",                 "High",     "Grafana dashboard"),
    ("portainer",               "High",     "Portainer Docker UI"),
    ("traefik",                 "High",     "Traefik dashboard"),
]

# Status codes that indicate a real finding
INTERESTING_CODES = {200, 201, 204, 301, 302, 307, 308, 401, 403}

# Status codes that indicate auth-protected but real endpoint
AUTH_CODES = {401, 403}

# Severity ordering for sorting
SEVERITY_RANK = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1}


# ===============================================
# HELPERS
# ===============================================

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


def _get(url, allow_redirects=False, timeout=6):
    """Safe GET. Returns response or None."""
    try:
        return requests.get(
            url,
            headers=HEADERS,
            timeout=timeout,
            allow_redirects=allow_redirects,
            verify=False
        )
    except Exception:
        return None


# ===============================================
# PER-HOST FUZZER
# ===============================================

def _fuzz_host(base_url):
    """
    Fuzz a single host against the full wordlist.
    Returns list of finding dicts.
    """
    base_url = base_url.rstrip("/")
    found    = []

    # Establish baseline with a nonexistent path
    baseline_res = _get(f"{base_url}/____does_not_exist_xyz____")
    baseline_len = len(baseline_res.text) if baseline_res else 0

    for path, severity, reason in WORDLIST:
        target = f"{base_url}/{path}"
        res    = _get(target, allow_redirects=False)

        if res is None:
            continue

        code    = res.status_code
        content = res.text
        length  = len(content)

        if code not in INTERESTING_CODES:
            continue

        # Soft 404 filter — skip if response looks identical to baseline
        if code == 200 and abs(length - baseline_len) < 50:
            continue

        # Follow redirect to get final destination
        redirect_to = None
        if code in (301, 302, 307, 308):
            redirect_to = res.headers.get("Location", "")

        title = _extract_title(content)

        # Auth-protected endpoints are still interesting
        note = ""
        if code in AUTH_CODES:
            note = "Auth-protected — test for bypass"

        found.append({
            "url":         target,
            "status":      code,
            "severity":    severity,
            "reason":      reason,
            "title":       title,
            "length":      length,
            "redirect_to": redirect_to,
            "note":        note,
        })

    return found


# ===============================================
# MAIN ENTRY POINT
# ===============================================

def fuzz_directories(hosts, max_workers=20):
    """
    Run directory fuzzing across all live hosts in parallel.

    Args:
        hosts:       list of host dicts with 'url' key, or URL strings
        max_workers: thread pool size (per-host tasks run concurrently)

    Returns:
        list of finding dicts sorted by severity then status code
    """
    if not hosts:
        return []

    print(f"[+] Directory fuzzing {len(hosts)} host(s) — {len(WORDLIST)} paths each...\n")

    all_found = []
    seen_urls = set()

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {}
        for host in hosts:
            url = host["url"] if isinstance(host, dict) else host
            futures[executor.submit(_fuzz_host, url)] = url

        for future in as_completed(futures):
            host_url = futures[future]
            try:
                results = future.result()
                for r in results:
                    if r["url"] not in seen_urls:
                        seen_urls.add(r["url"])
                        all_found.append(r)
            except Exception as e:
                print(f"[-] Fuzzing error on {host_url}: {e}")

    # Sort: severity descending, then status code
    all_found.sort(key=lambda r: (
        -SEVERITY_RANK.get(r["severity"], 0),
        r["status"]
    ))

    # Summary
    from collections import Counter
    by_severity = Counter(r["severity"] for r in all_found)
    print(f"\n[+] Directory fuzzing complete: {len(all_found)} paths found")
    for sev in ["Critical", "High", "Medium", "Low"]:
        if by_severity.get(sev):
            print(f"    {sev}: {by_severity[sev]}")

    return all_found


# ===============================================
# SELF-TEST
# ===============================================

if __name__ == "__main__":
    test_hosts = [
        {"url": "https://example.com"},
        {"url": "https://httpbin.org"},
    ]

    results = fuzz_directories(test_hosts)

    print("\n===== FINDINGS =====")
    for r in results:
        redir = f" → {r['redirect_to']}" if r.get("redirect_to") else ""
        note  = f" [{r['note']}]" if r.get("note") else ""
        print(
            f"  [{r['severity']}] [{r['status']}] {r['url']}"
            f"{redir}{note}"
        )