from urllib.parse import urlparse, parse_qs

# ===============================================
# SCORING TABLES
# ===============================================

# URL keyword → (score, reason)
KEYWORD_SCORES = {
    # Critical targets
    "admin":        (35, "Admin panel"),
    "superuser":    (35, "Superuser endpoint"),
    "root":         (30, "Root-level path"),
    "backup":       (30, "Backup file/endpoint"),
    "debug":        (28, "Debug endpoint"),
    "phpinfo":      (28, "PHP info disclosure"),
    ".env":         (35, "Environment file"),
    ".git":         (35, "Git repository exposure"),
    "config":       (28, "Config endpoint"),
    "console":      (28, "Console endpoint"),

    # Authentication
    "login":        (30, "Login endpoint"),
    "logout":       (15, "Logout endpoint"),
    "auth":         (30, "Auth endpoint"),
    "oauth":        (30, "OAuth endpoint"),
    "sso":          (30, "SSO endpoint"),
    "token":        (28, "Token endpoint"),
    "password":     (28, "Password endpoint"),
    "reset":        (28, "Password reset"),
    "forgot":       (25, "Forgot password"),
    "register":     (20, "Registration endpoint"),
    "signup":       (20, "Signup endpoint"),
    "2fa":          (25, "2FA endpoint"),
    "mfa":          (25, "MFA endpoint"),
    "verify":       (20, "Verification endpoint"),

    # API / Data
    "api":          (25, "API endpoint"),
    "graphql":      (30, "GraphQL endpoint"),
    "webhook":      (25, "Webhook endpoint"),
    "export":       (28, "Data export"),
    "import":       (25, "Data import"),
    "download":     (22, "Download endpoint"),
    "report":       (20, "Report endpoint"),

    # User / Account
    "dashboard":    (22, "Dashboard"),
    "profile":      (20, "User profile"),
    "account":      (20, "Account endpoint"),
    "user":         (18, "User endpoint"),
    "settings":     (18, "Settings endpoint"),
    "payment":      (30, "Payment endpoint"),
    "billing":      (28, "Billing endpoint"),
    "checkout":     (25, "Checkout endpoint"),
    "order":        (20, "Order endpoint"),
    "invoice":      (22, "Invoice endpoint"),

    # File / Upload
    "upload":       (32, "File upload"),
    "file":         (25, "File endpoint"),
    "attachment":   (22, "Attachment endpoint"),
    "media":        (18, "Media endpoint"),
    "document":     (20, "Document endpoint"),

    # Sensitive paths
    "internal":     (30, "Internal endpoint"),
    "private":      (30, "Private endpoint"),
    "secret":       (35, "Secret endpoint"),
    "key":          (25, "Key endpoint"),
    "cron":         (20, "Cron/scheduled job"),
    "batch":        (20, "Batch operation"),
    "migrate":      (22, "Migration endpoint"),
    "setup":        (22, "Setup endpoint"),
    "install":      (22, "Install endpoint"),
}

# Tag → (score, reason)
TAG_SCORES = {
    "auth":         (30, "Auth tag"),
    "api":          (25, "API tag"),
    "upload":       (32, "Upload tag"),
    "admin":        (35, "Admin tag"),
    "payment":      (30, "Payment tag"),
    "internal":     (30, "Internal tag"),
    "debug":        (28, "Debug tag"),
    "redirect":     (20, "Redirect tag"),
    "graphql":      (28, "GraphQL tag"),
    "idor":         (25, "IDOR candidate tag"),
    "sqli":         (25, "SQLi candidate tag"),
    "xss":          (20, "XSS candidate tag"),
    "ssrf":         (28, "SSRF candidate tag"),
    "lfi":          (28, "LFI candidate tag"),
    "rce":          (35, "RCE candidate tag"),
    "ssti":         (32, "SSTI candidate tag"),
}

# Interesting parameter names → (score, reason)
PARAM_SCORES = {
    # IDOR / SQLi
    "id":           (15, "ID parameter"),
    "user_id":      (18, "User ID parameter"),
    "account_id":   (18, "Account ID parameter"),
    "order_id":     (18, "Order ID parameter"),
    "uid":          (15, "UID parameter"),

    # Redirect / SSRF
    "redirect":     (20, "Redirect parameter"),
    "url":          (20, "URL parameter"),
    "next":         (18, "Next parameter"),
    "return":       (18, "Return parameter"),
    "callback":     (18, "Callback parameter"),
    "dest":         (18, "Destination parameter"),
    "target":       (18, "Target parameter"),
    "proxy":        (20, "Proxy parameter"),
    "webhook":      (20, "Webhook parameter"),
    "endpoint":     (20, "Endpoint parameter"),

    # File / LFI
    "file":         (20, "File parameter"),
    "path":         (20, "Path parameter"),
    "include":      (22, "Include parameter"),
    "template":     (22, "Template parameter"),
    "page":         (15, "Page parameter"),
    "load":         (18, "Load parameter"),

    # RCE / injection
    "cmd":          (30, "Command parameter"),
    "exec":         (30, "Exec parameter"),
    "command":      (30, "Command parameter"),
    "shell":        (30, "Shell parameter"),
    "run":          (25, "Run parameter"),
    "ping":         (20, "Ping parameter"),

    # Auth
    "token":        (22, "Token parameter"),
    "key":          (22, "Key parameter"),
    "api_key":      (25, "API key parameter"),
    "secret":       (25, "Secret parameter"),
    "password":     (25, "Password parameter"),
}

# Priority tiers
TIERS = [
    (80, "CRITICAL"),
    (55, "HIGH"),
    (30, "MEDIUM"),
    (0,  "LOW"),
]


# ===============================================
# CORE SCORER
# ===============================================

def calculate_priority(endpoint):
    """
    Score an endpoint across multiple signal dimensions and assign a priority tier.

    Args:
        endpoint: dict with 'url' and optional 'tags', 'technologies'

    Returns:
        dict with url, score, priority, reasons
    """
    url          = endpoint.get("url", "")
    tags         = [t.lower() for t in endpoint.get("tags", [])]
    technologies = [t.lower() for t in endpoint.get("technologies", [])]

    if not url:
        return {"url": url, "score": 0, "priority": "LOW", "reasons": []}

    url_lower = url.lower()
    score     = 0
    reasons   = []
    seen      = set()  # Avoid duplicate reasons

    def add(pts, reason):
        if reason not in seen:
            seen.add(reason)
            score_ref.append(pts)
            reasons.append(f"+{pts} {reason}")

    score_ref = []  # Mutable container so add() can append

    # ── 1. URL keyword scoring ─────────────────────
    for keyword, (pts, reason) in KEYWORD_SCORES.items():
        if keyword in url_lower:
            add(pts, reason)

    # ── 2. Parameter scoring ───────────────────────
    try:
        parsed = urlparse(url)
        params = parse_qs(parsed.query)

        if params:
            add(15, "Has query parameters")

        for param in params:
            param_lower = param.lower()
            if param_lower in PARAM_SCORES:
                pts, reason = PARAM_SCORES[param_lower]
                add(pts, reason)

        # Numeric param values → IDOR signal
        import re
        for param, values in params.items():
            for val in values:
                if re.fullmatch(r'\d+', val):
                    add(12, f"Numeric value in '{param}' (IDOR signal)")
                    break

        # Many params = larger attack surface
        if len(params) >= 4:
            add(10, f"Large attack surface ({len(params)} parameters)")
        elif len(params) >= 2:
            add(5, f"Multiple parameters ({len(params)})")

    except Exception:
        pass

    # ── 3. Tag scoring ─────────────────────────────
    for tag in tags:
        if tag in TAG_SCORES:
            pts, reason = TAG_SCORES[tag]
            add(pts, reason)

    # ── 4. Path depth heuristic ────────────────────
    try:
        path = urlparse(url).path
        depth = len([s for s in path.split("/") if s])
        if depth >= 4:
            add(8, f"Deep path (depth {depth}) — less likely to be filtered")
        elif depth >= 2:
            add(4, f"Moderate path depth ({depth})")
    except Exception:
        pass

    # ── 5. File extension signals ──────────────────
    sensitive_exts = {
        ".php": (8,  "PHP endpoint"),
        ".asp": (8,  "ASP endpoint"),
        ".aspx":(8,  "ASPX endpoint"),
        ".jsp": (8,  "JSP endpoint"),
        ".env": (30, ".env file"),
        ".sql": (30, "SQL file"),
        ".bak": (28, "Backup file"),
        ".log": (20, "Log file"),
        ".xml": (10, "XML file"),
        ".json":(10, "JSON file"),
        ".yaml":(15, "YAML config"),
        ".yml": (15, "YAML config"),
    }
    for ext, (pts, reason) in sensitive_exts.items():
        if url_lower.endswith(ext) or f"{ext}?" in url_lower:
            add(pts, reason)
            break

    # ── 6. Technology-aware boosts ─────────────────
    if any(t in technologies for t in ["wordpress", "drupal", "joomla"]):
        add(15, "CMS detected — known vuln surface")
    if any(t in technologies for t in ["php", "asp", "jsp"]):
        add(8, "Server-side language detected")
    if "graphql" in technologies:
        add(20, "GraphQL detected")

    # ── 7. HTTPS vs HTTP ───────────────────────────
    if url.startswith("http://"):
        add(10, "Unencrypted HTTP — credentials transmitted in plaintext")

    # Tally final score
    score = sum(score_ref)

    # ── Priority tier ──────────────────────────────
    priority = "LOW"
    for threshold, tier in TIERS:
        if score >= threshold:
            priority = tier
            break

    return {
        "url":      url,
        "score":    score,
        "priority": priority,
        "reasons":  reasons
    }


# ===============================================
# BATCH PRIORITIZER
# ===============================================

def prioritize_all(endpoints):
    """
    Score and rank all endpoints.

    Args:
        endpoints: list of endpoint dicts (url, tags, technologies)

    Returns:
        list of priority dicts sorted by score descending
    """
    seen_urls = set()
    results   = []

    for ep in endpoints:
        url = ep.get("url", "") if isinstance(ep, dict) else ep
        if url in seen_urls:
            continue
        seen_urls.add(url)

        item = ep if isinstance(ep, dict) else {"url": url}
        results.append(calculate_priority(item))

    results.sort(key=lambda x: x["score"], reverse=True)
    return results


# ===============================================
# FILTER / SUMMARY HELPERS
# ===============================================

def filter_by_priority(results, priority):
    """Return endpoints matching a specific priority tier."""
    return [r for r in results if r["priority"] == priority]


def summarize(results):
    """Return count per priority tier."""
    summary = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for r in results:
        tier = r.get("priority", "LOW")
        if tier in summary:
            summary[tier] += 1
    summary["total"] = len(results)
    return summary


def top_targets(results, n=10):
    """Return top N highest-scored endpoints."""
    return results[:n]


# ===============================================
# SELF-TEST
# ===============================================

if __name__ == "__main__":
    test_endpoints = [
        {"url": "https://example.com/admin/dashboard",         "tags": ["admin"]},
        {"url": "https://example.com/api/v1/users?id=42",      "tags": ["api"]},
        {"url": "https://example.com/login?next=/home",        "tags": ["auth"]},
        {"url": "https://example.com/upload/avatar",           "tags": ["upload"]},
        {"url": "https://example.com/graphql",                 "tags": ["api", "graphql"]},
        {"url": "https://example.com/profile?user_id=1",       "tags": []},
        {"url": "https://example.com/fetch?url=http://evil",   "tags": ["ssrf"]},
        {"url": "https://example.com/render?template={{7*7}}", "tags": ["ssti"]},
        {"url": "http://example.com/checkout?order_id=99",     "tags": ["payment"]},
        {"url": "https://example.com/static/logo.png",         "tags": []},
        {"url": "https://example.com/.env",                    "tags": []},
        {"url": "https://example.com/search?q=hello&lang=en",  "tags": []},
    ]

    results = prioritize_all(test_endpoints)

    print(f"{'PRIORITY':<10} {'SCORE':<7} URL")
    print("-" * 80)
    for r in results:
        print(f"{r['priority']:<10} {r['score']:<7} {r['url']}")
        for reason in r["reasons"]:
            print(f"           {reason}")
        print()

    print("Summary:", summarize(results))
    print("Top 3 targets:")
    for t in top_targets(results, 3):
        print(f"  [{t['priority']}] {t['url']} (score={t['score']})")