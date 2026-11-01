from urllib.parse import urlparse, parse_qs

# ===============================================
# TAG DEFINITIONS
# Each entry: (tag, [path/keyword signals], [param signals])
# ===============================================

TAG_RULES = [
    # ── Authentication ────────────────────────
    (
        "AUTH",
        ["login", "signin", "sign-in", "logout", "sign-out",
         "auth", "oauth", "authorize", "authentication",
         "sso", "saml", "2fa", "mfa", "totp",
         "forgot-password", "reset-password", "verify-email",
         "password-reset", "activate", "confirm"],
        ["token", "access_token", "id_token", "refresh_token",
         "code", "state", "nonce", "session"]
    ),

    # ── Registration ──────────────────────────
    (
        "REGISTER",
        ["register", "signup", "sign-up", "create-account",
         "new-user", "enroll", "onboard"],
        ["username", "email", "password", "confirm_password"]
    ),

    # ── API ───────────────────────────────────
    (
        "API",
        ["/api/", "/api/v1", "/api/v2", "/api/v3", "/api/v4",
         "/rest/", "/rpc/", "/service/", "/services/",
         "graphql", "/gql", "/__graphql"],
        []
    ),

    # ── Admin / Control ───────────────────────
    (
        "ADMIN",
        ["admin", "administrator", "dashboard", "panel",
         "backend", "backoffice", "console", "manage",
         "manager", "control", "superadmin", "superuser",
         "staff", "moderator", "cp/"],
        ["role", "permission", "privilege"]
    ),

    # ── User / Account ────────────────────────
    (
        "USER",
        ["user", "users", "profile", "account", "accounts",
         "member", "members", "me/", "/me", "identity",
         "customer", "subscriber", "person"],
        ["user_id", "uid", "account_id", "profile_id", "member_id"]
    ),

    # ── Payment / Billing ─────────────────────
    (
        "PAYMENT",
        ["payment", "payments", "pay", "checkout", "billing",
         "invoice", "invoices", "subscription", "subscriptions",
         "order", "orders", "purchase", "transaction",
         "stripe", "paypal", "card", "refund", "charge"],
        ["amount", "price", "currency", "card_number",
         "billing_id", "order_id", "invoice_id"]
    ),

    # ── File / Upload / Download ──────────────
    (
        "FILE",
        ["upload", "uploads", "download", "downloads",
         "export", "exports", "import", "imports",
         "file", "files", "attachment", "attachments",
         "media", "document", "documents", "report",
         "csv", "pdf", "xlsx", "zip"],
        ["file", "filename", "path", "download", "attachment"]
    ),

    # ── Search ───────────────────────────────
    (
        "SEARCH",
        ["search", "find", "query", "lookup", "filter",
         "browse", "explore", "suggest", "autocomplete"],
        ["q", "s", "search", "query", "keyword", "term", "find"]
    ),

    # ── Redirect / Callback ───────────────────
    (
        "REDIRECT",
        ["redirect", "callback", "return", "forward",
         "goto", "continue", "next", "redir"],
        ["redirect", "redirect_uri", "return_url", "next",
         "callback", "goto", "continue", "dest", "destination",
         "forward", "return", "redir", "url", "target"]
    ),

    # ── Sensitive / Secrets ───────────────────
    (
        "SENSITIVE",
        ["token", "tokens", "key", "keys", "secret",
         "secrets", "credential", "credentials", "private",
         "config", "configuration", "env", "environment",
         "backup", "backups", "debug", "internal"],
        ["token", "key", "api_key", "secret", "password",
         "passwd", "pwd", "credential", "auth_token"]
    ),

    # ── IDOR Candidate ────────────────────────
    (
        "IDOR",
        [],
        ["id", "user_id", "account_id", "order_id", "uid",
         "pid", "record_id", "doc_id", "file_id", "invoice_id",
         "customer_id", "profile_id", "object_id", "item_id"]
    ),

    # ── Injection Candidate ───────────────────
    (
        "INJECT",
        [],
        ["q", "search", "query", "input", "text", "data",
         "comment", "message", "name", "title", "body",
         "content", "description", "filter", "sort", "order"]
    ),

    # ── SSRF Candidate ────────────────────────
    (
        "SSRF",
        ["fetch", "proxy", "webhook", "request"],
        ["url", "uri", "endpoint", "proxy", "host", "dest",
         "target", "source", "fetch", "request", "webhook",
         "site", "domain", "link", "href"]
    ),

    # ── LFI Candidate ─────────────────────────
    (
        "LFI",
        ["include", "require", "load", "template"],
        ["file", "path", "page", "include", "template",
         "load", "read", "dir", "folder", "document",
         "view", "layout", "module", "component"]
    ),

    # ── RCE Candidate ─────────────────────────
    (
        "RCE",
        ["exec", "execute", "run", "shell", "cmd",
         "command", "eval", "process", "invoke"],
        ["cmd", "exec", "command", "shell", "run",
         "input", "ping", "query", "script"]
    ),

    # ── WebSocket ─────────────────────────────
    (
        "WEBSOCKET",
        ["ws://", "wss://", "/ws", "/wss", "websocket",
         "socket.io", "/socket", "/realtime", "/live"],
        []
    ),

    # ── GraphQL ───────────────────────────────
    (
        "GRAPHQL",
        ["graphql", "/gql", "/__graphql", "/graphiql"],
        ["query", "mutation", "subscription", "operationName"]
    ),

    # ── Debug / Info Disclosure ───────────────
    (
        "DEBUG",
        ["debug", "phpinfo", "info.php", "test", "dev",
         "staging", "health", "healthcheck", "status",
         "metrics", "actuator", "trace", "diagnostic",
         "server-status", "server-info", ".env", ".git"],
        ["debug", "trace", "verbose", "test"]
    ),
]

# File extensions that hint at content type
EXTENSION_TAGS = {
    ".php":  ["API"],
    ".asp":  ["API"],
    ".aspx": ["API"],
    ".jsp":  ["API"],
    ".json": ["API"],
    ".xml":  ["API"],
    ".pdf":  ["FILE"],
    ".csv":  ["FILE"],
    ".xlsx": ["FILE"],
    ".zip":  ["FILE"],
    ".sql":  ["SENSITIVE"],
    ".env":  ["SENSITIVE"],
    ".bak":  ["SENSITIVE"],
    ".log":  ["DEBUG"],
    ".conf": ["SENSITIVE"],
    ".yaml": ["SENSITIVE"],
    ".yml":  ["SENSITIVE"],
}

# Tag priority for picking the "primary" tag
TAG_PRIORITY = [
    "RCE", "SENSITIVE", "ADMIN", "PAYMENT", "AUTH",
    "SSRF", "LFI", "IDOR", "GRAPHQL", "API",
    "FILE", "REDIRECT", "USER", "REGISTER",
    "SEARCH", "INJECT", "WEBSOCKET", "DEBUG", "GENERAL"
]


# ===============================================
# CORE CLASSIFIER
# ===============================================

def classify_endpoint(url):
    """
    Classify a URL endpoint into one or more semantic tags.

    Args:
        url: Full URL string

    Returns:
        list of tag strings (e.g. ["AUTH", "API", "IDOR"])
    """
    if not url:
        return ["GENERAL"]

    url_lower = url.lower()
    tags      = set()

    # Parse URL components
    try:
        parsed = urlparse(url)
        path   = parsed.path.lower()
        params = set(parse_qs(parsed.query).keys())
    except Exception:
        path   = url_lower
        params = set()

    # ── Apply tag rules ────────────────────────
    for tag, path_signals, param_signals in TAG_RULES:
        # Path match
        if any(sig in url_lower for sig in path_signals):
            tags.add(tag)
            continue

        # Parameter match
        if params and any(p.lower() in {s.lower() for s in param_signals} for p in params):
            tags.add(tag)

    # ── File extension tags ────────────────────
    try:
        ext = "." + path.rsplit(".", 1)[-1].split("?")[0] if "." in path else ""
        for extension, ext_tags in EXTENSION_TAGS.items():
            if path.endswith(extension) or url_lower.endswith(extension):
                tags.update(ext_tags)
    except Exception:
        pass

    # ── Numeric ID in path → IDOR signal ──────
    import re
    if re.search(r'/\d{1,10}(?:/|$|\?)', path):
        tags.add("IDOR")

    # ── Has parameters at all → INJECT signal ─
    if params and "INJECT" not in tags:
        # Only add INJECT if no stronger tag already covers it
        strong_tags = {"RCE", "LFI", "SSRF", "IDOR", "SENSITIVE"}
        if not tags.intersection(strong_tags):
            tags.add("INJECT")

    return sorted(tags) if tags else ["GENERAL"]


# ===============================================
# PRIMARY TAG (for sorting/prioritization)
# ===============================================

def primary_tag(tags):
    """
    Return the single highest-priority tag from a list.
    Useful for sorting endpoints by criticality.

    Args:
        tags: list of tag strings

    Returns:
        str: highest priority tag
    """
    for t in TAG_PRIORITY:
        if t in tags:
            return t
    return "GENERAL"


# ===============================================
# BATCH CLASSIFIER
# ===============================================

def classify_all(endpoints):
    """
    Classify a list of endpoints and attach tags + primary tag.

    Args:
        endpoints: list of URL strings or dicts with 'url' key

    Returns:
        list of dicts with url, tags, primary_tag
    """
    results = []
    for ep in endpoints:
        url = ep["url"] if isinstance(ep, dict) else ep
        tags = classify_endpoint(url)
        results.append({
            "url":         url,
            "tags":        tags,
            "primary_tag": primary_tag(tags)
        })
    return results


# ===============================================
# SELF-TEST
# ===============================================

if __name__ == "__main__":
    test_urls = [
        "https://example.com/api/v1/users?id=42",
        "https://example.com/admin/dashboard",
        "https://example.com/login?next=/home",
        "https://example.com/upload/avatar",
        "https://example.com/graphql",
        "https://example.com/profile?user_id=1",
        "https://example.com/fetch?url=http://evil.com",
        "https://example.com/render?template={{7*7}}",
        "https://example.com/checkout?order_id=99",
        "https://example.com/search?q=hello&lang=en",
        "https://example.com/.env",
        "https://example.com/exec?cmd=whoami",
        "https://example.com/ws/realtime",
        "https://example.com/static/logo.png",
        "https://example.com/debug/status",
        "https://example.com/api/v2/orders/1234/invoice",
    ]

    print(f"{'PRIMARY':<12} {'TAGS':<45} URL")
    print("-" * 100)
    for url in test_urls:
        tags = classify_endpoint(url)
        ptag = primary_tag(tags)
        print(f"{ptag:<12} {str(tags):<45} {url}")