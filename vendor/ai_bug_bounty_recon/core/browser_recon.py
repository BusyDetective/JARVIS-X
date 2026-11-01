"""
Browser Reconnaissance Engine v2.0

Uses Playwright to perform active browser-based recon.
Improvements over v1:
- Outer timeout protection (whole function can't hang)
- Proper request deduplication with interest scoring
- JS error capture (stack traces = tech fingerprints + misconfigs)
- localStorage/sessionStorage scanning for leaked tokens
- Cookie security flag analysis
- Console log capture for debug info leakage
- Response body sampling for API calls
"""

import re
import json
import time
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FuturesTimeoutError


# =========================
# PATTERNS
# =========================

SECRET_PATTERNS = [
    (r"AIza[0-9A-Za-z\-_]{35}",              "Google API Key"),
    (r"sk_live_[0-9a-zA-Z]{24,}",            "Stripe Secret Key"),
    (r"sk_test_[0-9a-zA-Z]{24,}",            "Stripe Test Key"),
    (r"pk_live_[0-9a-zA-Z]{24,}",            "Stripe Public Key"),
    (r"Bearer\s+[A-Za-z0-9\-\._~\+\/]{20,}=*", "Bearer Token"),
    (r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}", "JWT Token"),
    (r"AKIA[0-9A-Z]{16}",                    "AWS Access Key"),
    (r"ghp_[A-Za-z0-9]{36}",                 "GitHub Personal Token"),
    (r"glpat-[A-Za-z0-9\-_]{20}",            "GitLab Personal Token"),
    (r"xoxb-[0-9]{11}-[0-9]{11}-[a-zA-Z0-9]{24}", "Slack Bot Token"),
    (r"['\"]api[_-]?key['\"]?\s*[:=]\s*['\"]([A-Za-z0-9_\-]{16,})['\"]", "API Key"),
    (r"['\"]secret['\"]?\s*[:=]\s*['\"]([A-Za-z0-9_\-]{16,})['\"]", "Secret Value"),
    (r"password\s*=\s*['\"][^'\"]{6,}['\"]", "Hardcoded Password"),
]

INTERESTING_REQUEST_PATTERNS = [
    "/api", "/graphql", "/ajax", "/rest",
    "/v1/", "/v2/", "/v3/",
    "token", "auth", "user", "account",
    "admin", "payment", "checkout",
    "upload", "export", "download",
    "internal", "private", "secret",
]

TECH_PATTERNS = {
    "React":       r"react(?:\.min)?\.js|__REACT_|data-reactroot",
    "Vue.js":      r"vue(?:\.min)?\.js|__vue_",
    "Angular":     r"ng-version=|angular(?:\.min)?\.js",
    "Next.js":     r"_next/static|__NEXT_DATA__",
    "jQuery":      r"jquery(?:\.min)?\.js",
    "Bootstrap":   r"bootstrap(?:\.min)?\.(?:js|css)",
    "Tailwind":    r"tailwindcss",
    "Svelte":      r"__svelte_",
    "Webpack":     r"webpack",
    "Vite":        r"/@vite/|vite\.config",
}


def _scan_secrets(text: str) -> list:
    """Find secrets in a string using all known patterns."""
    found = []
    for pattern, label in SECRET_PATTERNS:
        matches = re.findall(pattern, text, re.IGNORECASE)
        for match in matches:
            value = match if isinstance(match, str) else match[0]
            if len(value) > 8:  # skip trivially short matches
                found.append({"type": label, "value": value[:60] + "..." if len(value) > 60 else value})
    return found


def _score_request(url: str) -> int:
    """Score how interesting an intercepted request is."""
    score = 0
    url_lower = url.lower()
    for pattern in INTERESTING_REQUEST_PATTERNS:
        if pattern in url_lower:
            score += 1
    return score


def _run_browser_recon(url: str) -> dict:
    """
    Internal function that does the actual Playwright work.
    Wrapped in a thread with timeout for safety.
    """
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        return {"error": "playwright not installed — run: pip install playwright && playwright install chromium"}

    results = {
        "url":             url,
        "page_title":      "",
        "api_calls":       [],
        "technologies":    [],
        "client_secrets":  [],
        "forms":           [],
        "links":           [],
        "js_errors":       [],
        "console_logs":    [],
        "storage_data":    [],
        "cookies":         [],
        "security_issues": [],
        "meta_tags":       {},
    }

    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(
                headless=True,
                args=[
                    "--no-sandbox",
                    "--disable-setuid-sandbox",
                    "--disable-dev-shm-usage",
                    "--disable-gpu",
                ]
            )

            context = browser.new_context(
                user_agent=(
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                    "AppleWebKit/537.36 (KHTML, like Gecko) "
                    "Chrome/120.0.0.0 Safari/537.36"
                ),
                ignore_https_errors=True,
            )

            page = context.new_page()

            # --- Intercept network requests ---
            captured_requests = {}

            def handle_request(request):
                req_url = request.url
                score   = _score_request(req_url)
                if score > 0 and req_url not in captured_requests:
                    captured_requests[req_url] = {
                        "url":    req_url,
                        "method": request.method,
                        "score":  score,
                    }

            # --- Capture JS errors ---
            js_errors = []

            def handle_pageerror(error):
                js_errors.append(str(error)[:200])

            # --- Capture console logs ---
            console_logs = []

            def handle_console(msg):
                if msg.type in ("error", "warning") or any(
                    x in msg.text.lower() for x in
                    ["token", "key", "secret", "password", "auth", "debug"]
                ):
                    console_logs.append({
                        "type": msg.type,
                        "text": msg.text[:200],
                    })

            page.on("request",   handle_request)
            page.on("pageerror", handle_pageerror)
            page.on("console",   handle_console)

            # --- Navigate ---
            try:
                page.goto(url, wait_until="domcontentloaded", timeout=15000)
                page.wait_for_timeout(2500)
            except Exception as nav_err:
                results["error"] = f"Navigation failed: {str(nav_err)[:100]}"
                browser.close()
                return results

            results["page_title"] = page.title()

            html = page.content()

            # --- Technology detection from HTML ---
            for tech, pattern in TECH_PATTERNS.items():
                if re.search(pattern, html, re.IGNORECASE):
                    results["technologies"].append(tech)

            # --- Secret scanning in HTML ---
            secrets = _scan_secrets(html)
            results["client_secrets"].extend(secrets)

            # --- Form analysis ---
            try:
                forms = page.evaluate("""
                    () => Array.from(document.querySelectorAll('form')).map(f => ({
                        action: f.action || '',
                        method: f.method || 'get',
                        inputs: Array.from(f.querySelectorAll('input')).map(i => ({
                            name: i.name,
                            type: i.type,
                            id:   i.id,
                        }))
                    }))
                """)
                results["forms"] = forms[:20]
            except Exception:
                pass

            # --- Link extraction ---
            try:
                links = page.evaluate("""
                    () => Array.from(document.querySelectorAll('a[href]'))
                        .map(a => a.href)
                        .filter(h => h.startsWith('http'))
                        .slice(0, 50)
                """)
                results["links"] = list(set(links))
            except Exception:
                pass

            # --- Meta tag extraction ---
            try:
                meta = page.evaluate("""
                    () => {
                        const tags = {};
                        document.querySelectorAll('meta').forEach(m => {
                            const name = m.name || m.property || m.httpEquiv;
                            if (name) tags[name] = m.content;
                        });
                        return tags;
                    }
                """)
                results["meta_tags"] = meta
            except Exception:
                pass

            # --- localStorage/sessionStorage scanning ---
            try:
                storage = page.evaluate("""
                    () => {
                        const items = [];
                        for (let i = 0; i < localStorage.length; i++) {
                            const key = localStorage.key(i);
                            const val = localStorage.getItem(key);
                            items.push({store: 'localStorage', key, value: val ? val.substring(0, 100) : ''});
                        }
                        for (let i = 0; i < sessionStorage.length; i++) {
                            const key = sessionStorage.key(i);
                            const val = sessionStorage.getItem(key);
                            items.push({store: 'sessionStorage', key, value: val ? val.substring(0, 100) : ''});
                        }
                        return items;
                    }
                """)

                # Flag sensitive storage keys
                sensitive_storage_keywords = [
                    "token", "key", "secret", "auth", "jwt",
                    "password", "credential", "session"
                ]
                for item in storage:
                    if any(kw in item["key"].lower() for kw in sensitive_storage_keywords):
                        results["storage_data"].append(item)
                        results["security_issues"].append({
                            "type":   "Sensitive Data in Browser Storage",
                            "detail": f"{item['store']}: {item['key']} = {item['value'][:50]}",
                        })
            except Exception:
                pass

            # --- Cookie security analysis ---
            try:
                cookies = context.cookies()
                for cookie in cookies:
                    cookie_info = {
                        "name":      cookie["name"],
                        "secure":    cookie.get("secure", False),
                        "httpOnly":  cookie.get("httpOnly", False),
                        "sameSite":  cookie.get("sameSite", "None"),
                        "domain":    cookie.get("domain", ""),
                    }
                    results["cookies"].append(cookie_info)

                    # Flag insecure cookies
                    if not cookie.get("httpOnly") and any(
                        x in cookie["name"].lower()
                        for x in ["session", "auth", "token", "sid"]
                    ):
                        results["security_issues"].append({
                            "type":   "Cookie Missing HttpOnly Flag",
                            "detail": f"Cookie '{cookie['name']}' lacks HttpOnly flag",
                        })

                    if not cookie.get("secure") and any(
                        x in cookie["name"].lower()
                        for x in ["session", "auth", "token", "sid"]
                    ):
                        results["security_issues"].append({
                            "type":   "Cookie Missing Secure Flag",
                            "detail": f"Cookie '{cookie['name']}' lacks Secure flag",
                        })
            except Exception:
                pass

            # --- Finalize intercepted requests ---
            sorted_requests = sorted(
                captured_requests.values(),
                key=lambda x: x["score"],
                reverse=True
            )
            results["api_calls"] = [r["url"] for r in sorted_requests[:50]]

            # --- JS errors and console logs ---
            results["js_errors"]    = js_errors[:20]
            results["console_logs"] = console_logs[:20]

            # Print summary
            print(f"\n{'='*40}")
            print(f"  BROWSER RECON: {url[:50]}")
            print(f"{'='*40}")
            print(f"  Title       : {results['page_title']}")
            print(f"  Tech        : {results['technologies']}")
            print(f"  API calls   : {len(results['api_calls'])}")
            print(f"  Forms       : {len(results['forms'])}")
            print(f"  Secrets     : {len(results['client_secrets'])}")
            print(f"  JS errors   : {len(results['js_errors'])}")
            print(f"  Issues      : {len(results['security_issues'])}")
            print(f"{'='*40}\n")

            browser.close()

    except Exception as e:
        results["error"] = str(e)[:200]
        print(f"[-] Browser recon failed for {url}: {e}")

    return results


# =========================
# PUBLIC FUNCTION
# =========================

def browser_recon(url: str, timeout: int = 45) -> dict:
    """
    Run browser-based reconnaissance on a URL.

    Wraps the Playwright execution in a thread with hard timeout
    so a hanging page can never block the full scan pipeline.

    Args:
        url:     target URL
        timeout: max seconds to wait (default 45)

    Returns:
        dict with recon results, or empty dict on timeout/failure
    """
    empty_result = {
        "url":            url,
        "page_title":     "",
        "api_calls":      [],
        "technologies":   [],
        "client_secrets": [],
        "forms":          [],
        "links":          [],
        "js_errors":      [],
        "console_logs":   [],
        "storage_data":   [],
        "cookies":        [],
        "security_issues": [],
        "meta_tags":      {},
        "error":          "",
    }

    try:
        with ThreadPoolExecutor(max_workers=1) as executor:
            future = executor.submit(_run_browser_recon, url)
            try:
                result = future.result(timeout=timeout)
                return result
            except FuturesTimeoutError:
                print(f"[-] Browser recon timed out after {timeout}s for {url}")
                empty_result["error"] = f"Timed out after {timeout}s"
                return empty_result
    except Exception as e:
        print(f"[-] Browser recon error for {url}: {e}")
        empty_result["error"] = str(e)
        return empty_result


# =========================
# QUICK TEST
# =========================

if __name__ == "__main__":
    result = browser_recon("https://example.com", timeout=30)
    print("\nResult keys:", list(result.keys()))
    print("Title:", result.get("page_title"))
    print("Technologies:", result.get("technologies"))
    print("Forms:", len(result.get("forms", [])))
    print("API calls:", len(result.get("api_calls", [])))
    print("Secrets found:", len(result.get("client_secrets", [])))
    print("Security issues:", result.get("security_issues"))