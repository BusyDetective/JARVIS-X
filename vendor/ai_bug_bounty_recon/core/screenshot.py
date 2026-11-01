from playwright.sync_api import sync_playwright, TimeoutError as PlaywrightTimeout
import os
import re

# ===============================================
# CONFIGURATION
# ===============================================

DEFAULT_OUTPUT_DIR = "screenshots"
VIEWPORT           = {"width": 1280, "height": 800}   # Reduced from 2560×1440 — faster, enough for recon
PAGE_TIMEOUT       = 20000   # 20s max for page load
WAIT_AFTER_LOAD    = 2000    # 2s settle time (was 8s — no need to wait that long)
BROWSER_TIMEOUT    = 30000   # 30s hard cap on entire browser session

# Browser args for headless stability
BROWSER_ARGS = [
    "--disable-dev-shm-usage",
    "--no-sandbox",
    "--disable-gpu",
    "--disable-setuid-sandbox",
    "--disable-extensions",
    "--disable-background-networking",
    "--disable-sync",
    "--no-first-run",
]

# Cookie/consent button selectors to dismiss before screenshot
COOKIE_SELECTORS = [
    "button[id*='accept']",
    "button[id*='cookie']",
    "button[class*='accept']",
    "button[class*='cookie']",
    "button[class*='consent']",
    "[data-testid='cookie-accept']",
    "#onetrust-accept-btn-handler",
    ".cc-accept",
    ".accept-cookies",
]


# ===============================================
# HELPERS
# ===============================================

def _safe_filename(url):
    """Convert URL to a safe filename."""
    name = (
        url.replace("https://", "")
           .replace("http://", "")
           .replace("/", "_")
           .replace(":", "_")
           .replace("?", "_")
           .replace("&", "_")
           .replace("=", "_")
           .replace(".", "_")
    )
    # Truncate to avoid filesystem limits
    return name[:180]


def _dismiss_dialogs(page):
    """Dismiss cookie banners and JS dialogs."""
    # Handle JS alert/confirm/prompt dialogs
    page.on("dialog", lambda dialog: dialog.dismiss())

    # Try to click common cookie accept buttons
    for selector in COOKIE_SELECTORS:
        try:
            btn = page.locator(selector).first
            if btn.is_visible(timeout=500):
                btn.click(timeout=500)
                break
        except Exception:
            continue


def _extract_title(page):
    """Get page title safely."""
    try:
        return page.title()[:200]
    except Exception:
        return ""


def _extract_tech_hints(page):
    """
    Quick technology hints from the rendered page.
    Not a replacement for tech_fingerprint.py — just opportunistic.
    """
    hints = []
    try:
        html = page.content().lower()

        tech_sigs = {
            "React":      "react",
            "Vue.js":     "vue.",
            "Angular":    "ng-version",
            "WordPress":  "wp-content",
            "Drupal":     "drupal",
            "Laravel":    "laravel",
            "Django":     "csrfmiddlewaretoken",
            "Next.js":    "__next",
            "Nuxt.js":    "__nuxt",
            "jQuery":     "jquery",
        }

        for tech, sig in tech_sigs.items():
            if sig in html:
                hints.append(tech)

    except Exception:
        pass

    return hints


# ===============================================
# MAIN CAPTURE FUNCTION
# ===============================================

def capture_screenshot(url, output_dir=DEFAULT_OUTPUT_DIR):
    """
    Capture a screenshot of a URL using headless Chromium.

    Args:
        url:        Target URL
        output_dir: Directory to save screenshots

    Returns:
        dict with keys: url, path, title, tech_hints
        or None if capture failed
    """
    os.makedirs(output_dir, exist_ok=True)

    safe_name       = _safe_filename(url)
    screenshot_path = os.path.join(output_dir, f"{safe_name}.png")

    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(
                headless=True,
                args=BROWSER_ARGS,
                timeout=BROWSER_TIMEOUT
            )

            context = browser.new_context(
                viewport=VIEWPORT,
                ignore_https_errors=True,          # Don't fail on bad SSL
                java_script_enabled=True,
                user_agent=(
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                    "AppleWebKit/537.36 (KHTML, like Gecko) "
                    "Chrome/120.0.0.0 Safari/537.36"
                )
            )

            page = context.new_page()

            # Dismiss any JS dialogs automatically
            page.on("dialog", lambda dialog: dialog.dismiss())

            # Block unnecessary resource types to speed up load
            def _block_resources(route):
                if route.request.resource_type in ("image", "font", "media"):
                    route.abort()
                else:
                    route.continue_()

            page.route("**/*", _block_resources)

            # Navigate to page
            try:
                page.goto(
                    url,
                    wait_until="domcontentloaded",
                    timeout=PAGE_TIMEOUT
                )
            except PlaywrightTimeout:
                print(f"[-] Page load timeout: {url}")
                browser.close()
                return None

            # Short settle wait (reduced from 8s → 2s)
            page.wait_for_timeout(WAIT_AFTER_LOAD)

            # Dismiss cookie banners after page settles
            _dismiss_dialogs(page)

            # Skip blank pages
            try:
                body_text = page.locator("body").inner_text(timeout=3000).strip()
                if not body_text:
                    browser.close()
                    return None
            except Exception:
                pass

            # Extract metadata before screenshot
            title      = _extract_title(page)
            tech_hints = _extract_tech_hints(page)

            # Re-enable images for screenshot
            page.unroute("**/*")

            # Capture viewport screenshot (not full page — faster, sufficient)
            page.screenshot(
                path=screenshot_path,
                full_page=False,
                type="png"
            )

            browser.close()

        print(f"[+] Screenshot saved: {screenshot_path}")

        return {
            "url":        url,
            "path":       screenshot_path,
            "title":      title,
            "tech_hints": tech_hints,
            # Keep 'image' key for backward compat with existing templates
            "image":      screenshot_path,
        }

    except PlaywrightTimeout:
        print(f"[-] Browser timeout for {url}")
        return None
    except Exception as e:
        print(f"[-] Screenshot failed for {url}: {e}")
        return None


# ===============================================
# BATCH CAPTURE
# ===============================================

def capture_all(hosts, output_dir=DEFAULT_OUTPUT_DIR, limit=10):
    """
    Capture screenshots for a list of hosts.

    Args:
        hosts:      list of host dicts with 'url' key, or URL strings
        output_dir: directory to save screenshots
        limit:      max number of screenshots to take

    Returns:
        list of result dicts (only successful captures)
    """
    results = []

    targets = hosts[:limit]
    print(f"[+] Capturing screenshots for {len(targets)} hosts...")

    for host in targets:
        url = host["url"] if isinstance(host, dict) else host
        result = capture_screenshot(url, output_dir)
        if result:
            results.append(result)

    print(f"[+] Screenshots captured: {len(results)}/{len(targets)}")
    return results


# ===============================================
# SELF-TEST
# ===============================================

if __name__ == "__main__":
    test_urls = [
        "https://example.com",
        "https://httpbin.org",
    ]

    for url in test_urls:
        result = capture_screenshot(url)
        if result:
            print(f"  ✓ {result['url']}")
            print(f"    Path:  {result['path']}")
            print(f"    Title: {result['title']}")
            print(f"    Tech:  {result['tech_hints']}")
        else:
            print(f"  ✗ {url} — failed")