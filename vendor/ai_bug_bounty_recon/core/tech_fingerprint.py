"""
Technology Fingerprinter v3.0

Production-grade technology intelligence engine comparable to Wappalyzer / WhatWeb.

Detects 80+ technologies from HTTP headers, HTML content, cookies, meta tags,
JavaScript globals, inline scripts, asset paths, and response headers.

Public API (backwards-compatible):
    detect_technologies(url)      -> list[str]
    detect_technologies_full(url) -> dict
"""

from __future__ import annotations

import re
import socket
from dataclasses import dataclass, field
from functools import lru_cache
from typing import Optional
from urllib.parse import urlparse

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ===============================================
# SHARED HTTP HEADERS
# ===============================================

HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/120.0.0.0 Safari/537.36"
    )
}

# ===============================================
# TECHNOLOGY DATACLASS
# ===============================================

@dataclass(slots=True)
class Technology:
    """Internal representation of a detected technology."""
    name:       str
    category:   str
    confidence: int          = 0      # 0–100
    version:    str          = ""
    vendor:     str          = ""
    evidence:   list[str]    = field(default_factory=list)
    # Source signals that contributed
    headers:    list[str]    = field(default_factory=list)
    cookies:    list[str]    = field(default_factory=list)
    html:       list[str]    = field(default_factory=list)
    javascript: list[str]    = field(default_factory=list)
    source:     str          = ""     # primary source label

    def add_evidence(self, signal: str, weight: int, src: str = "") -> None:
        """Accumulate evidence and confidence (capped at 100)."""
        self.evidence.append(signal)
        self.confidence = min(100, self.confidence + weight)
        if src and not self.source:
            self.source = src

    def to_name(self) -> str:
        """Return display string with version if present."""
        return f"{self.name} {self.version}".strip() if self.version else self.name


# ===============================================
# COMPILED SIGNATURE TABLES
# ===============================================

# Each entry: (compiled_pattern, tech_name, category, version_group, confidence_weight)
# version_group: regex group index that captures version, or 0 for none

@dataclass(slots=True)
class _Sig:
    pattern:    re.Pattern
    name:       str
    category:   str
    version_grp:int   = 0
    weight:     int   = 20
    vendor:     str   = ""


def _c(pattern: str, flags: int = re.IGNORECASE) -> re.Pattern:
    return re.compile(pattern, flags)


# ── HTML / body signatures ──────────────────────────────────────────────────

HTML_SIGS: list[_Sig] = [
    # React
    _Sig(_c(r'(?:react(?:\.min)?\.js|__REACT_DEVTOOLS|data-reactroot|react-dom)'), "React",          "Frontend",  0, 20, "Meta"),
    _Sig(_c(r'(?:_next/static|__NEXT_DATA__|next\.js)'),                             "Next.js",        "Frontend",  0, 20, "Vercel"),
    _Sig(_c(r'(?:__nuxt__|nuxt\.js|/_nuxt/)'),                                       "Nuxt.js",        "Frontend",  0, 20, "NuxtLabs"),
    _Sig(_c(r'(?:vue(?:\.min)?\.js|__vue_|v-bind:|v-on:|v-model=|data-v-)'),        "Vue.js",         "Frontend",  0, 20, "Evan You"),
    _Sig(_c(r'(?:ng-version=|angular(?:\.min)?\.js|ng-app=|ng-controller=|zone\.js)'), "Angular",     "Frontend",  0, 20, "Google"),
    _Sig(_c(r'(?:jquery(?:\.min)?\.js|jQuery\.fn\.jquery|\$\.fn\.jquery)'),         "jQuery",         "Frontend",  0, 15),
    _Sig(_c(r'(?:bootstrap(?:\.min)?\.(?:js|css)|class="[^"]*(?:navbar-|btn-primary|container-fluid))'), "Bootstrap","Frontend",0,15,"Twitter"),
    _Sig(_c(r'(?:tailwindcss|class="[^"]*(?:text-\w+-\d+|bg-\w+-\d+|flex\s+items-))'), "Tailwind CSS","Frontend",  0, 15, "Tailwind Labs"),
    _Sig(_c(r'(?:ember(?:\.min)?\.js|Ember\.VERSION)'),                              "Ember.js",       "Frontend",  0, 20, "Ember"),
    _Sig(_c(r'(?:backbone(?:\.min)?\.js|Backbone\.VERSION)'),                        "Backbone.js",    "Frontend",  0, 20),
    _Sig(_c(r'(?:svelte|__svelte_|\.svelte-\w+)'),                                   "Svelte",         "Frontend",  0, 20, "Rich Harris"),
    _Sig(_c(r'(?:alpinejs|x-data=|x-bind:|x-show=)'),                               "Alpine.js",      "Frontend",  0, 20),
    _Sig(_c(r'(?:htmx(?:\.min)?\.js|hx-get=|hx-post=|hx-swap=)'),                  "HTMX",           "Frontend",  0, 20),
    _Sig(_c(r'(?:solidjs|solid-js|@solidjs)'),                                       "SolidJS",        "Frontend",  0, 25),
    _Sig(_c(r'(?:preact|preact/compat)'),                                             "Preact",         "Frontend",  0, 25),
    _Sig(_c(r'(?:astro-island|astro:page-load|@astro)'),                             "Astro",          "Frontend",  0, 25, "Astro"),
    # CMS
    _Sig(_c(r'(?:wp-content/|wp-includes/|/wp-json/)'),                              "WordPress",      "CMS",       0, 25, "Automattic"),
    _Sig(_c(r'(?:/sites/default/files|drupal\.js|Drupal\.settings)'),                "Drupal",         "CMS",       0, 25),
    _Sig(_c(r'(?:joomla!|/components/com_|mootools-core)'),                          "Joomla",         "CMS",       0, 25),
    _Sig(_c(r'(?:shopify\.com/s/files|Shopify\.theme|cdn\.shopify\.com)'),           "Shopify",        "CMS",       0, 25, "Shopify"),
    _Sig(_c(r'(?:ghost/assets|content/themes/casper|ghost\.org)'),                   "Ghost CMS",      "CMS",       0, 25, "Ghost Foundation"),
    _Sig(_c(r'(?:squarespace\.com|static\.squarespace|sqsp\.net)'),                  "Squarespace",    "CMS",       0, 30, "Squarespace"),
    _Sig(_c(r'(?:wix\.com|wixsite\.com|parastorage\.com)'),                          "Wix",            "CMS",       0, 30, "Wix"),
    _Sig(_c(r'(?:mage/cookies\.js|Mage\.Cookies|magento)'),                          "Magento",        "CMS",       0, 25, "Adobe"),
    _Sig(_c(r'(?:mediawiki|wgPageName|mw\.config)'),                                 "MediaWiki",      "CMS",       0, 25, "Wikimedia"),
    _Sig(_c(r'(?:woocommerce|wc-ajax|add-to-cart)'),                                 "WooCommerce",    "eCommerce", 0, 20, "Automattic"),
    # Backend hints in HTML
    _Sig(_c(r'(?:laravel_session|csrf-token.*laravel|Laravel\s+v)'),                 "Laravel",        "Backend",   0, 20, "Taylor Otwell"),
    _Sig(_c(r'(?:csrfmiddlewaretoken|__django_|djdt)'),                              "Django",         "Backend",   0, 20, "Django Software Foundation"),
    _Sig(_c(r'(?:rails-ujs|csrf-token.*rails|data-remote.*rails)'),                  "Ruby on Rails",  "Backend",   0, 20, "DHH"),
    _Sig(_c(r'(?:__symfony_|sf_redirect|symfony\.com)'),                             "Symfony",        "Backend",   0, 20, "SensioLabs"),
    _Sig(_c(r'(?:codeigniter|ci_session|spark ignite)'),                             "CodeIgniter",    "Backend",   0, 20, "BCITstudios"),
    _Sig(_c(r'(?:cakephp|cake_session)'),                                             "CakePHP",        "Backend",   0, 20),
    _Sig(_c(r'(?:powered by express|x-powered-by.*express)'),                        "Express.js",     "Backend",   0, 15, "OpenJS"),
    _Sig(_c(r'(?:nestjs|@nestjs)'),                                                   "NestJS",         "Backend",   0, 20, "Kamil Mysliwiec"),
    _Sig(_c(r'(?:spring boot|thymeleaf:)'),                                           "Spring Boot",    "Backend",   0, 20, "Pivotal"),
    _Sig(_c(r'(?:flask|jinja2|wtf_csrf_token)'),                                      "Flask",          "Backend",   0, 20, "Pallets"),
    _Sig(_c(r'(?:fastapi|uvicorn|/openapi\.json)'),                                  "FastAPI",        "Backend",   0, 25, "Tiangolo"),
    _Sig(_c(r'(?:phoenix_live_reload|lv:page-loading|phx-socket)'),                  "Phoenix",        "Backend",   0, 25, "Elixir"),
    _Sig(_c(r'(?:fiber\.go|go-fiber)'),                                               "Go Fiber",       "Backend",   0, 25, "gofiber"),
    _Sig(_c(r'(?:gin-gonic|gin\.Context)'),                                           "Gin",            "Backend",   0, 25, "gin-gonic"),
    _Sig(_c(r'(?:echo\.labstack|labstack\.com)'),                                     "Echo",           "Backend",   0, 25, "labstack"),
    # Analytics / tracking
    _Sig(_c(r'(?:google-analytics\.com/ga\.js|gtag\(|UA-\d{4,}-\d|G-[A-Z0-9]+)'),  "Google Analytics","Analytics", 0, 15, "Google"),
    _Sig(_c(r'(?:googletagmanager\.com/gtm\.js)'),                                   "Google Tag Manager","Analytics",0,15,"Google"),
    _Sig(_c(r'(?:connect\.facebook\.net/|fbq\()'),                                   "Facebook Pixel", "Analytics", 0, 20, "Meta"),
    _Sig(_c(r'(?:static\.hotjar\.com)'),                                              "Hotjar",         "Analytics", 0, 20),
    _Sig(_c(r'(?:cdn\.segment\.com|analytics\.(?:js|min\.js))'),                     "Segment",        "Analytics", 0, 20, "Twilio"),
    # Security / Payments
    _Sig(_c(r'(?:recaptcha\.net|recaptcha/api\.js|g-recaptcha)'),                    "reCAPTCHA",      "Security",  0, 15, "Google"),
    _Sig(_c(r'(?:hcaptcha\.com|h-captcha)'),                                          "hCAPTCHA",       "Security",  0, 20),
    _Sig(_c(r'(?:stripe\.com/v\d/|Stripe\()'),                                        "Stripe",         "Payments",  0, 20, "Stripe"),
    _Sig(_c(r'(?:paypal\.com/sdk|paypal\.Buttons)'),                                  "PayPal SDK",     "Payments",  0, 20, "PayPal"),
]

# ── JavaScript global variable signatures ──────────────────────────────────

JS_GLOBAL_SIGS: list[tuple[re.Pattern, str, str, int]] = [
    # (pattern, tech_name, category, weight)
    (_c(r'window\.__REACT_DEVTOOLS_GLOBAL_HOOK__'),       "React",          "Frontend",  25),
    (_c(r'window\.__NEXT_DATA__'),                         "Next.js",        "Frontend",  35),
    (_c(r'window\.__nuxt__'),                              "Nuxt.js",        "Frontend",  35),
    (_c(r'window\.angular|angular\.version'),              "Angular",        "Frontend",  25),
    (_c(r'window\.Vue|Vue\.version'),                      "Vue.js",         "Frontend",  25),
    (_c(r'window\.__svelte'),                              "Svelte",         "Frontend",  30),
    (_c(r'window\.Shopify'),                               "Shopify",        "CMS",       30),
    (_c(r'window\.wp\b|window\.wpApiSettings'),            "WordPress",      "CMS",       30),
    (_c(r'window\.Drupal'),                                "Drupal",         "CMS",       30),
    (_c(r'window\.Stripe'),                                "Stripe",         "Payments",  20),
    (_c(r'window\.dataLayer'),                             "Google Tag Manager","Analytics",15),
    (_c(r'window\.gtag\s*='),                              "Google Analytics","Analytics", 15),
]

# ── Meta tag signatures ─────────────────────────────────────────────────────

META_GENERATOR_SIGS: list[tuple[re.Pattern, str, str, re.Pattern | None]] = [
    # (pattern, tech_name, category, version_pattern)
    (_c(r'wordpress\s*([\d.]+)?',     re.IGNORECASE), "WordPress",   "CMS",     _c(r'wordpress\s+([\d.]+)', re.IGNORECASE)),
    (_c(r'drupal\s*([\d.]+)?',        re.IGNORECASE), "Drupal",      "CMS",     _c(r'drupal\s+([\d.]+)',    re.IGNORECASE)),
    (_c(r'joomla[!]?\s*([\d.]+)?',    re.IGNORECASE), "Joomla",      "CMS",     _c(r'joomla[!]?\s+([\d.]+)',re.IGNORECASE)),
    (_c(r'ghost\s*([\d.]+)?',         re.IGNORECASE), "Ghost CMS",   "CMS",     _c(r'ghost\s+([\d.]+)',     re.IGNORECASE)),
    (_c(r'mediawiki\s*([\d.]+)?',     re.IGNORECASE), "MediaWiki",   "CMS",     _c(r'mediawiki\s+([\d.]+)', re.IGNORECASE)),
    (_c(r'magento',                   re.IGNORECASE), "Magento",     "CMS",     None),
    (_c(r'squarespace',               re.IGNORECASE), "Squarespace", "CMS",     None),
    (_c(r'wix\.com',                  re.IGNORECASE), "Wix",         "CMS",     None),
]

_META_GEN_RE: re.Pattern = _c(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)["\']', re.IGNORECASE | re.DOTALL)
_META_GEN_ALT_RE: re.Pattern = _c(r'<meta[^>]+content=["\']([^"\']+)["\'][^>]+name=["\']generator["\']', re.IGNORECASE | re.DOTALL)

# ── HTTP header signatures ──────────────────────────────────────────────────

# (header_name_lower, pattern, tech_name, category, version_group, weight, vendor)
@dataclass(slots=True)
class _HeaderSig:
    header:      str
    pattern:     re.Pattern
    name:        str
    category:    str
    version_grp: int  = 0
    weight:      int  = 15
    vendor:      str  = ""

HEADER_SIGS: list[_HeaderSig] = [
    # Server
    _HeaderSig("server", _c(r"nginx(?:/([\d.]+))?"),               "nginx",           "Web Server",  1, 20, "nginx"),
    _HeaderSig("server", _c(r"apache(?:/([\d.]+))?"),              "Apache",          "Web Server",  1, 20, "Apache"),
    _HeaderSig("server", _c(r"microsoft-iis(?:/([\d.]+))?"),       "IIS",             "Web Server",  1, 20, "Microsoft"),
    _HeaderSig("server", _c(r"litespeed"),                         "LiteSpeed",       "Web Server",  0, 20, "LiteSpeed"),
    _HeaderSig("server", _c(r"caddy"),                             "Caddy",           "Web Server",  0, 20),
    _HeaderSig("server", _c(r"gunicorn(?:/([\d.]+))?"),            "Gunicorn",        "Web Server",  1, 15),
    _HeaderSig("server", _c(r"waitress"),                          "Waitress",        "Web Server",  0, 15),
    _HeaderSig("server", _c(r"jetty(?:/([\d.]+))?"),               "Jetty",           "Web Server",  1, 15, "Eclipse"),
    _HeaderSig("server", _c(r"tomcat(?:/([\d.]+))?|apache-coyote"),"Apache Tomcat",   "Web Server",  1, 15, "Apache"),
    _HeaderSig("server", _c(r"cowboy"),                            "Cowboy",          "Web Server",  0, 15),
    _HeaderSig("server", _c(r"openresty(?:/([\d.]+))?"),           "OpenResty",       "Web Server",  1, 20),
    _HeaderSig("server", _c(r"cloudflare"),                        "Cloudflare",      "CDN",         0, 20, "Cloudflare"),
    _HeaderSig("server", _c(r"sucuri"),                            "Sucuri WAF",      "WAF",         0, 25, "GoDaddy"),
    _HeaderSig("server", _c(r"big-ip"),                            "F5 BIG-IP",       "WAF",         0, 30, "F5"),
    _HeaderSig("server", _c(r"akamaighost"),                       "Akamai",          "CDN",         0, 25, "Akamai"),
    # X-Powered-By
    _HeaderSig("x-powered-by", _c(r"php/([\d.]+)"),               "PHP",             "Language",    1, 20),
    _HeaderSig("x-powered-by", _c(r"asp\.net"),                   "ASP.NET",         "Backend",     0, 20, "Microsoft"),
    _HeaderSig("x-powered-by", _c(r"express"),                    "Express.js",      "Backend",     0, 15, "OpenJS"),
    _HeaderSig("x-powered-by", _c(r"next\.js"),                   "Next.js",         "Frontend",    0, 20, "Vercel"),
    _HeaderSig("x-powered-by", _c(r"django"),                     "Django",          "Backend",     0, 20),
    _HeaderSig("x-powered-by", _c(r"ruby"),                       "Ruby",            "Language",    0, 15),
    _HeaderSig("x-powered-by", _c(r"servlet"),                    "Java Servlet",    "Backend",     0, 15),
    _HeaderSig("x-powered-by", _c(r"nestjs"),                     "NestJS",          "Backend",     0, 20),
    # X-AspNet-Version
    _HeaderSig("x-aspnet-version", _c(r"([\d.]+)"),               "ASP.NET",         "Backend",     1, 25, "Microsoft"),
    _HeaderSig("x-aspnetmvc-version", _c(r"([\d.]+)"),            "ASP.NET MVC",     "Backend",     1, 25, "Microsoft"),
    # Generator
    _HeaderSig("x-generator", _c(r"wordpress"),                   "WordPress",       "CMS",         0, 30, "Automattic"),
    _HeaderSig("x-generator", _c(r"drupal"),                      "Drupal",          "CMS",         0, 30),
    _HeaderSig("x-generator", _c(r"joomla"),                      "Joomla",          "CMS",         0, 30),
    _HeaderSig("x-generator", _c(r"ghost"),                       "Ghost CMS",       "CMS",         0, 30),
    # CDN / cloud
    _HeaderSig("via",          _c(r"cloudflare"),                  "Cloudflare",      "CDN",         0, 15, "Cloudflare"),
    _HeaderSig("via",          _c(r"varnish"),                     "Varnish Cache",   "Cache",       0, 15),
    _HeaderSig("via",          _c(r"squid"),                       "Squid Proxy",     "Proxy",       0, 15),
    _HeaderSig("cf-ray",       _c(r"."),                           "Cloudflare",      "CDN",         0, 25, "Cloudflare"),
    _HeaderSig("x-cache",      _c(r"cloudfront"),                  "AWS CloudFront",  "CDN",         0, 20, "Amazon"),
    _HeaderSig("x-amz-cf-id",  _c(r"."),                           "AWS CloudFront",  "CDN",         0, 25, "Amazon"),
    _HeaderSig("x-azure-ref",  _c(r"."),                           "Azure CDN",       "CDN",         0, 25, "Microsoft"),
    _HeaderSig("x-served-by",  _c(r"cache-"),                      "Fastly",          "CDN",         0, 20, "Fastly"),
    _HeaderSig("fastly-restarts",_c(r"."),                         "Fastly",          "CDN",         0, 20, "Fastly"),
    _HeaderSig("x-fd-healthprobe",_c(r"."),                        "Azure Front Door","CDN",         0, 25, "Microsoft"),
    # WAF
    _HeaderSig("x-sucuri-id",         _c(r"."),                   "Sucuri WAF",      "WAF",         0, 30, "GoDaddy"),
    _HeaderSig("x-sucuri-cache",      _c(r"."),                   "Sucuri WAF",      "WAF",         0, 25),
    _HeaderSig("x-firewall-protection",_c(r"."),                  "Firewall",        "WAF",         0, 20),
    _HeaderSig("x-waf-event-info",    _c(r"."),                   "WAF",             "WAF",         0, 20),
    _HeaderSig("x-distil-cs",         _c(r"."),                   "Distil Networks", "WAF",         0, 30),
    _HeaderSig("x-akamai-transformed",_c(r"."),                   "Akamai",          "WAF",         0, 25, "Akamai"),
    _HeaderSig("x-edgeconnect-midmile",_c(r"."),                  "Akamai",          "CDN",         0, 25, "Akamai"),
    _HeaderSig("x-iinfo",             _c(r"."),                   "Imperva Incapsula","WAF",        0, 30, "Imperva"),
    _HeaderSig("x-wa-info",           _c(r"."),                   "F5 BIG-IP",       "WAF",         0, 25, "F5"),
    # Security headers
    _HeaderSig("strict-transport-security", _c(r"."),             "HSTS Enabled",    "Security",    0, 10),
    _HeaderSig("content-security-policy",   _c(r"."),             "CSP Enabled",     "Security",    0, 10),
    _HeaderSig("x-frame-options",           _c(r"."),             "Clickjacking Protection","Security",0,10),
    # Laravel / framework headers
    _HeaderSig("x-laravel-version", _c(r"([\d.]+)"),              "Laravel",         "Backend",     1, 30, "Taylor Otwell"),
    _HeaderSig("x-wp-total",        _c(r"."),                     "WordPress",       "CMS",         0, 30, "Automattic"),
]

# ── Cookie signatures ───────────────────────────────────────────────────────

@dataclass(slots=True)
class _CookieSig:
    pattern: re.Pattern
    name:    str
    category:str
    weight:  int = 20
    vendor:  str = ""

COOKIE_SIGS: list[_CookieSig] = [
    _CookieSig(_c(r"PHPSESSID"),           "PHP",              "Language",  20),
    _CookieSig(_c(r"JSESSIONID"),          "Java/J2EE",        "Backend",   20),
    _CookieSig(_c(r"ASP\.NET_SessionId"),  "ASP.NET",          "Backend",   25, "Microsoft"),
    _CookieSig(_c(r"laravel_session"),     "Laravel",          "Backend",   25, "Taylor Otwell"),
    _CookieSig(_c(r"django_session|csrftoken"),"Django",        "Backend",   20),
    _CookieSig(_c(r"_rails_session"),      "Ruby on Rails",    "Backend",   25, "DHH"),
    _CookieSig(_c(r"wp-settings-"),        "WordPress",        "CMS",       25, "Automattic"),
    _CookieSig(_c(r"connect\.sid"),        "Express.js",       "Backend",   20, "OpenJS"),
    _CookieSig(_c(r"incap_ses"),           "Imperva Incapsula","WAF",       30, "Imperva"),
    _CookieSig(_c(r"visid_incap"),         "Imperva Incapsula","WAF",       30, "Imperva"),
    _CookieSig(_c(r"sucuri_cloudproxy"),   "Sucuri WAF",       "WAF",       30, "GoDaddy"),
    _CookieSig(_c(r"__cfduid|cf_clearance|__cf_bm"),"Cloudflare","CDN",    25, "Cloudflare"),
    _CookieSig(_c(r"bm_sz|ak_bmsc"),       "Akamai Bot Manager","WAF",     30, "Akamai"),
    _CookieSig(_c(r"_shopify_"),           "Shopify",          "CMS",       30, "Shopify"),
    _CookieSig(_c(r"magento"),             "Magento",          "CMS",       25, "Adobe"),
]

# ── Cloud / URL signatures ──────────────────────────────────────────────────

CLOUD_SIGS: list[tuple[re.Pattern, str, str]] = [
    (_c(r"\.amazonaws\.com"),          "AWS",                  "Cloud"),
    (_c(r"\.azurewebsites\.net"),      "Azure",                "Cloud"),
    (_c(r"\.appspot\.com"),            "Google App Engine",    "Cloud"),
    (_c(r"\.cloudfunctions\.net"),     "Google Cloud Functions","Cloud"),
    (_c(r"\.vercel\.app"),             "Vercel",               "Cloud"),
    (_c(r"\.netlify\.app"),            "Netlify",              "Cloud"),
    (_c(r"\.herokuapp\.com"),          "Heroku",               "Cloud"),
    (_c(r"\.fly\.dev"),                "Fly.io",               "Cloud"),
    (_c(r"\.render\.com"),             "Render",               "Cloud"),
    (_c(r"\.railway\.app"),            "Railway",              "Cloud"),
    (_c(r"\.pages\.dev"),              "Cloudflare Pages",     "Cloud"),
    (_c(r"\.github\.io"),              "GitHub Pages",         "Cloud"),
]

# Security headers inventory
_SECURITY_HEADERS: dict[str, str] = {
    "strict-transport-security": "HSTS",
    "content-security-policy":   "CSP",
    "x-frame-options":           "X-Frame-Options",
    "x-content-type-options":    "X-Content-Type-Options",
    "referrer-policy":           "Referrer-Policy",
    "permissions-policy":        "Permissions-Policy",
}

# ===============================================
# URL CACHE
# ===============================================

@lru_cache(maxsize=512)
def _parse_url(url: str) -> tuple[str, str]:
    p = urlparse(url)
    return p.scheme, p.hostname or ""

# ===============================================
# DETECTION HELPERS
# ===============================================

def _merge(bank: dict[str, Technology], name: str, category: str,
           signal: str, weight: int, version: str = "",
           vendor: str = "", src: str = "") -> None:
    """Merge a signal into the technology bank."""
    if name not in bank:
        bank[name] = Technology(name=name, category=category, vendor=vendor)
    t = bank[name]
    t.add_evidence(signal, weight, src)
    if version and not t.version:
        t.version = version
    if vendor and not t.vendor:
        t.vendor = vendor


def _scan_html(html: str, bank: dict[str, Technology]) -> None:
    """Run all HTML/body signatures against the response body."""
    for sig in HTML_SIGS:
        if sig.pattern.search(html):
            _merge(bank, sig.name, sig.category,
                   f"html_pattern:{sig.pattern.pattern[:60]}",
                   sig.weight, vendor=sig.vendor, src="html")


def _scan_js_globals(html: str, bank: dict[str, Technology]) -> None:
    """Detect JavaScript globals in inline scripts and body."""
    for pattern, name, category, weight in JS_GLOBAL_SIGS:
        if pattern.search(html):
            _merge(bank, name, category,
                   f"js_global:{pattern.pattern[:60]}",
                   weight, src="javascript")


def _scan_meta_tags(html: str, bank: dict[str, Technology]) -> None:
    """Extract generator meta tags and match against known CMS signatures."""
    gen_value = ""
    m = _META_GEN_RE.search(html) or _META_GEN_ALT_RE.search(html)
    if m:
        gen_value = m.group(1)

    if not gen_value:
        return

    for pat, name, category, ver_pat in META_GENERATOR_SIGS:
        if pat.search(gen_value):
            version = ""
            if ver_pat:
                vm = ver_pat.search(gen_value)
                if vm:
                    try:
                        version = vm.group(1)
                    except IndexError:
                        pass
            _merge(bank, name, category,
                   f"meta_generator:{gen_value[:80]}",
                   40, version=version, src="meta")


def _scan_headers(headers: dict[str, str], bank: dict[str, Technology]) -> None:
    """Run HTTP header signatures."""
    lower_headers = {k.lower(): v for k, v in headers.items()}

    for sig in HEADER_SIGS:
        val = lower_headers.get(sig.header, "")
        if not val:
            continue
        m = sig.pattern.search(val)
        if m:
            version = ""
            if sig.version_grp:
                try:
                    version = m.group(sig.version_grp) or ""
                except IndexError:
                    pass
            _merge(bank, sig.name, sig.category,
                   f"header:{sig.header}={val[:80]}",
                   sig.weight, version=version, vendor=sig.vendor, src="header")


def _scan_cookies(cookies: dict[str, str], bank: dict[str, Technology]) -> None:
    """Run cookie name signatures."""
    cookie_str = " ".join(cookies.keys())
    for sig in COOKIE_SIGS:
        if sig.pattern.search(cookie_str):
            _merge(bank, sig.name, sig.category,
                   f"cookie:{sig.pattern.pattern}",
                   sig.weight, vendor=sig.vendor, src="cookie")


def _scan_url(url: str, bank: dict[str, Technology]) -> None:
    """Detect cloud providers from URL patterns."""
    for pattern, name, category in CLOUD_SIGS:
        if pattern.search(url):
            _merge(bank, name, category,
                   f"url_pattern:{pattern.pattern}",
                   30, src="url")


def _check_security_headers(headers: dict[str, str]) -> dict:
    """Return security header presence / absence report."""
    present: list[str] = []
    missing: list[str] = []
    lower = {k.lower() for k in headers}
    for hdr, label in _SECURITY_HEADERS.items():
        (present if hdr in lower else missing).append(label)
    return {"present": present, "missing": missing}

# ===============================================
# CORE SCANNER
# ===============================================

def _scan_response(url: str, response: requests.Response,
                   verbose: bool = False) -> dict[str, Technology]:
    """Run all detection methods against a single response. Returns tech bank."""
    bank: dict[str, Technology] = {}

    html    = response.text
    headers = dict(response.headers)
    cookies = {c.name: c.value for c in response.cookies}

    _scan_url(url, bank)
    _scan_html(html, bank)
    _scan_js_globals(html, bank)
    _scan_meta_tags(html, bank)
    _scan_headers(headers, bank)
    _scan_cookies(cookies, bank)

    if verbose:
        for t in sorted(bank.values(), key=lambda x: -x.confidence):
            print(
                f"  [{t.category}] {t.name}"
                + (f" v{t.version}" if t.version else "")
                + f" | confidence={t.confidence}"
                + f" | evidence={len(t.evidence)}"
            )

    return bank


def _fetch(url: str) -> Optional[requests.Response]:
    """Fetch URL with fallback on SSL error. Returns response or None."""
    try:
        return requests.get(url, headers=HEADERS, timeout=8,
                            verify=False, allow_redirects=True)
    except requests.exceptions.SSLError:
        try:
            return requests.get(url, headers=HEADERS, timeout=8,
                                verify=False, allow_redirects=False)
        except Exception:
            return None
    except Exception:
        return None

# ===============================================
# PUBLIC API  (backwards-compatible)
# ===============================================

def detect_technologies(url: str, verbose: bool = False) -> list[str]:
    """
    Detect technologies used by a web application.

    Args:
        url:     target URL
        verbose: if True, print per-technology debug lines

    Returns:
        sorted list of detected technology name strings
        (backwards-compatible with v2.0)
    """
    bank: dict[str, Technology] = {}

    # URL-only pass (no HTTP needed)
    _scan_url(url, bank)

    response = _fetch(url)
    if response is not None:
        extra = _scan_response(url, response, verbose=verbose)
        # Merge extra into bank (extra is authoritative from full scan)
        bank = extra

    return sorted(t.to_name() for t in bank.values())


def detect_technologies_full(url: str, verbose: bool = False) -> dict:
    """
    Extended detection returning tech stack + security header analysis.

    Returns:
        {
            "technologies":     list[str],
            "security_headers": {"present": [...], "missing": [...]},
            "waf_detected":     bool,
            "cloud_provider":   str | None,
            "tech_objects":     list[dict],   # NEW: rich objects for report consumers
        }

    Core keys are identical to v2.0 for backwards compatibility.
    """
    bank: dict[str, Technology] = {}
    security_info = {"present": [], "missing": []}
    cloud_provider: Optional[str] = None

    # Cloud from URL
    for pattern, name, _ in CLOUD_SIGS:
        if pattern.search(url):
            cloud_provider = name
            break

    response = _fetch(url)
    if response is not None:
        bank = _scan_response(url, response, verbose=verbose)
        security_info = _check_security_headers(dict(response.headers))

    waf_detected = any(t.category == "WAF" for t in bank.values())

    # Rich objects for new consumers (report engine, detection_engine, etc.)
    tech_objects = [
        {
            "name":       t.name,
            "category":   t.category,
            "confidence": t.confidence,
            "version":    t.version,
            "vendor":     t.vendor,
            "evidence":   t.evidence,
            "source":     t.source,
        }
        for t in sorted(bank.values(), key=lambda x: (-x.confidence, x.name))
    ]

    return {
        "technologies":     sorted(t.to_name() for t in bank.values()),
        "security_headers": security_info,
        "waf_detected":     waf_detected,
        "cloud_provider":   cloud_provider,
        "tech_objects":     tech_objects,
    }

# ===============================================
# BACKWARDS-COMPAT INTERNAL FUNCTIONS
# (preserved for any internal callers)
# ===============================================

def _check_html(html: str) -> set:
    bank: dict[str, Technology] = {}
    _scan_html(html, bank)
    return {t.name for t in bank.values()}


def _check_headers(headers: dict) -> set:
    bank: dict[str, Technology] = {}
    _scan_headers(headers, bank)
    return {t.name for t in bank.values()}


def _check_wafs(headers: dict, cookies: dict) -> set:
    bank: dict[str, Technology] = {}
    _scan_headers(headers, bank)
    _scan_cookies(cookies, bank)
    return {t.name for t in bank.values() if t.category == "WAF"}


def _check_cookies(cookies: dict) -> set:
    bank: dict[str, Technology] = {}
    _scan_cookies(cookies, bank)
    return {t.name for t in bank.values()}


def _check_url(url: str) -> set:
    bank: dict[str, Technology] = {}
    _scan_url(url, bank)
    return {t.name for t in bank.values()}


def _check_security_headers(headers: dict) -> dict:
    return _check_security_headers(headers)

# ===============================================
# QUICK TEST
# ===============================================

if __name__ == "__main__":
    import sys

    test_urls = [
        "https://example.com",
        "https://wordpress.org",
        "https://reactjs.org",
    ]

    verbose = "--verbose" in sys.argv or "-v" in sys.argv

    for url in test_urls:
        print(f"\n[+] Scanning: {url}")
        techs = detect_technologies(url, verbose=verbose)
        print(f"    Technologies: {techs}")

        full = detect_technologies_full(url, verbose=verbose)
        print(f"    Security headers present: {full['security_headers']['present']}")
        print(f"    Security headers MISSING: {full['security_headers']['missing']}")
        print(f"    WAF detected: {full['waf_detected']}")
        print(f"    Cloud provider: {full['cloud_provider']}")
        if full["tech_objects"]:
            print("    Top detections:")
            for obj in full["tech_objects"][:5]:
                ver = f" v{obj['version']}" if obj['version'] else ""
                print(f"      [{obj['category']}] {obj['name']}{ver} "
                      f"(confidence={obj['confidence']}, source={obj['source']})")
