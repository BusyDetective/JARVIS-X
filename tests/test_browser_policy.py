"""URL, content-type, click, fill and link policy. Pure logic (no browser)."""
from __future__ import annotations

import pytest

from app.browser.errors import BlockedURLError, PolicyViolationError
from app.browser.models import BrowserLimits
from app.browser.policy import BrowserPolicy
from tests.phase9_helpers import FakeResolver, PUBLIC_IP, public_validator
from app.web.urls import UrlValidator


def policy(limits: BrowserLimits | None = None, *hosts: str) -> BrowserPolicy:
    return BrowserPolicy(limits or BrowserLimits(), public_validator(*(hosts or ("site.test",))))


@pytest.mark.parametrize("url", [
    "file:///etc/passwd", "javascript:alert(1)", "data:text/html,<script>1</script>", "ftp://site.test/x",
    "chrome://settings", "about:blank", "view-source:http://site.test/", "blob:http://site.test/abc", "ws://site.test/",
    "http://localhost/", "http://127.0.0.1/", "http://[::1]/", "http://169.254.169.254/latest/meta-data/",
    "http://10.0.0.5/", "http://192.168.1.1/", "http://172.16.0.1/", "http://0.0.0.0/", "http://2130706433/",
    "http://0x7f000001/", "http://127.1/", "http://user:pass@site.test/", "http://metadata.google.internal/",
    "", "   ", "http://", "not a url",
])
async def test_dangerous_or_malformed_urls_are_blocked(url):
    with pytest.raises(BlockedURLError):
        await policy().check_url(url)


async def test_public_https_url_is_allowed_and_pinned_to_verified_addresses():
    target = await policy().check_url("https://site.test/path?q=1#frag")
    assert target.addresses == (PUBLIC_IP,) and target.port == 443 and "#" not in target.url


async def test_hostname_resolving_to_private_address_is_blocked():
    p = BrowserPolicy(BrowserLimits(), UrlValidator(FakeResolver({"evil.test": ["10.1.2.3"]})))
    with pytest.raises(BlockedURLError):
        await p.check_url("http://evil.test/")


async def test_mixed_public_and_private_resolution_is_blocked():
    p = BrowserPolicy(BrowserLimits(), UrlValidator(FakeResolver({"mix.test": [PUBLIC_IP, "127.0.0.1"]})))
    with pytest.raises(BlockedURLError):
        await p.check_url("http://mix.test/")


async def test_dns_rebinding_is_caught_because_every_hop_is_revalidated():
    class Rebinder:
        n = 0
        async def resolve(self, host, port):
            self.n += 1
            return [PUBLIC_IP] if self.n == 1 else ["127.0.0.1"]
    p = BrowserPolicy(BrowserLimits(), UrlValidator(Rebinder()))
    assert (await p.check_url("http://rebind.test/")).addresses == (PUBLIC_IP,)
    with pytest.raises(BlockedURLError):
        await p.check_url("http://rebind.test/")  # second lookup now private


@pytest.mark.parametrize("url", ["http://site.test:22/", "http://site.test:8080/", "https://site.test:6379/"])
async def test_non_allowed_ports_blocked(url):
    with pytest.raises(BlockedURLError):
        await policy().check_url(url)


async def test_configured_extra_port_allowed():
    p = policy(BrowserLimits(allowed_ports=(80, 443, 8080)))
    assert (await p.check_url("http://site.test:8080/")).port == 8080


async def test_domain_allow_list_enforced_including_subdomains():
    p = policy(BrowserLimits(allowed_domains=("docs.test",)), "docs.test", "a.docs.test", "other.test")
    await p.check_url("https://docs.test/")
    await p.check_url("https://a.docs.test/")
    with pytest.raises(BlockedURLError):
        await p.check_url("https://other.test/")
    with pytest.raises(BlockedURLError):
        await p.check_url("https://evildocs.test/")


@pytest.mark.parametrize("ctype,disp,ok", [
    ("text/html; charset=utf-8", None, True), ("image/png", None, True), ("application/json", None, True),
    ("font/woff2", None, True), ("application/zip", None, False), ("application/octet-stream", None, False),
    ("application/pdf", None, False), ("application/x-msdownload", None, False), ("text/html", "attachment; filename=a.html", False),
    ("video/mp4", None, False), ("audio/mpeg", None, False),
])
def test_content_type_policy(ctype, disp, ok):
    assert BrowserPolicy.content_type_allowed(ctype, disp) is ok


@pytest.mark.parametrize("href,text,attrs,ok", [
    ("http://site.test/about", "About us", {}, True),
    ("http://site.test/logout", "Log out", {}, False),
    ("http://site.test/x", "Sign in", {}, False),
    ("http://site.test/cart/add?id=1", "Add to cart", {}, False),
    ("http://site.test/checkout", "Go", {}, False),
    ("http://site.test/file.zip", "Get it", {"download": ""}, False),
    ("javascript:void(0)", "Click", {}, False),
    ("mailto:a@b.c", "Mail", {}, False),
    ("http://site.test/c", "Verify you are human", {"class": "g-recaptcha"}, False),
    ("http://site.test/delete/5", "Remove item", {}, False),
])
def test_link_policy(href, text, attrs, ok):
    allowed, reason = policy().check_link(href, text, attrs)
    assert allowed is ok and (ok or reason)


@pytest.mark.parametrize("tag,attrs,text,in_form,ok", [
    ("summary", {}, "More details", False, True),
    ("button", {"aria-expanded": "false"}, "Menu", False, True),
    ("button", {"aria-controls": "panel"}, "Show", False, True),
    ("button", {"type": "submit"}, "Go", False, False),
    ("button", {}, "Next", False, False),                         # plain button: not provably a toggle
    ("button", {"aria-expanded": "false"}, "Menu", True, False),   # inside a form
    ("button", {"aria-expanded": "false"}, "Buy now", False, False),
    ("button", {"aria-expanded": "false"}, "Delete account", False, False),
    ("button", {"aria-expanded": "false"}, "I'm not a robot", False, True),  # no keyword: structural allow
    ("button", {"aria-expanded": "false", "class": "g-recaptcha"}, "x", False, False),
    ("input", {"type": "submit"}, "Send", False, False),
    ("a", {"href": "http://x"}, "link", False, False),
    ("div", {}, "x", False, False),
])
def test_click_policy_is_deny_by_default(tag, attrs, text, in_form, ok):
    allowed, reason = policy().check_click(tag, attrs, text, in_form)
    assert allowed is ok and (ok or reason)


@pytest.mark.parametrize("kind,name,label,method,sensitive,ok", [
    ("text", "q", "Search", "get", False, True),
    ("search", "query", None, None, False, True),
    ("textarea", "notes", "Notes", "get", False, True),
    ("password", "pw", None, "get", False, False),
    ("file", "upload", None, "get", False, False),
    ("hidden", "csrf", None, "get", False, False),
    ("submit", "go", None, "get", False, False),
    ("text", "card_number", "Card", "get", False, False),
    ("text", "otp", None, "get", False, False),
    ("text", "username", None, "post", False, False),             # POST form
    ("text", "username", None, "get", True, False),               # form also has a password field
    ("checkbox", "agree", None, "get", False, False),
    ("text", "g-recaptcha-response", None, "get", False, False),
])
def test_field_policy(kind, name, label, method, sensitive, ok):
    allowed, reason = policy().check_field(kind, name, label, None, method, sensitive, None)
    assert allowed is ok and (ok or reason)


@pytest.mark.parametrize("value", ["sk-abcdefghijklmnopqrstuvwxyz123456", "AKIAABCDEFGHIJKLMNOP", "x" * 501, "a\x07b"])
def test_fill_values_that_look_secret_or_unsafe_are_refused(value):
    with pytest.raises(PolicyViolationError):
        BrowserPolicy.check_fill_value(value)


def test_normal_fill_value_ok():
    BrowserPolicy.check_fill_value("how to bake sourdough")


def test_display_url_strips_credentials_query_and_fragment():
    assert BrowserPolicy.display_url("https://u:p@site.test/a/b?token=SECRET#x") == "https://site.test/a/b"
    assert "SECRET" not in BrowserPolicy.strip_query("https://site.test/a?token=SECRET")


def test_limits_clamp_only_downwards():
    lim = BrowserLimits(max_text_chars=1000)
    assert lim.clamp(5000, lim.max_text_chars) == 1000 and lim.clamp(10, 1000) == 10 and lim.clamp(None, 1000) == 1000
