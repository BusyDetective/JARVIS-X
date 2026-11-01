"""PinnedFetcher + NetworkGuard with fake Playwright route objects and an httpx MockTransport
(MOCKED: no browser). The real-browser equivalents live in tests/test_browser_real.py."""
from __future__ import annotations

import httpx
import pytest

from app.browser.models import BrowserLimits
from app.browser.network import NetworkGuard, PinnedFetcher
from app.browser.policy import BrowserPolicy
from app.web.urls import UrlValidator
from tests.phase9_helpers import PUBLIC_IP, public_validator


class FakeFrame:
    def __init__(self, parent=None): self.parent_frame = parent


class FakeRequest:
    def __init__(self, url, method="GET", rtype="document", nav=True, main=True, headers=None):
        self.url, self.method, self.resource_type = url, method, rtype
        self._nav, self.headers = nav, headers or {"accept": "text/html"}
        self.frame = FakeFrame(None if main else FakeFrame())

    def is_navigation_request(self): return self._nav


class FakeRoute:
    def __init__(self, req): self.request, self.fulfilled, self.aborted = req, None, None
    async def fulfill(self, **kw): self.fulfilled = kw
    async def abort(self, code="failed"): self.aborted = code


def make_guard(handler, hosts=("site.test",), limits=None, validator=None):
    limits = limits or BrowserLimits()
    policy = BrowserPolicy(limits, validator or public_validator(*hosts))
    fetcher = PinnedFetcher(limits, httpx.MockTransport(handler))
    return NetworkGuard(policy, fetcher), fetcher


def html(body=b"<p>ok</p>", status=200, **headers):
    return httpx.Response(status, headers={"content-type": "text/html", **headers}, content=body)


async def run(guard, req):
    route = FakeRoute(req)
    await guard.handle(route)
    return route


async def test_fetch_connects_to_validated_ip_with_original_host_header():
    seen = {}
    def handler(r: httpx.Request):
        seen.update(host=r.url.host, hdr=r.headers["host"], sni=r.extensions.get("sni_hostname"), cookie=r.headers.get("cookie"))
        return html()
    guard, f = make_guard(handler)
    route = await run(guard, FakeRequest("http://site.test/p"))
    assert route.fulfilled["status"] == 200
    assert seen == {"host": PUBLIC_IP, "hdr": "site.test", "sni": "site.test", "cookie": None}


@pytest.mark.parametrize("method", ["POST", "PUT", "DELETE", "PATCH"])
async def test_non_get_requests_are_blocked_and_never_fetched(method):
    hits = []
    guard, _ = make_guard(lambda r: hits.append(r) or html())
    route = await run(guard, FakeRequest("http://site.test/x", method=method, rtype="xhr", nav=False))
    assert route.aborted and not hits and guard.blocked_count == 1


@pytest.mark.parametrize("rtype", ["websocket", "eventsource", "media", "ping", "manifest", "other"])
async def test_dangerous_resource_types_are_blocked(rtype):
    hits = []
    guard, _ = make_guard(lambda r: hits.append(r) or html())
    route = await run(guard, FakeRequest("http://site.test/x", rtype=rtype, nav=False))
    assert route.aborted and not hits


async def test_private_subresource_is_blocked_before_any_fetch():
    hits = []
    guard, _ = make_guard(lambda r: hits.append(r) or html())
    route = await run(guard, FakeRequest("http://127.0.0.1/admin", rtype="image", nav=False))
    assert route.aborted and not hits


async def test_subresource_redirect_to_private_address_is_blocked_at_the_hop():
    def handler(r):
        return httpx.Response(302, headers={"location": "http://169.254.169.254/latest/meta-data/"})
    guard, _ = make_guard(handler)
    route = await run(guard, FakeRequest("http://site.test/img.png", rtype="image", nav=False))
    assert route.aborted and route.fulfilled is None


async def test_subresource_redirects_followed_internally_and_final_body_served():
    def handler(r):
        if r.headers["host"] == "site.test" and r.url.path == "/a":
            return httpx.Response(302, headers={"location": "/b"})
        return html(b"final")
    guard, _ = make_guard(handler)
    route = await run(guard, FakeRequest("http://site.test/a", rtype="stylesheet", nav=False))
    assert route.fulfilled["body"] == b"final" and route.fulfilled["status"] == 200


async def test_main_navigation_redirect_is_never_handed_to_browser():
    guard, _ = make_guard(lambda r: httpx.Response(302, headers={"location": "http://site.test/next"}))
    guard.begin_navigation()
    route = await run(guard, FakeRequest("http://site.test/start"))
    assert route.aborted and route.fulfilled is None and guard.pending_redirect == "http://site.test/next"


async def test_redirect_loop_limit_for_subresources():
    guard, _ = make_guard(lambda r: httpx.Response(302, headers={"location": "/loop"}), limits=BrowserLimits(max_redirects=3))
    route = await run(guard, FakeRequest("http://site.test/loop", rtype="image", nav=False))
    assert route.aborted and "redirect" in guard.blocked[-1]


async def test_request_count_limit():
    guard, _ = make_guard(lambda r: html(), limits=BrowserLimits(max_requests_per_page=2))
    outcomes = [await run(guard, FakeRequest("http://site.test/%d" % i, rtype="image", nav=False)) for i in range(4)]
    assert [bool(o.fulfilled) for o in outcomes] == [True, True, False, False]


async def test_total_download_budget():
    guard, _ = make_guard(lambda r: html(b"x" * 6000), limits=BrowserLimits(max_total_bytes=10_000, max_resource_bytes=10_000))
    a = await run(guard, FakeRequest("http://site.test/1", rtype="image", nav=False))
    b = await run(guard, FakeRequest("http://site.test/2", rtype="image", nav=False))
    assert a.fulfilled and b.aborted


async def test_oversized_resource_is_rejected_not_truncated():
    guard, _ = make_guard(lambda r: html(b"x" * 20_000), limits=BrowserLimits(max_resource_bytes=10_000))
    route = await run(guard, FakeRequest("http://site.test/big"))
    assert route.aborted and route.fulfilled is None


@pytest.mark.parametrize("hdrs", [{"content-type": "application/zip"}, {"content-type": "application/octet-stream"},
                                  {"content-type": "text/html", "content-disposition": "attachment; filename=x.html"}])
async def test_downloads_are_blocked(hdrs):
    guard, _ = make_guard(lambda r: httpx.Response(200, headers=hdrs, content=b"PK"))
    route = await run(guard, FakeRequest("http://site.test/dl"))
    assert route.aborted and route.fulfilled is None


async def test_set_cookie_and_other_headers_are_not_forwarded():
    guard, _ = make_guard(lambda r: html(b"x", **{"set-cookie": "sid=abc", "x-secret": "1", "content-language": "en"}))
    route = await run(guard, FakeRequest("http://site.test/"))
    assert set(route.fulfilled["headers"]) == {"content-type", "content-language"}


async def test_dns_rebinding_between_check_and_use_cannot_redirect_the_connection():
    # The validator returns the public address once; the fetcher must connect to THAT address, never re-resolve.
    ips = []
    class OneShot:
        async def resolve(self, host, port): return [PUBLIC_IP]
    def handler(r): ips.append(r.url.host); return html()
    guard, _ = make_guard(handler, validator=UrlValidator(OneShot()))
    await run(guard, FakeRequest("http://rebind.test/"))
    assert ips == [PUBLIC_IP]


async def test_unexpected_exception_aborts_request_instead_of_leaking_or_hanging():
    def handler(r): raise RuntimeError("secret-internal-detail")
    guard, _ = make_guard(handler)
    route = await run(guard, FakeRequest("http://site.test/"))
    assert route.aborted == "failed" and "secret-internal-detail" not in " ".join(guard.blocked)


async def test_network_errors_abort_cleanly():
    def handler(r): raise httpx.ConnectError("refused")
    guard, _ = make_guard(handler)
    route = await run(guard, FakeRequest("http://site.test/"))
    assert route.aborted == "failed"


async def test_blocked_log_is_bounded_and_contains_no_urls_with_queries():
    guard, _ = make_guard(lambda r: html())
    for i in range(80):
        await run(guard, FakeRequest(f"http://127.0.0.1/?token=SECRET{i}", rtype="image", nav=False))
    assert guard.blocked_count == 80 and len(guard.blocked) <= 50
    assert not any("SECRET" in b for b in guard.blocked)
