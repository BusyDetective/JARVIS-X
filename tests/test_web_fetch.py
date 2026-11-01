from __future__ import annotations

import asyncio

import httpx
import pytest

from app.web.errors import FetchError, InvalidWebURL, UnsafeWebTarget, WebLimitExceeded
from app.web.urls import UrlValidator, is_blocked_ip
import ipaddress

from tests.web_helpers import FakeResolver, html_response, make_fetcher


async def test_successful_fetch_pins_ip_and_keeps_host_header():
    seen = {}

    def handler(request: httpx.Request):
        seen.update(host=request.url.host, hdr=request.headers["host"], ua=request.headers["user-agent"],
                    ext=request.extensions.get("sni_hostname"), cookie=request.headers.get("cookie"),
                    auth=request.headers.get("authorization"))
        return html_response("<html><title>Hi</title><body>hello</body></html>")

    doc = await make_fetcher(handler).fetch("https://Example.com/a?b=1#frag")
    assert doc.status_code == 200 and "hello" in doc.content
    assert doc.url == "https://Example.com/a?b=1#frag" and doc.final_url == "https://example.com/a?b=1"
    assert doc.content_type.startswith("text/html") and doc.domain == "example.com"
    assert doc.fetched_at.tzinfo is not None and doc.truncated is False
    assert seen["host"] == "93.184.216.34" and seen["hdr"] == "example.com" and seen["ext"] == "example.com"
    assert seen["cookie"] is None and seen["auth"] is None and "JARVIS-X" in seen["ua"]


async def test_redirect_followed_and_final_url_recorded():
    def handler(request):
        if request.headers["host"] == "a.example.com":
            return httpx.Response(302, headers={"location": "https://b.example.com/final"})
        return html_response("landed")

    doc = await make_fetcher(handler).fetch("https://a.example.com/start")
    assert doc.final_url == "https://b.example.com/final" and doc.content == "landed"
    assert doc.metadata["redirects"] == 1


async def test_relative_redirect():
    def handler(request):
        if request.url.path == "/old":
            return httpx.Response(301, headers={"location": "/new"})
        return html_response("new page")

    doc = await make_fetcher(handler).fetch("https://example.com/old")
    assert doc.final_url == "https://example.com/new"


async def test_too_many_redirects():
    def handler(request):
        return httpx.Response(302, headers={"location": "https://example.com/loop"})

    with pytest.raises(WebLimitExceeded, match="too many redirects"):
        await make_fetcher(handler, max_redirects=3).fetch("https://example.com/loop")


async def test_redirect_to_unsafe_destination_blocked():
    calls = []

    def handler(request):
        calls.append(request.headers["host"])
        return httpx.Response(302, headers={"location": "http://169.254.169.254/latest/meta-data/"})

    with pytest.raises(UnsafeWebTarget):
        await make_fetcher(handler).fetch("https://example.com/redir")
    assert calls == ["example.com"]  # the internal target was never requested


@pytest.mark.parametrize("location", [
    "http://localhost/admin", "http://127.0.0.1:8080/", "http://[::1]/", "http://10.0.0.1/",
    "file:///etc/passwd", "ftp://example.com/x", "http://user:pw@example.com/",
])
async def test_redirect_to_bad_targets_blocked(location):
    def handler(request):
        return httpx.Response(307, headers={"location": location})

    with pytest.raises((UnsafeWebTarget, InvalidWebURL)):
        await make_fetcher(handler).fetch("https://example.com/")


async def test_redirect_to_hostname_resolving_internal_blocked():
    resolver = FakeResolver({"rebind.example.com": ["10.1.2.3"]})

    def handler(request):
        return httpx.Response(302, headers={"location": "https://rebind.example.com/x"})

    with pytest.raises(UnsafeWebTarget):
        await make_fetcher(handler, resolver).fetch("https://example.com/")


async def test_timeout_is_typed_error():
    def handler(request):
        raise httpx.ReadTimeout("slow", request=request)

    with pytest.raises(FetchError, match="timed out"):
        await make_fetcher(handler).fetch("https://example.com/")


async def test_overall_deadline_for_slow_body():
    class SlowStream(httpx.AsyncByteStream):
        async def __aiter__(self):
            yield b"<html>"
            await asyncio.sleep(5)
            yield b"</html>"

    def handler(request):
        return httpx.Response(200, headers={"content-type": "text/html"}, stream=SlowStream())

    with pytest.raises(FetchError, match="timed out"):
        await make_fetcher(handler, request_timeout_seconds=0.05).fetch("https://example.com/")


async def test_network_error_is_typed_and_safe():
    def handler(request):
        raise httpx.ConnectError("boom token=abc123", request=request)

    with pytest.raises(FetchError, match="network error") as ei:
        await make_fetcher(handler).fetch("https://example.com/p?token=abc123")
    assert "abc123" not in str(ei.value)


@pytest.mark.parametrize("status", [404, 403, 500, 503])
async def test_http_errors(status):
    with pytest.raises(FetchError, match=f"HTTP {status}"):
        await make_fetcher(lambda r: httpx.Response(status)).fetch("https://example.com/missing?secret=1")


async def test_error_messages_omit_query_strings():
    with pytest.raises(FetchError) as ei:
        await make_fetcher(lambda r: httpx.Response(404)).fetch("https://example.com/p?apikey=SECRET")
    assert "SECRET" not in str(ei.value) and "example.com/p" in str(ei.value)


async def test_malformed_encoding_is_tolerated():
    body = b"<html><body>caf\xe9 \xff\xfe ok</body></html>"
    doc = await make_fetcher(lambda r: html_response(body, ctype="text/html; charset=utf-8")).fetch("https://example.com/")
    assert "ok" in doc.content and "\ufffd" in doc.content


async def test_declared_and_meta_charsets():
    latin = "<html><body>café</body></html>".encode("latin-1")
    d1 = await make_fetcher(lambda r: html_response(latin, ctype="text/html; charset=iso-8859-1")).fetch("https://example.com/")
    assert "café" in d1.content
    meta = b'<html><head><meta charset="iso-8859-1"></head><body>caf\xe9</body></html>'
    d2 = await make_fetcher(lambda r: html_response(meta, ctype="text/html")).fetch("https://example.com/")
    assert "café" in d2.content
    d3 = await make_fetcher(lambda r: html_response(b"abc", ctype="text/html; charset=nonsense-9")).fetch("https://example.com/")
    assert d3.content == "abc"


async def test_oversized_response_is_truncated_and_flagged():
    body = b"<html><body>" + b"a" * 50_000 + b"</body></html>"
    doc = await make_fetcher(lambda r: html_response(body), max_response_bytes=2_000).fetch("https://example.com/")
    assert doc.truncated is True and len(doc.content) == 2_000 and doc.metadata["bytes"] == 2_000


async def test_unsupported_content_types_are_not_downloaded():
    read = []

    class Tracking(httpx.AsyncByteStream):
        async def __aiter__(self):
            read.append(1)
            yield b"%PDF-1.4"

    def handler(request):
        return httpx.Response(200, headers={"content-type": "application/pdf"}, stream=Tracking())

    with pytest.raises(FetchError, match="unsupported content type"):
        await make_fetcher(handler).fetch("https://example.com/file.pdf")
    assert read == []


async def test_missing_content_type_text_ok_binary_refused():
    ok = await make_fetcher(lambda r: httpx.Response(200, content=b"plain words")).fetch("https://example.com/")
    assert ok.content == "plain words"
    with pytest.raises(FetchError, match="binary"):
        await make_fetcher(lambda r: httpx.Response(200, content=b"\x00\x01\x02bin")).fetch("https://example.com/")


# --- URL validation ------------------------------------------------------------


@pytest.mark.parametrize("url", [
    "file:///etc/passwd", "ftp://example.com/x", "data:text/html,hi", "javascript:alert(1)",
    "gopher://example.com", "ws://example.com", "//example.com/x", "example.com/x", "",
    "https://", "http:///path", "https://example.com/a b", "https://exa\nmple.com",
])
async def test_unsupported_or_malformed_urls_rejected(url):
    called = []
    fetcher = make_fetcher(lambda r: called.append(r) or html_response("x"))
    with pytest.raises(InvalidWebURL):
        await fetcher.fetch(url)
    assert called == []


@pytest.mark.parametrize("url", [
    "https://user@example.com/", "https://user:pass@example.com/", "http://:pw@example.com/",
])
async def test_credentials_in_url_rejected(url):
    with pytest.raises(InvalidWebURL, match="credentials"):
        await make_fetcher(lambda r: html_response("x")).fetch(url)


@pytest.mark.parametrize("url", [
    "http://localhost/", "http://LOCALHOST:8000/", "http://foo.localhost/", "http://127.0.0.1/",
    "http://127.1.2.3/", "http://[::1]/", "http://10.0.0.5/", "http://172.16.0.1/", "http://192.168.1.1/",
    "http://169.254.169.254/latest/meta-data/", "http://0.0.0.0/", "http://[::]/", "http://[fe80::1]/",
    "http://[fd00::1]/", "http://[::ffff:127.0.0.1]/", "http://[::ffff:10.0.0.1]/", "http://100.64.0.1/",
    "http://metadata.google.internal/", "http://printer.local/", "http://db.internal/", "http://224.0.0.1/",
    "http://[64:ff9b::7f00:1]/", "http://[2002:7f00:1::1]/",
])
async def test_internal_targets_blocked(url):
    called = []
    fetcher = make_fetcher(lambda r: called.append(r) or html_response("x"))
    with pytest.raises(UnsafeWebTarget):
        await fetcher.fetch(url)
    assert called == []


@pytest.mark.parametrize("url", ["http://2130706433/", "http://0x7f.0.0.1/", "http://0177.0.0.1/", "http://127.1/", "http://1/"])
async def test_numeric_obfuscated_hosts_rejected(url):
    with pytest.raises((InvalidWebURL, UnsafeWebTarget)):
        await make_fetcher(lambda r: html_response("x")).fetch(url)


@pytest.mark.parametrize("resolved", [
    ["127.0.0.1"], ["10.0.0.9"], ["169.254.169.254"], ["::1"], ["fc00::5"],
    [PUBLIC := "93.184.216.34", "10.0.0.1"],  # ANY internal answer blocks the target
])
async def test_hostname_resolving_to_unsafe_address_blocked(resolved):
    called = []
    fetcher = make_fetcher(lambda r: called.append(r) or html_response("x"), FakeResolver({"sneaky.example.com": resolved}))
    with pytest.raises(UnsafeWebTarget, match="non-public"):
        await fetcher.fetch("https://sneaky.example.com/")
    assert called == []


async def test_unresolvable_host_is_invalid_url():
    class Empty:
        async def resolve(self, host, port):
            return []

    with pytest.raises(InvalidWebURL, match="could not resolve"):
        await UrlValidator(Empty()).validate("https://nowhere.example.com/")


async def test_public_addresses_allowed_incl_ipv6_and_literal():
    v = UrlValidator(FakeResolver({"v6.example.com": ["2606:2800:220:1:248:1893:25c8:1946"]}))
    t = await v.validate("https://v6.example.com:8443/x")
    assert t.port == 8443 and t.host == "v6.example.com"
    t2 = await v.validate("http://93.184.216.34/x")
    assert t2.addresses == ("93.184.216.34",)


async def test_validator_normalizes():
    v = UrlValidator(FakeResolver())
    t = await v.validate("HTTPS://Example.COM:443/Path?q=1#frag")
    assert t.url == "https://example.com/Path?q=1"
    assert (await v.validate("https://bücher.example/")).host == "xn--bcher-kva.example"


def test_is_blocked_ip_table():
    for bad in ["127.0.0.1", "10.1.1.1", "172.31.0.1", "192.168.0.1", "169.254.1.1", "0.0.0.0", "255.255.255.255",
                "100.100.0.1", "198.18.0.1", "::1", "::", "fe80::1", "fc00::1", "ff02::1", "::ffff:192.168.0.1"]:
        assert is_blocked_ip(ipaddress.ip_address(bad)), bad
    for good in ["93.184.216.34", "8.8.8.8", "1.1.1.1", "2606:4700:4700::1111"]:
        assert not is_blocked_ip(ipaddress.ip_address(good)), good
