from __future__ import annotations

import json
import logging

import httpx
import pytest

from app.config.settings import settings
from app.web.errors import WebConfigurationError, WebProviderError
from app.web.models import SearchQuery
from app.web.search import BraveSearchProvider, SearchProvider, build_search_provider

KEY = "sk-test-SECRET-123"


def provider(handler, key=KEY, **kw):
    return BraveSearchProvider(key, transport=httpx.MockTransport(handler), **kw)


def ok(payload):
    return lambda request: httpx.Response(200, json=payload)


PAYLOAD = {"web": {"results": [
    {"title": " First  result ", "url": "https://a.example.com/1", "description": "desc  one",
     "page_age": "2025-03-01T10:00:00", "language": "en"},
    {"title": "Second", "url": "https://b.example.com/2", "description": "desc two"},
]}}


async def test_successful_search_normalizes_results():
    seen = {}

    def handler(request: httpx.Request):
        seen["url"], seen["headers"] = request.url, request.headers
        return httpx.Response(200, json=PAYLOAD)

    resp = await provider(handler).search(SearchQuery(query="asyncio", max_results=2, language="en-US"))
    assert resp.provider == "brave" and resp.returned_count == 2
    r1, r2 = resp.results
    assert (r1.rank, r1.title, r1.snippet, r1.domain) == (1, "First result", "desc one", "a.example.com")
    assert r1.published_at.tzinfo is not None and r1.published_at.year == 2025 and r2.published_at is None
    assert r1.metadata == {"language": "en"} and r2.rank == 2
    assert seen["url"].params["q"] == "asyncio" and seen["url"].params["count"] == "2"
    assert seen["url"].params["search_lang"] == "en" and seen["url"].params["safesearch"] == "moderate"
    assert seen["headers"]["x-subscription-token"] == KEY


async def test_domain_restriction_in_query_and_filtered_results():
    seen = {}

    def handler(request):
        seen["q"] = request.url.params["q"]
        return httpx.Response(200, json=PAYLOAD)

    q = SearchQuery(query="x", allowed_domains=["example.com"])
    assert (await provider(handler).search(q)).returned_count == 2
    assert seen["q"] == "(site:example.com) x"
    q2 = SearchQuery(query="x", allowed_domains=["a.example.com"])
    resp = await provider(handler).search(q2)
    assert [r.domain for r in resp.results] == ["a.example.com"] and resp.provider_metadata["skipped_results"] == 1


async def test_count_capped_to_api_ceiling():
    seen = {}
    many = {"web": {"results": [{"title": f"t{i}", "url": f"https://x{i}.com"} for i in range(30)]}}

    def handler(request):
        seen["count"] = request.url.params["count"]
        return httpx.Response(200, json=many)

    resp = await provider(handler).search(SearchQuery(query="q", max_results=50))
    assert seen["count"] == "20" and len(resp.results) == 30


async def test_empty_results_are_valid():
    for payload in ({"web": {"results": []}}, {"query": {}}):
        resp = await provider(ok(payload)).search(SearchQuery(query="q"))
        assert resp.results == [] and resp.returned_count == 0


async def test_invalid_items_are_skipped_not_fatal():
    payload = {"web": {"results": [
        "junk", {"title": "no url"}, {"url": "https://x.com"}, {"title": "bad", "url": "ftp://x.com"},
        {"title": "good", "url": "https://good.example.com"},
    ]}}
    resp = await provider(ok(payload)).search(SearchQuery(query="q"))
    assert [r.title for r in resp.results] == ["good"] and resp.provider_metadata["skipped_results"] == 4


@pytest.mark.parametrize("handler", [
    lambda r: httpx.Response(200, content=b"<html>not json"),
    lambda r: httpx.Response(200, json=["a list"]),
    lambda r: httpx.Response(200, json={"web": "string"}),
    lambda r: httpx.Response(200, json={"web": {"results": "nope"}}),
])
async def test_malformed_provider_response(handler):
    with pytest.raises(WebProviderError, match="malformed|unexpected"):
        await provider(handler).search(SearchQuery(query="q"))


@pytest.mark.parametrize("status,fragment", [(401, "credentials"), (403, "credentials"),
                                             (429, "rate limit"), (503, "unavailable"), (400, "rejected")])
async def test_http_errors(status, fragment):
    with pytest.raises(WebProviderError, match=fragment) as ei:
        await provider(lambda r: httpx.Response(status, text=f"body mentions {KEY}")).search(SearchQuery(query="q"))
    assert KEY not in str(ei.value)


async def test_timeout_and_network_errors_are_typed_and_safe():
    def timeout(request):
        raise httpx.ReadTimeout("slow", request=request)

    def network(request):
        raise httpx.ConnectError(f"cannot connect with {KEY}", request=request)

    with pytest.raises(WebProviderError, match="timed out"):
        await provider(timeout).search(SearchQuery(query="q"))
    with pytest.raises(WebProviderError, match="could not reach") as ei:
        await provider(network).search(SearchQuery(query="q"))
    assert KEY not in str(ei.value)


@pytest.mark.parametrize("key", [None, "", "   "])
async def test_missing_credentials_raise_and_never_fabricate(key):
    called = []
    p = provider(lambda r: called.append(r) or httpx.Response(200, json=PAYLOAD), key=key)
    assert p.is_configured is False
    with pytest.raises(WebConfigurationError, match="BRAVE_SEARCH_API_KEY"):
        await p.search(SearchQuery(query="q"))
    assert called == []  # no request is even attempted


def test_key_never_in_repr():
    assert KEY not in repr(BraveSearchProvider(KEY)) and "configured=True" in repr(BraveSearchProvider(KEY))


async def test_key_never_logged(caplog):
    caplog.set_level(logging.DEBUG)
    await provider(ok(PAYLOAD)).search(SearchQuery(query="q"))
    assert KEY not in caplog.text


def test_factory(monkeypatch):
    monkeypatch.setattr(settings, "brave_search_api_key", None)
    with pytest.raises(WebConfigurationError, match="not configured"):
        build_search_provider()
    monkeypatch.setattr(settings, "brave_search_api_key", KEY)
    p = build_search_provider()
    assert isinstance(p, SearchProvider) and p.name == "brave"
    with pytest.raises(WebConfigurationError, match="unknown web search provider"):
        build_search_provider("mystery")
    assert json.dumps(p.is_configured) == "true"


async def test_credential_bearing_results_are_dropped_during_normalization():
    payload = {"web": {"results": [
        {"title": "leaky", "url": "https://user:secret@example.com/private", "description": "d"},
        {"title": "leaky2", "url": "https://token@example.com/x"},
        {"title": "fine", "url": "https://example.com/@handle?e=a@b.c", "description": "ok"},
    ]}}
    resp = await provider(ok(payload)).search(SearchQuery(query="q"))
    assert [r.title for r in resp.results] == ["fine"] and resp.results[0].rank == 1
    assert resp.provider_metadata["skipped_results"] == 2
    assert "secret" not in resp.model_dump_json() and "token@" not in resp.model_dump_json()
