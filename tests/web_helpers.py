"""Shared fakes for the web tests. Nothing here touches the network."""
from __future__ import annotations

import asyncio

import httpx

from app.web.errors import FetchError
from app.web.fetch import HttpxWebFetcher, WebFetcher
from app.web.limits import WebLimits
from app.web.models import SearchQuery, SearchResponse, SearchResult, WebDocument
from app.web.search import SearchProvider
from app.web.urls import UrlValidator

PUBLIC_IP = "93.184.216.34"


class FakeResolver:
    def __init__(self, mapping: dict[str, list[str]] | None = None, default: list[str] | None = None):
        self.mapping = mapping or {}
        self.default = default if default is not None else [PUBLIC_IP]
        self.calls: list[str] = []

    async def resolve(self, host: str, port: int) -> list[str]:
        self.calls.append(host)
        return self.mapping.get(host, self.default)


def make_fetcher(handler, resolver=None, **limit_kw) -> HttpxWebFetcher:
    return HttpxWebFetcher(
        WebLimits(**limit_kw), UrlValidator(resolver or FakeResolver()), httpx.MockTransport(handler)
    )


def html_response(body: str | bytes, status=200, ctype="text/html; charset=utf-8", headers=None):
    h = {"content-type": ctype, **(headers or {})}
    return httpx.Response(status, content=body if isinstance(body, bytes) else body.encode(), headers=h)


class FakeSearchProvider(SearchProvider):
    name = "fake"

    def __init__(self, urls: list[str] | None = None, results: list[SearchResult] | None = None):
        self.queries: list[SearchQuery] = []
        if results is None:
            urls = urls if urls is not None else []
            results = [
                SearchResult(title=f"Result {i}", url=u, snippet=f"snippet {i}", rank=i, provider="fake")
                for i, u in enumerate(urls, 1)
            ]
        self._results = results

    async def search(self, query: SearchQuery) -> SearchResponse:
        self.queries.append(query)
        return SearchResponse(query=query, results=list(self._results), provider=self.name)


class FakeFetcher(WebFetcher):
    """Serves canned pages; tracks calls and peak concurrency."""

    def __init__(self, pages: dict[str, str | Exception] | None = None, delay: float = 0.0, ctype="text/html"):
        self.pages = pages or {}
        self.delay = delay
        self.ctype = ctype
        self.calls: list[str] = []
        self.in_flight = 0
        self.peak = 0

    async def fetch(self, url: str) -> WebDocument:
        self.calls.append(url)
        self.in_flight += 1
        self.peak = max(self.peak, self.in_flight)
        try:
            if self.delay:
                await asyncio.sleep(self.delay)
            page = self.pages.get(url, f"<html><title>T {url}</title><body><p>body of {url}</p></body></html>")
            if isinstance(page, Exception):
                raise page
            return WebDocument(url=url, final_url=url, content=page, content_type=self.ctype, status_code=200)
        finally:
            self.in_flight -= 1


__all__ = ["FakeResolver", "make_fetcher", "html_response", "FakeSearchProvider", "FakeFetcher", "FetchError"]
