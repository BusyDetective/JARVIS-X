from __future__ import annotations

import asyncio
import json

import pytest

from app.web.errors import FetchError, SearchError, UnsafeWebTarget, WebConfigurationError, WebProviderError
from app.web.extraction import HtmlExtractor
from app.web.limits import WebLimits
from app.web.models import ResearchMode, SearchQuery, SearchResponse, SearchResult, SourceType
from app.web.research import WebResearchManager
from app.web.search import SearchProvider
from tests.web_helpers import FakeFetcher, FakeSearchProvider

U = [f"https://s{i}.example.com/page" for i in range(1, 5)]


def mgr(provider=None, fetcher=None, **limits):
    return WebResearchManager(provider or FakeSearchProvider(U), fetcher or FakeFetcher(), WebLimits(**limits))


async def test_search_only_never_fetches():
    fetcher = FakeFetcher()
    res = await mgr(fetcher=fetcher).research("q", ResearchMode.SEARCH_ONLY)
    assert fetcher.calls == [] and res.mode == ResearchMode.SEARCH_ONLY
    assert [s.source_type for s in res.sources] == [SourceType.SEARCH_RESULT] * 4
    assert res.sources[0].content == "snippet 1" and res.usage.pages_selected == 0
    assert res.limits_applied["effective_pages"] == 0


async def test_search_and_fetch_normalizes_sources():
    res = await mgr(max_pages_to_fetch=2).research("q", max_results=4, max_pages=2)
    fetched, snippet_only = res.sources[:2], res.sources[2:]
    for i, s in enumerate(fetched, 1):
        assert s.source_type == SourceType.FETCHED_PAGE and s.fetch_succeeded and s.search_rank == i
        assert s.title == f"T {U[i-1]}" and f"body of {U[i-1]}" in s.content
        assert s.https is True and s.status_code == 200 and s.content_type == "text/html"
        assert s.domain == f"s{i}.example.com" and s.provider == "fake" and s.retrieved_at.tzinfo is not None
    assert all(not s.fetch_succeeded and s.source_type == SourceType.SEARCH_RESULT for s in snippet_only)
    assert res.usage.pages_fetched == 2 and res.usage.pages_failed == 0 and res.usage.content_chars > 0
    assert res.search_provider == "fake" and res.started_at <= res.completed_at
    assert len(res.search_results) == 4 and res.errors == []


async def test_partial_fetch_failure_is_source_level():
    fetcher = FakeFetcher({U[1]: FetchError("HTTP 500 fetching https://s2.example.com/page"),
                           U[2]: UnsafeWebTarget("refusing to fetch an internal host name")})
    res = await mgr(fetcher=fetcher).research("q", max_pages=4)
    assert [s.fetch_succeeded for s in res.sources] == [True, False, False, True]
    failed = res.sources[1]
    assert failed.source_type == SourceType.SEARCH_RESULT and failed.content == "snippet 2" and "HTTP 500" in failed.error
    assert {e.error_type for e in res.errors} == {"FetchError", "UnsafeWebTarget"}
    assert res.usage.pages_fetched == 2 and res.usage.pages_failed == 2
    assert not any("all page fetches failed" in w for w in res.warnings)


async def test_all_fetches_failing_still_returns_snippets():
    fetcher = FakeFetcher({u: FetchError(f"HTTP 503 fetching {u}") for u in U})
    res = await mgr(fetcher=fetcher).research("q", max_pages=4)
    assert res.usage.pages_fetched == 0 and res.usage.pages_failed == 4
    assert any("all page fetches failed" in w for w in res.warnings)
    assert [s.content for s in res.sources] == ["snippet 1", "snippet 2", "snippet 3", "snippet 4"]


async def test_unexpected_fetcher_exception_is_contained_and_safe():
    fetcher = FakeFetcher({U[0]: RuntimeError("internal detail secret=zzz")})
    res = await mgr(fetcher=fetcher).research("q", max_pages=2)
    assert res.sources[0].fetch_succeeded is False and res.sources[1].fetch_succeeded
    assert "zzz" not in json.dumps(res.model_dump(mode="json")) and "RuntimeError" in res.errors[0].message


async def test_non_html_unsupported_extraction_is_source_level_error():
    fetcher = FakeFetcher(ctype="application/pdf")
    res = await mgr(fetcher=fetcher).research("q", max_pages=1)
    assert res.errors[0].error_type == "ExtractionError" and not res.sources[0].fetch_succeeded


async def test_plain_text_documents_supported():
    fetcher = FakeFetcher({U[0]: "just  some\n\n\n text"}, ctype="text/plain")
    res = await mgr(fetcher=fetcher).research("q", max_pages=1)
    assert res.sources[0].content == "just some\n\ntext"


async def test_empty_page_warns():
    res = await mgr(fetcher=FakeFetcher({U[0]: "<html></html>"})).research("q", max_pages=1)
    assert res.sources[0].fetch_succeeded and res.sources[0].content == ""
    assert any("no extractable text" in w for w in res.warnings)


async def test_bounded_concurrency_and_rank_order_preserved():
    class Staggered(FakeFetcher):
        async def fetch(self, url):
            await asyncio.sleep(0.03 if url == U[0] else 0.001)  # first page finishes last
            return await super().fetch(url)

    f = Staggered()
    res = await mgr(fetcher=f, max_concurrent_fetches=2).research("q", max_pages=4)
    assert f.peak <= 2 and [s.search_rank for s in res.sources] == [1, 2, 3, 4]


async def test_duplicate_urls_fetched_once():
    provider = FakeSearchProvider([U[0], U[0] + "#frag", U[1]])
    fetcher = FakeFetcher()
    res = await mgr(provider, fetcher).research("q", max_pages=3)
    assert fetcher.calls == [U[0], U[1]] and len(res.sources) == 3


async def test_empty_search_results():
    res = await mgr(FakeSearchProvider([])).research("q")
    assert res.sources == [] and any("no results" in w for w in res.warnings) and res.usage.pages_selected == 0


async def test_search_errors_propagate_typed():
    class Failing(SearchProvider):
        name = "failing"

        def __init__(self, exc):
            self.exc = exc

        async def search(self, query):
            raise self.exc

    for exc, expected in [(WebProviderError("down"), WebProviderError),
                          (WebConfigurationError("no key"), WebConfigurationError)]:
        with pytest.raises(expected):
            await mgr(Failing(exc)).research("q")
    with pytest.raises(SearchError, match="unexpectedly") as ei:
        await mgr(Failing(RuntimeError("api_key=SECRET"))).research("q")
    assert "SECRET" not in str(ei.value)


async def test_invalid_query_is_search_error():
    with pytest.raises(SearchError, match="invalid search query"):
        await mgr().research("   ")


async def test_provider_independence_with_a_different_provider():
    class Other(SearchProvider):
        name = "other-engine"

        async def search(self, query: SearchQuery) -> SearchResponse:
            r = SearchResult(title="From other", url="https://other.example.org/x", rank=1, provider=self.name)
            return SearchResponse(query=query, results=[r], provider=self.name)

    res = await mgr(Other()).research("q", max_pages=1)
    assert res.search_provider == "other-engine" and res.sources[0].provider == "other-engine"
    assert res.sources[0].fetch_succeeded


async def test_published_date_from_result_or_page_metadata():
    page = '<html><head><title>P</title><meta property="article:published_time" content="2025-02-03T04:05:06Z"></head><body>x</body></html>'
    res = await mgr(FakeSearchProvider(U[:1]), FakeFetcher({U[0]: page})).research("q", max_pages=1)
    assert res.sources[0].published_at.year == 2025 and res.sources[0].published_at.tzinfo is not None
    assert res.sources[0].metadata["final_url"] == U[0] and "published" not in res.sources[0].metadata


async def test_result_is_serializable():
    res = await mgr().research("q", max_pages=2)
    again = json.loads(res.model_dump_json())
    assert again["usage"]["pages_fetched"] == 2 and again["limits_applied"]["effective_pages"] == 2


async def test_custom_extractor_is_used():
    class Upper(HtmlExtractor):
        def extract(self, content, content_type, max_chars, base_url=None):
            r = super().extract(content, content_type, max_chars, base_url)
            return r.model_copy(update={"text": r.text.upper()})

    m = WebResearchManager(FakeSearchProvider(U[:1]), FakeFetcher(), WebLimits(), Upper())
    assert (await m.research("q", max_pages=1)).sources[0].content.isupper()


async def test_credentialed_search_results_never_reach_sources_or_tool_output():
    import httpx
    from app.web.search import BraveSearchProvider
    from app.web.tools import WebSearchTool

    payload = {"web": {"results": [
        {"title": "leaky", "url": "https://user:secret@example.com/private", "description": "d"},
        {"title": "fine", "url": "https://ok.example.com/p", "description": "ok"},
    ]}}
    provider = BraveSearchProvider("k", transport=httpx.MockTransport(lambda r: httpx.Response(200, json=payload)))
    manager = WebResearchManager(provider, FakeFetcher(), WebLimits())
    result = await manager.research("q", ResearchMode.SEARCH_ONLY)
    assert [s.url for s in result.sources] == ["https://ok.example.com/p"]
    tool = WebSearchTool(manager)
    out = await tool.execute(tool.args_model(query="q"))
    assert "secret" not in json.dumps(out) and "user:" not in json.dumps(out)
