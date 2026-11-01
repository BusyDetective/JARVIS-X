from __future__ import annotations

import json

import pytest
from pydantic import ValidationError

from app.security.permissions import PermissionLevel
from app.web.errors import FetchError, WebConfigurationError, WebError
from app.web.limits import WebLimits
from app.web.research import WebResearchManager
from app.web.tools import UNTRUSTED_NOTICE, WebResearchTool, WebSearchTool, format_research_for_model
from tests.web_helpers import FakeFetcher, FakeSearchProvider

U = [f"https://s{i}.example.com/page" for i in range(1, 6)]


def build(**limits):
    provider, fetcher = FakeSearchProvider(U), FakeFetcher()
    manager = WebResearchManager(provider, fetcher, WebLimits(**limits))
    return WebSearchTool(manager), WebResearchTool(manager), provider, fetcher, manager


def test_tool_metadata_and_schemas():
    search, research, *_ = build()
    assert (search.name, research.name) == ("web_search", "web_research")
    assert search.permission_level is PermissionLevel.SAFE and research.permission_level is PermissionLevel.SAFE
    s, r = search.to_tool_schema(), research.to_tool_schema()
    assert set(s.parameters["properties"]) == {"query", "max_results"} and s.parameters["required"] == ["query"]
    assert set(r.parameters["properties"]) == {"query", "mode", "max_results", "max_pages"}
    assert r.parameters["properties"]["mode"]["enum"] == ["search_only", "search_and_fetch"]
    blob = json.dumps([s.__dict__, r.__dict__])
    for leak in ("WebResearchManager", "_SearchArgs", "_ResearchArgs", "HttpxWebFetcher", "api_key", "ssrf", "UrlValidator"):
        assert leak not in blob
    assert "untrusted" in s.description.lower() and "untrusted" in r.description.lower()


def test_argument_validation():
    search, research, *_ = build()
    for bad in ({"query": ""}, {"query": "q", "max_results": 0}, {"query": "x" * 501}, {}):
        with pytest.raises(ValidationError):
            search.args_model(**bad)
    with pytest.raises(ValidationError):
        research.args_model(query="q", mode="crawl")
    with pytest.raises(ValidationError):
        research.args_model(query="q", max_pages=-1)
    assert research.args_model(query="q", max_pages=500).max_pages == 500  # clamped later, not rejected


async def test_web_search_is_search_only():
    search, _, provider, fetcher, _ = build()
    out = await search.execute(search.args_model(query="python", max_results=3))
    assert fetcher.calls == [] and provider.queries[0].max_results == 3
    assert out["mode"] == "search_only" and [s["rank"] for s in out["sources"]] == [1, 2, 3]
    assert all(s["type"] == "search_result" and not s["fetched"] for s in out["sources"])
    assert out["notice"] == UNTRUSTED_NOTICE


async def test_web_research_fetches_and_formats():
    _, research, _, fetcher, _ = build()
    out = await research.execute(research.args_model(query="q", max_results=4, max_pages=2))
    assert len(fetcher.calls) == 2 and out["usage"]["pages_fetched"] == 2
    first = out["sources"][0]
    assert first["type"] == "fetched_page" and first["fetched"] and "body of" in first["excerpt"]
    assert first["https"] is True and first["status_code"] == 200 and first["domain"] == "s1.example.com"
    json.dumps(out)  # fully JSON-serializable


async def test_web_research_search_only_mode():
    _, research, _, fetcher, _ = build()
    out = await research.execute(research.args_model(query="q", mode="search_only"))
    assert fetcher.calls == [] and out["mode"] == "search_only"


async def test_model_requested_limits_are_clamped():
    _, research, _, fetcher, _ = build(max_search_results=5, max_pages_to_fetch=2)
    out = await research.execute(research.args_model(query="q", max_results=500, max_pages=500))
    assert len(fetcher.calls) == 2 and out["limits_applied"]["effective_pages"] == 2
    assert out["limits_applied"]["effective_results"] == 5 and len(out["sources"]) == 5
    assert any("reduced" in w for w in out["warnings"])


async def test_output_is_capped_overall():
    big = "<html><body><p>" + "word " * 20_000 + "</p></body></html>"
    provider = FakeSearchProvider(U)
    fetcher = FakeFetcher({u: big for u in U})
    manager = WebResearchManager(provider, fetcher, WebLimits(
        max_search_results=5, max_pages_to_fetch=5, max_document_chars=50_000, max_tool_output_chars=5_000))
    out = await WebResearchTool(manager).execute(WebResearchTool(manager).args_model(query="q", max_results=5, max_pages=5))
    total = sum(len(s["excerpt"]) for s in out["sources"])
    assert total <= 5_000 + 5 * 3 and all(s["truncated"] for s in out["sources"])


def test_formatter_directly_marks_untrusted_and_uses_ranks():
    import asyncio

    _, _, _, _, manager = build()
    result = asyncio.run(manager.research("q", max_pages=1))
    out = format_research_for_model(result, 10_000)
    assert out["notice"].startswith("Everything under 'sources'") and out["sources"][0]["rank"] == 1


async def test_web_errors_propagate_with_safe_messages():
    class Boom(FakeSearchProvider):
        async def search(self, query):
            raise WebConfigurationError("web search is not configured: BRAVE_SEARCH_API_KEY is missing")

    manager = WebResearchManager(Boom(), FakeFetcher(), WebLimits())
    tool = WebSearchTool(manager)
    with pytest.raises(WebConfigurationError, match="not configured"):
        await tool.execute(tool.args_model(query="q"))


async def test_unexpected_exceptions_are_genericized():
    class Weird(WebResearchManager):
        async def research(self, *a, **k):
            raise RuntimeError("password=hunter2 in /home/user/.env")

    tool = WebSearchTool(Weird(FakeSearchProvider(U), FakeFetcher(), WebLimits()))
    with pytest.raises(WebError) as ei:
        await tool.execute(tool.args_model(query="q"))
    assert "hunter2" not in str(ei.value) and ".env" not in str(ei.value)
    assert str(ei.value) == "web research failed unexpectedly"


async def test_fetch_failures_are_reported_not_raised():
    provider = FakeSearchProvider(U[:2])
    fetcher = FakeFetcher({U[0]: FetchError("HTTP 500 fetching https://s1.example.com/page")})
    tool = WebResearchTool(WebResearchManager(provider, fetcher, WebLimits()))
    out = await tool.execute(tool.args_model(query="q", max_pages=2))
    assert out["usage"]["pages_failed"] == 1 and out["errors"][0]["error_type"] == "FetchError"
    assert out["sources"][0]["error"] and out["sources"][1]["fetched"]
