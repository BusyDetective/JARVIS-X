from __future__ import annotations

import asyncio

import pytest
from pydantic import ValidationError

from app.config.settings import settings
from app.web.limits import WebLimits
from app.web.models import ResearchMode
from app.web.research import WebResearchManager
from tests.web_helpers import FakeFetcher, FakeSearchProvider


def test_safe_defaults():
    L = WebLimits()
    assert (L.max_search_results, L.max_pages_to_fetch, L.max_redirects, L.max_concurrent_fetches) == (10, 5, 5, 3)
    assert L.max_response_bytes == 2_000_000 and L.max_document_chars == 8_000 and L.request_timeout_seconds == 15


@pytest.mark.parametrize("kw", [
    dict(max_search_results=0), dict(max_search_results=51), dict(max_pages_to_fetch=21),
    dict(max_response_bytes=10), dict(max_document_chars=5), dict(request_timeout_seconds=0),
    dict(max_redirects=11), dict(max_concurrent_fetches=0), dict(max_concurrent_fetches=11),
])
def test_absurd_values_rejected(kw):
    with pytest.raises(ValidationError):
        WebLimits(**kw)


def test_clamp_only_lowers():
    L = WebLimits()
    assert L.clamp(500, 5) == 5 and L.clamp(3, 5) == 3 and L.clamp(None, 5) == 5
    assert L.clamp(-4, 5) == 0 and L.clamp(0, 5) == 0


def test_from_settings(monkeypatch):
    monkeypatch.setattr(settings, "web_max_pages", 2)
    monkeypatch.setattr(settings, "web_max_results", 7)
    monkeypatch.setattr(settings, "web_request_timeout", 3.0)
    L = WebLimits.from_settings()
    assert (L.max_pages_to_fetch, L.max_search_results, L.request_timeout_seconds) == (2, 7, 3.0)


def urls(n):
    return [f"https://site{i}.example.com/p" for i in range(n)]


async def test_search_result_limit_enforced_even_if_provider_overreturns():
    provider = FakeSearchProvider(urls(30))
    mgr = WebResearchManager(provider, FakeFetcher(), WebLimits(max_search_results=4))
    res = await mgr.research("q", ResearchMode.SEARCH_ONLY, max_results=500)
    assert len(res.sources) == 4 and provider.queries[0].max_results == 4
    assert any("reduced" in w for w in res.warnings) and any("more results" in w for w in res.warnings)


async def test_page_limit_model_asks_500_gets_5():
    fetcher = FakeFetcher()
    mgr = WebResearchManager(FakeSearchProvider(urls(20)), fetcher, WebLimits(max_search_results=20, max_pages_to_fetch=5))
    res = await mgr.research("q", max_results=20, max_pages=500)
    assert len(fetcher.calls) == 5 and res.usage.pages_selected == 5
    assert res.limits_applied["effective_pages"] == 5 and res.limits_applied["requested_pages"] == 500
    assert any("max_pages reduced" in w for w in res.warnings)


async def test_model_can_lower_but_not_raise_limits():
    fetcher = FakeFetcher()
    mgr = WebResearchManager(FakeSearchProvider(urls(10)), fetcher, WebLimits(max_pages_to_fetch=5))
    await mgr.research("q", max_pages=2)
    assert len(fetcher.calls) == 2
    fetcher2 = FakeFetcher()
    await WebResearchManager(FakeSearchProvider(urls(10)), fetcher2).research("q", max_pages=0)
    assert fetcher2.calls == []


async def test_document_char_limit_applied_to_sources():
    big = "<html><body><p>" + "word " * 5000 + "</p></body></html>"
    u = "https://a.example.com/x"
    mgr = WebResearchManager(FakeSearchProvider([u]), FakeFetcher({u: big}), WebLimits(max_document_chars=300))
    res = await mgr.research("q")
    assert len(res.sources[0].content) <= 300 and res.sources[0].truncated is True


async def test_concurrency_limit_enforced():
    fetcher = FakeFetcher(delay=0.02)
    mgr = WebResearchManager(
        FakeSearchProvider(urls(9)), fetcher,
        WebLimits(max_search_results=9, max_pages_to_fetch=9, max_concurrent_fetches=2),
    )
    res = await mgr.research("q", max_results=9, max_pages=9)
    assert res.usage.pages_fetched == 9 and fetcher.peak == 2


async def test_concurrency_actually_parallel_up_to_limit():
    fetcher = FakeFetcher(delay=0.02)
    mgr = WebResearchManager(
        FakeSearchProvider(urls(6)), fetcher,
        WebLimits(max_search_results=6, max_pages_to_fetch=6, max_concurrent_fetches=3),
    )
    await mgr.research("q", max_results=6, max_pages=6)
    assert fetcher.peak == 3
    assert asyncio.get_running_loop() is not None
