from __future__ import annotations

import json
from datetime import datetime

import pytest
from pydantic import ValidationError

from app.web.models import (
    ResearchMode,
    ResearchResult,
    ResearchSource,
    SearchQuery,
    SearchResponse,
    SearchResult,
    SourceType,
    WebDocument,
)


def test_valid_query_defaults_and_normalization():
    q = SearchQuery(query="  python   asyncio \n tips ")
    assert q.query == "python asyncio tips" and q.max_results == 5
    assert q.allowed_domains == [] and q.language is None and q.safe_search.value == "moderate"


@pytest.mark.parametrize("bad", [
    dict(query=""), dict(query="   "), dict(query="x" * 501),
    dict(query="q", max_results=0), dict(query="q", max_results=51),
    dict(query="q", language="english!"), dict(query="q", allowed_domains=["not a domain"]),
    dict(query="q", allowed_domains=["localhost"]), dict(query="q", safe_search="loose"),
    dict(query="q", allowed_domains=[f"d{i}.com" for i in range(11)]),
])
def test_invalid_queries(bad):
    with pytest.raises(ValidationError):
        SearchQuery(**bad)


def test_domains_normalized_and_deduped():
    q = SearchQuery(query="q", allowed_domains=[" Example.COM ", "example.com", "docs.python.org"], language="en-US")
    assert q.allowed_domains == ["example.com", "docs.python.org"] and q.language == "en-US"


def test_search_result_validation_and_domain():
    r = SearchResult(title="t", url="https://Docs.Python.org/3/", rank=1, provider="p")
    assert r.domain == "docs.python.org" and r.snippet == ""
    for bad_url in ("ftp://x.com/a", "javascript:alert(1)", "/relative", "https://", "file:///etc/passwd"):
        with pytest.raises(ValidationError):
            SearchResult(title="t", url=bad_url, rank=1, provider="p")
    with pytest.raises(ValidationError):
        SearchResult(title="t", url="https://a.com", rank=0, provider="p")
    with pytest.raises(ValidationError):
        SearchResult(title="t", url="https://a.com", rank=1, provider="p", published_at=datetime(2026, 1, 1))


def test_search_response_counts_results():
    q = SearchQuery(query="q")
    rs = [SearchResult(title="t", url=f"https://a{i}.com", rank=i, provider="p") for i in (1, 2)]
    assert SearchResponse(query=q, results=rs, provider="p").returned_count == 2
    assert SearchResponse(query=q, results=[], provider="p").returned_count == 0


def test_web_document_defaults():
    d = WebDocument(url="https://a.com/x", final_url="https://b.com/y", content="hi", status_code=200)
    assert d.domain == "b.com" and d.fetched_at.tzinfo is not None and d.truncated is False
    with pytest.raises(ValidationError):
        WebDocument(url="gopher://a", final_url="https://b.com", content="", status_code=200)
    with pytest.raises(ValidationError):
        WebDocument(url="https://a.com", final_url="https://b.com", content="", status_code=200,
                    fetched_at=datetime(2026, 1, 1))


def test_research_models_serialize_and_roundtrip():
    q = SearchQuery(query="q")
    src = ResearchSource(url="https://a.com", title="t", domain="a.com", source_type=SourceType.FETCHED_PAGE)
    assert src.retrieved_at.tzinfo is not None and src.fetch_succeeded is False
    res = ResearchResult(query=q, mode=ResearchMode.SEARCH_ONLY, search_provider="p", sources=[src])
    data = json.loads(res.model_dump_json())
    assert data["mode"] == "search_only" and data["sources"][0]["source_type"] == "fetched_page"
    assert ResearchResult.model_validate(data).sources[0].url == "https://a.com"
    assert res.started_at.tzinfo is not None and res.completed_at.tzinfo is not None
    with pytest.raises(ValidationError):
        ResearchSource(url="https://a.com", title="t", domain="a.com", source_type="search_result",
                       retrieved_at=datetime(2026, 1, 1))


CRED_URLS = [
    "https://user:secret@example.com/", "https://user@example.com/", "http://:pw@example.com/x",
    "https://example.com@evil.com/", "http://user:secret@93.184.216.34:8080/a?b=1",
]


@pytest.mark.parametrize("url", CRED_URLS)
def test_credential_bearing_urls_rejected_by_models(url):
    with pytest.raises(ValidationError, match="credentials"):
        SearchResult(title="t", url=url, rank=1, provider="p")
    with pytest.raises(ValidationError):
        WebDocument(url=url, final_url="https://example.com/", content="", status_code=200)
    with pytest.raises(ValidationError):
        WebDocument(url="https://example.com/", final_url=url, content="", status_code=200)


def test_at_sign_outside_authority_is_fine():
    r = SearchResult(title="t", url="https://example.com/@user/post?email=a@b.com#x@y", rank=1, provider="p")
    assert r.domain == "example.com"
