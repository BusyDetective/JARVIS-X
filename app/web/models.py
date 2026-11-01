from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any
from urllib.parse import urlsplit

from pydantic import BaseModel, Field, field_validator, model_validator

import re

_LANG_RE = re.compile(r"^[a-z]{2,3}(-[A-Za-z]{2,4})?$")
_DOMAIN_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _require_utc(v: datetime | None) -> datetime | None:
    if v is not None and v.tzinfo is None:
        raise ValueError("datetime fields must be timezone-aware (UTC), not naive")
    return v


def _check_http_url(v: str) -> str:
    """Syntactic check for URL fields on web models: absolute http(s) with a
    host and no embedded credentials. Internal-target/SSRF decisions remain
    UrlValidator's job (applied again at fetch time)."""
    parts = urlsplit(v)
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise ValueError("url must be an absolute http(s) URL")
    if parts.username is not None or parts.password is not None or "@" in parts.netloc:
        # Credential-bearing URLs must never become model-facing sources.
        raise ValueError("url must not contain embedded credentials")
    return v


def domain_of(url: str) -> str:
    return (urlsplit(url).hostname or "").lower()


class SafeSearch(str, Enum):
    OFF = "off"
    MODERATE = "moderate"
    STRICT = "strict"


class ResearchMode(str, Enum):
    SEARCH_ONLY = "search_only"
    SEARCH_AND_FETCH = "search_and_fetch"


class SourceType(str, Enum):
    SEARCH_RESULT = "search_result"  # snippet only; page not (successfully) fetched
    FETCHED_PAGE = "fetched_page"


class SearchQuery(BaseModel):
    query: str
    max_results: int = Field(default=5, ge=1, le=50)
    allowed_domains: list[str] = Field(default_factory=list, max_length=10)
    language: str | None = None
    safe_search: SafeSearch = SafeSearch.MODERATE

    @field_validator("query")
    @classmethod
    def _query_ok(cls, v: str) -> str:
        v = " ".join(v.split())
        if not v:
            raise ValueError("query cannot be blank")
        if len(v) > 500:
            raise ValueError("query is too long (max 500 characters)")
        return v

    @field_validator("allowed_domains")
    @classmethod
    def _domains_ok(cls, v: list[str]) -> list[str]:
        out: list[str] = []
        for d in v:
            d = d.strip().lower()
            if not _DOMAIN_RE.match(d):
                raise ValueError(f"invalid domain: {d!r}")
            if d not in out:
                out.append(d)
        return out

    @field_validator("language")
    @classmethod
    def _lang_ok(cls, v: str | None) -> str | None:
        if v is not None and not _LANG_RE.match(v):
            raise ValueError("language must look like 'en' or 'en-US'")
        return v


class SearchResult(BaseModel):
    title: str
    url: str
    snippet: str = ""
    domain: str = ""
    rank: int = Field(ge=1)
    provider: str
    published_at: datetime | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("url")
    @classmethod
    def _url_ok(cls, v: str) -> str:
        return _check_http_url(v)

    @field_validator("published_at")
    @classmethod
    def _utc(cls, v: datetime | None) -> datetime | None:
        return _require_utc(v)

    @model_validator(mode="after")
    def _fill_domain(self) -> "SearchResult":
        if not self.domain:
            self.domain = domain_of(self.url)
        return self


class SearchResponse(BaseModel):
    query: SearchQuery
    results: list[SearchResult]
    provider: str
    returned_count: int = 0
    provider_metadata: dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode="after")
    def _count(self) -> "SearchResponse":
        self.returned_count = len(self.results)
        return self


class WebDocument(BaseModel):
    """A fetched page. `content` is the decoded body as received (bounded
    by max_response_bytes) — text extraction happens separately."""

    url: str
    final_url: str
    title: str | None = None
    content: str
    content_type: str | None = None
    status_code: int
    fetched_at: datetime = Field(default_factory=utcnow)
    domain: str = ""
    truncated: bool = False
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("url", "final_url")
    @classmethod
    def _url_ok(cls, v: str) -> str:
        return _check_http_url(v)

    @field_validator("fetched_at")
    @classmethod
    def _utc(cls, v: datetime) -> datetime:
        return _require_utc(v)  # type: ignore[return-value]

    @model_validator(mode="after")
    def _fill_domain(self) -> "WebDocument":
        if not self.domain:
            self.domain = domain_of(self.final_url)
        return self


class ResearchSource(BaseModel):
    """One source offered to the model. All fields are FACTS about retrieval
    (where it came from, how it was fetched); nothing here asserts the
    content is true or trustworthy."""

    url: str
    title: str
    domain: str
    source_type: SourceType
    search_rank: int | None = None
    retrieved_at: datetime = Field(default_factory=utcnow)
    published_at: datetime | None = None
    https: bool = False
    status_code: int | None = None
    content_type: str | None = None
    fetch_succeeded: bool = False
    content: str = ""  # excerpt: extracted page text, or the search snippet
    truncated: bool = False
    provider: str = ""
    error: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("retrieved_at", "published_at")
    @classmethod
    def _utc(cls, v: datetime | None) -> datetime | None:
        return _require_utc(v)


class ResearchError(BaseModel):
    url: str | None = None
    error_type: str
    message: str


class ResearchUsage(BaseModel):
    search_results_returned: int = 0
    pages_selected: int = 0
    pages_fetched: int = 0
    pages_failed: int = 0
    content_chars: int = 0


class ResearchResult(BaseModel):
    query: SearchQuery
    mode: ResearchMode
    search_provider: str
    search_results: list[SearchResult] = Field(default_factory=list)
    sources: list[ResearchSource] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    errors: list[ResearchError] = Field(default_factory=list)
    started_at: datetime = Field(default_factory=utcnow)
    completed_at: datetime = Field(default_factory=utcnow)
    usage: ResearchUsage = Field(default_factory=ResearchUsage)
    limits_applied: dict[str, Any] = Field(default_factory=dict)

    @field_validator("started_at", "completed_at")
    @classmethod
    def _utc(cls, v: datetime) -> datetime:
        return _require_utc(v)  # type: ignore[return-value]
