from __future__ import annotations

import logging
import time
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from typing import Any, ClassVar

import httpx

from app.web.errors import WebConfigurationError, WebProviderError
from app.web.models import SafeSearch, SearchQuery, SearchResponse, SearchResult, domain_of

logger = logging.getLogger(__name__)


class SearchProvider(ABC):
    """Provider-neutral web search. The research layer depends only on
    this; adding another engine means adding another subclass (and a
    branch in `build_search_provider`) — nothing else changes."""

    name: ClassVar[str]

    @abstractmethod
    async def search(self, query: SearchQuery) -> SearchResponse:
        """Raises WebConfigurationError (not configured) or WebProviderError."""


class BraveSearchProvider(SearchProvider):
    """Brave Search API (https://api.search.brave.com) — plain HTTPS+JSON,
    no scraping. The key comes from configuration, travels only in the
    `X-Subscription-Token` header, and never appears in errors or logs.

    NOTE: written against Brave's documented response shape
    (`web.results[].{title,url,description,page_age}`); it is exercised in
    tests with mocked responses only, not against the live service.
    """

    name = "brave"
    BASE_URL = "https://api.search.brave.com/res/v1/web/search"
    MAX_COUNT = 20  # per-request ceiling of the API

    def __init__(
        self,
        api_key: str | None,
        timeout_seconds: float = 15.0,
        transport: httpx.AsyncBaseTransport | None = None,
        base_url: str | None = None,
    ) -> None:
        self._api_key = (api_key or "").strip() or None
        self._timeout = timeout_seconds
        self._transport = transport
        self._base_url = base_url or self.BASE_URL

    @property
    def is_configured(self) -> bool:
        return self._api_key is not None

    def __repr__(self) -> str:  # never reveal the key
        return f"BraveSearchProvider(configured={self.is_configured})"

    async def search(self, query: SearchQuery) -> SearchResponse:
        if self._api_key is None:
            raise WebConfigurationError(
                "web search is not configured: BRAVE_SEARCH_API_KEY is missing"
            )
        q = query.query
        if query.allowed_domains:
            sites = " OR ".join(f"site:{d}" for d in query.allowed_domains)
            q = f"({sites}) {q}"
        params: dict[str, Any] = {
            "q": q,
            "count": min(query.max_results, self.MAX_COUNT),
            "safesearch": {SafeSearch.OFF: "off", SafeSearch.MODERATE: "moderate",
                           SafeSearch.STRICT: "strict"}[query.safe_search],
        }
        if query.language:
            params["search_lang"] = query.language.split("-")[0].lower()
        started = time.monotonic()
        try:
            async with httpx.AsyncClient(
                transport=self._transport, timeout=self._timeout, trust_env=False
            ) as client:
                response = await client.get(
                    self._base_url,
                    params=params,
                    headers={"Accept": "application/json", "X-Subscription-Token": self._api_key},
                )
        except httpx.TimeoutException as exc:
            raise WebProviderError("search provider timed out") from exc
        except httpx.HTTPError as exc:
            raise WebProviderError(
                f"could not reach the search provider ({type(exc).__name__})"
            ) from exc
        logger.info(
            "web_search: provider=%s status=%s elapsed=%.2fs",
            self.name, response.status_code, time.monotonic() - started,
        )
        self._raise_for_status(response.status_code)
        return self._parse(query, response)

    # --- internals ---------------------------------------------------------

    @staticmethod
    def _raise_for_status(status: int) -> None:
        if status in (401, 403):
            raise WebProviderError("search provider rejected the credentials (HTTP %d)" % status)
        if status == 429:
            raise WebProviderError("search provider rate limit reached (HTTP 429)")
        if status >= 500:
            raise WebProviderError("search provider is unavailable (HTTP %d)" % status)
        if status >= 400:
            raise WebProviderError("search provider rejected the request (HTTP %d)" % status)

    def _parse(self, query: SearchQuery, response: httpx.Response) -> SearchResponse:
        try:
            data = response.json()
        except ValueError as exc:
            raise WebProviderError("search provider returned malformed JSON") from exc
        if not isinstance(data, dict):
            raise WebProviderError("search provider returned an unexpected response shape")
        web = data.get("web")
        if web is None:
            raw_results: Any = []  # no `web` section: a valid "no results" response
        elif isinstance(web, dict) and isinstance(web.get("results", []), list):
            raw_results = web.get("results", [])
        else:
            raise WebProviderError("search provider returned an unexpected response shape")

        results: list[SearchResult] = []
        skipped = 0
        for item in raw_results:
            if not isinstance(item, dict):
                skipped += 1
                continue
            url = item.get("url")
            title = item.get("title")
            if not isinstance(url, str) or not isinstance(title, str) or not title.strip():
                skipped += 1
                continue
            if query.allowed_domains and not any(
                domain_of(url) == d or domain_of(url).endswith("." + d) for d in query.allowed_domains
            ):
                skipped += 1
                continue
            try:
                results.append(
                    SearchResult(
                        title=" ".join(title.split())[:300],
                        url=url,
                        snippet=" ".join(str(item.get("description") or "").split())[:1000],
                        rank=len(results) + 1,
                        provider=self.name,
                        published_at=self._parse_date(item.get("page_age")),
                        metadata={k: item[k] for k in ("language", "family_friendly") if k in item},
                    )
                )
            except ValueError:
                skipped += 1
        return SearchResponse(
            query=query,
            results=results[: query.max_results],
            provider=self.name,
            provider_metadata={"skipped_results": skipped},
        )

    @staticmethod
    def _parse_date(value: Any) -> datetime | None:
        if not isinstance(value, str) or not value:
            return None
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return None
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def build_search_provider(
    name: str | None = None,
    api_key: str | None = None,
    timeout_seconds: float | None = None,
) -> SearchProvider:
    """Builds the configured provider; raises WebConfigurationError for an
    unknown provider name or missing credentials — never returns a provider
    that cannot work."""
    from app.config.settings import settings

    provider_name = (name or settings.web_search_provider).strip().lower()
    timeout = timeout_seconds if timeout_seconds is not None else settings.web_request_timeout
    if provider_name == "brave":
        provider = BraveSearchProvider(api_key or settings.brave_search_api_key, timeout)
        if not provider.is_configured:
            raise WebConfigurationError(
                "web search is not configured: BRAVE_SEARCH_API_KEY is missing"
            )
        return provider
    raise WebConfigurationError(f"unknown web search provider '{provider_name[:40]}'")
