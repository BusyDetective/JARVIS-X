from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone
from urllib.parse import urldefrag, urlsplit

from pydantic import ValidationError

from app.web.errors import SearchError, WebError, safe_url
from app.web.extraction import ExtractedContent, HtmlExtractor
from app.web.fetch import WebFetcher
from app.web.limits import WebLimits
from app.web.models import (
    ResearchError,
    ResearchMode,
    ResearchResult,
    ResearchSource,
    ResearchUsage,
    SafeSearch,
    SearchQuery,
    SearchResult,
    SourceType,
    WebDocument,
    domain_of,
    utcnow,
)
from app.web.search import SearchProvider

logger = logging.getLogger(__name__)


def _parse_published(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


class WebResearchManager:
    """search -> (optionally) fetch -> extract -> normalized sources.

    Knows nothing about HTTP, search-engine APIs or HTML: it talks to an
    injected SearchProvider and WebFetcher and an extractor. All bounds come
    from `WebLimits` and are applied on top of whatever the caller (e.g. a
    model) requests — requests can only lower them.

    Web content is DATA. This class never turns it into instructions,
    permissions, configuration or capability changes; it only returns
    ResearchSource records describing what was retrieved. It never writes
    to memory.
    """

    def __init__(
        self,
        search_provider: SearchProvider,
        fetcher: WebFetcher,
        limits: WebLimits | None = None,
        extractor: HtmlExtractor | None = None,
    ) -> None:
        self.search_provider = search_provider
        self.fetcher = fetcher
        self.limits = limits or WebLimits()
        self.extractor = extractor or HtmlExtractor()

    async def research(
        self,
        query: str,
        mode: ResearchMode = ResearchMode.SEARCH_AND_FETCH,
        max_results: int | None = None,
        max_pages: int | None = None,
        allowed_domains: list[str] | None = None,
        language: str | None = None,
        safe_search: SafeSearch = SafeSearch.MODERATE,
    ) -> ResearchResult:
        started_at = utcnow()
        warnings: list[str] = []
        effective_results = max(1, self.limits.clamp(max_results, self.limits.max_search_results))
        if max_results is not None and max_results > effective_results:
            warnings.append(f"max_results reduced from {max_results} to {effective_results} (configured limit)")
        if mode == ResearchMode.SEARCH_ONLY:
            effective_pages = 0
        else:
            effective_pages = self.limits.clamp(max_pages, self.limits.max_pages_to_fetch)
            if max_pages is not None and max_pages > effective_pages:
                warnings.append(f"max_pages reduced from {max_pages} to {effective_pages} (configured limit)")

        try:
            search_query = SearchQuery(
                query=query, max_results=effective_results,
                allowed_domains=allowed_domains or [], language=language, safe_search=safe_search,
            )
        except ValidationError as exc:
            raise SearchError("invalid search query: " + "; ".join(
                str(e["msg"]) for e in exc.errors()
            )[:300]) from None
        try:
            response = await self.search_provider.search(search_query)
        except WebError:
            raise
        except Exception as exc:  # noqa: BLE001 — provider bug must not leak raw details
            raise SearchError(f"search failed unexpectedly ({type(exc).__name__})") from exc

        results = list(response.results)
        if len(results) > effective_results:
            warnings.append("search provider returned more results than requested; extra results dropped")
            results = results[:effective_results]
        if not results:
            warnings.append("the search returned no results")

        candidates = self._select(results, effective_pages)
        errors: list[ResearchError] = []
        outcomes: dict[int, tuple[ExtractedContent, WebDocument] | ResearchError] = {}
        if candidates:
            sem = asyncio.Semaphore(self.limits.max_concurrent_fetches)
            fetched = await asyncio.gather(*(self._fetch_one(r, sem) for r in candidates))
            for result, outcome in zip(candidates, fetched):
                outcomes[result.rank] = outcome
                if isinstance(outcome, ResearchError):
                    errors.append(outcome)

        sources = [self._build_source(r, outcomes.get(r.rank), warnings) for r in results]
        usage = ResearchUsage(
            search_results_returned=len(results),
            pages_selected=len(candidates),
            pages_fetched=sum(1 for s in sources if s.fetch_succeeded),
            pages_failed=len(errors),
            content_chars=sum(len(s.content) for s in sources if s.fetch_succeeded),
        )
        if candidates and usage.pages_fetched == 0:
            warnings.append("all page fetches failed; only search snippets are available")
        logger.info(
            "web_research: provider=%s mode=%s results=%d fetched=%d failed=%d",
            self.search_provider.name, mode.value, len(results), usage.pages_fetched, usage.pages_failed,
        )
        return ResearchResult(
            query=search_query,
            mode=mode,
            search_provider=self.search_provider.name,
            search_results=results,
            sources=sources,
            warnings=warnings,
            errors=errors,
            started_at=started_at,
            completed_at=utcnow(),
            usage=usage,
            limits_applied={
                "requested_results": max_results,
                "effective_results": effective_results,
                "requested_pages": max_pages,
                "effective_pages": effective_pages,
                "max_response_bytes": self.limits.max_response_bytes,
                "max_document_chars": self.limits.max_document_chars,
                "max_concurrent_fetches": self.limits.max_concurrent_fetches,
                "request_timeout_seconds": self.limits.request_timeout_seconds,
                "max_redirects": self.limits.max_redirects,
            },
        )

    # --- internals ---------------------------------------------------------

    @staticmethod
    def _select(results: list[SearchResult], limit: int) -> list[SearchResult]:
        chosen: list[SearchResult] = []
        seen: set[str] = set()
        if limit <= 0:
            return chosen
        for r in results:
            key = urldefrag(r.url)[0].lower()
            if key in seen:
                continue
            seen.add(key)
            chosen.append(r)
            if len(chosen) >= limit:
                break
        return chosen

    async def _fetch_one(
        self, result: SearchResult, sem: asyncio.Semaphore
    ) -> tuple[ExtractedContent, WebDocument] | ResearchError:
        async with sem:
            try:
                doc = await self.fetcher.fetch(result.url)
                extracted = self.extractor.extract(
                    doc.content, doc.content_type, self.limits.max_document_chars, doc.final_url
                )
                return extracted, doc
            except WebError as exc:
                return ResearchError(url=safe_url(result.url), error_type=type(exc).__name__, message=str(exc))
            except asyncio.CancelledError:
                raise
            except Exception as exc:  # noqa: BLE001 — one bad page must not sink the research
                return ResearchError(
                    url=safe_url(result.url), error_type="FetchError",
                    message=f"unexpected error fetching {safe_url(result.url)} ({type(exc).__name__})",
                )

    def _build_source(
        self,
        result: SearchResult,
        outcome: tuple[ExtractedContent, WebDocument] | ResearchError | None,
        warnings: list[str],
    ) -> ResearchSource:
        base = dict(
            url=result.url, domain=result.domain, search_rank=result.rank, provider=result.provider,
            published_at=result.published_at, https=urlsplit(result.url).scheme == "https",
        )
        if outcome is None:  # not selected for fetching: snippet only
            return ResearchSource(
                title=result.title, source_type=SourceType.SEARCH_RESULT, content=result.snippet, **base,
            )
        if isinstance(outcome, ResearchError):
            return ResearchSource(
                title=result.title, source_type=SourceType.SEARCH_RESULT, content=result.snippet,
                error=outcome.message, **base,
            )
        extracted, doc = outcome
        if not extracted.text:
            warnings.append(f"no extractable text from {safe_url(doc.final_url)}")
        if doc.truncated:
            warnings.append(f"response from {domain_of(doc.final_url)} exceeded the size limit and was truncated")
        base.update(
            published_at=result.published_at or _parse_published(extracted.metadata.get("published")),
            https=urlsplit(doc.final_url).scheme == "https",
            domain=domain_of(doc.final_url) or result.domain,
        )
        return ResearchSource(
            title=extracted.title or result.title,
            source_type=SourceType.FETCHED_PAGE,
            retrieved_at=doc.fetched_at,
            status_code=doc.status_code,
            content_type=(doc.content_type or "").split(";")[0].strip().lower() or None,
            fetch_succeeded=True,
            content=extracted.text,
            truncated=doc.truncated or extracted.truncated,
            metadata={
                "final_url": safe_url(doc.final_url),
                "headings": extracted.headings[:10],
                "link_count": len(extracted.links),
                **{k: v for k, v in extracted.metadata.items() if k != "published"},
            },
            **base,
        )
