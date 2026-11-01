from __future__ import annotations

import asyncio
import logging
import re
import time
from abc import ABC, abstractmethod
from urllib.parse import urljoin, urlsplit

import httpx

from app.web.errors import FetchError, WebLimitExceeded, safe_url
from app.web.limits import WebLimits
from app.web.models import WebDocument, utcnow
from app.web.urls import UrlValidator, ValidatedTarget

logger = logging.getLogger(__name__)

USER_AGENT = "JARVIS-X-research/1.0 (bounded information retrieval)"
_REDIRECT_STATUSES = {301, 302, 303, 307, 308}
_TEXT_TYPES = {
    "text/html", "application/xhtml+xml", "text/plain", "text/markdown",
    "text/xml", "application/xml", "application/json",
}
_META_CHARSET = re.compile(rb"<meta[^>]+charset=[\"']?\s*([A-Za-z0-9_\-:.]+)", re.IGNORECASE)


class WebFetcher(ABC):
    @abstractmethod
    async def fetch(self, url: str) -> WebDocument:
        """Fetch one public web page. Raises a WebError subclass on failure."""


def _decode(body: bytes, content_type_header: str | None) -> str:
    """Never raises: declared charset -> <meta> charset -> UTF-8, with
    undecodable bytes replaced."""
    charset: str | None = None
    if content_type_header:
        m = re.search(r"charset=([^;\s]+)", content_type_header, re.IGNORECASE)
        if m:
            charset = m.group(1).strip("\"'")
    if charset is None:
        m2 = _META_CHARSET.search(body[:4096])
        if m2:
            charset = m2.group(1).decode("ascii", "ignore")
    for candidate in (charset, "utf-8"):
        if not candidate:
            continue
        try:
            return body.decode(candidate, errors="replace")
        except LookupError:
            continue
    return body.decode("utf-8", errors="replace")


class HttpxWebFetcher(WebFetcher):
    """Plain bounded HTTP GET.

    - Redirects are followed MANUALLY (max `max_redirects`) so each hop's
      target goes through UrlValidator again.
    - Each hop connects to an IP the validator just verified (Host header
      and TLS SNI/certificate checking stay on the original hostname), so a
      DNS answer that changes after validation cannot redirect the
      connection to an internal address.
    - Streams the body and stops at `max_response_bytes` (the document is
      then flagged `truncated`); only text-like content types are read —
      anything else is refused without downloading the body.
    - No cookies, no credentials, no JavaScript, GET only.
    """

    def __init__(
        self,
        limits: WebLimits | None = None,
        validator: UrlValidator | None = None,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self.limits = limits or WebLimits()
        self.validator = validator or UrlValidator()
        self._transport = transport  # injectable for tests

    async def fetch(self, url: str) -> WebDocument:
        started = time.monotonic()
        current = url
        redirects = 0
        async with httpx.AsyncClient(
            transport=self._transport, follow_redirects=False, trust_env=False,
            timeout=httpx.Timeout(self.limits.request_timeout_seconds),
        ) as client:
            while True:
                target = await self.validator.validate(current)  # every hop
                try:
                    response_info = await asyncio.wait_for(
                        self._request(client, target), self.limits.request_timeout_seconds
                    )
                except asyncio.TimeoutError as exc:
                    raise FetchError(f"timed out fetching {safe_url(target.url)}") from exc
                except httpx.TimeoutException as exc:
                    raise FetchError(f"timed out fetching {safe_url(target.url)}") from exc
                except httpx.HTTPError as exc:
                    raise FetchError(
                        f"network error fetching {safe_url(target.url)} ({type(exc).__name__})"
                    ) from exc
                status, headers, body, truncated = response_info
                if status in _REDIRECT_STATUSES and headers.get("location"):
                    redirects += 1
                    if redirects > self.limits.max_redirects:
                        raise WebLimitExceeded(
                            f"too many redirects fetching {safe_url(url)} (max {self.limits.max_redirects})"
                        )
                    current = urljoin(target.url, headers["location"])
                    continue
                break
        if status >= 400:
            raise FetchError(f"HTTP {status} fetching {safe_url(target.url)}")
        ctype_header = headers.get("content-type")
        text = _decode(body, ctype_header)
        logger.info(
            "web_fetch: domain=%s status=%s bytes=%s truncated=%s redirects=%s elapsed=%.2fs",
            urlsplit(target.url).hostname, status, len(body), truncated, redirects,
            time.monotonic() - started,
        )
        return WebDocument(
            url=url,
            final_url=target.url,
            content=text,
            content_type=ctype_header,
            status_code=status,
            fetched_at=utcnow(),
            truncated=truncated,
            metadata={"redirects": redirects, "bytes": len(body)},
        )

    async def _request(
        self, client: httpx.AsyncClient, target: ValidatedTarget
    ) -> tuple[int, dict[str, str], bytes, bool]:
        parts = urlsplit(target.url)
        ip = target.addresses[0]
        ip_host = f"[{ip}]" if ":" in ip else ip
        default_port = 443 if target.scheme == "https" else 80
        netloc = ip_host if target.port == default_port else f"{ip_host}:{target.port}"
        pinned = f"{target.scheme}://{netloc}{parts.path or '/'}" + (f"?{parts.query}" if parts.query else "")
        host_header = target.host if target.port == default_port else f"{target.host}:{target.port}"
        request = client.build_request(
            "GET", pinned,
            headers={"Host": host_header, "User-Agent": USER_AGENT,
                     "Accept": "text/html,application/xhtml+xml,text/plain;q=0.9,*/*;q=0.1",
                     "Accept-Encoding": "gzip, deflate"},
            extensions={"sni_hostname": target.host},
        )
        response = await client.send(request, stream=True)
        try:
            headers = {k.lower(): v for k, v in response.headers.items()}
            status = response.status_code
            if status in _REDIRECT_STATUSES or status >= 400:
                return status, headers, b"", False
            ctype = (headers.get("content-type") or "").split(";")[0].strip().lower()
            if ctype and ctype not in _TEXT_TYPES:
                raise FetchError(
                    f"unsupported content type '{ctype[:60]}' at {safe_url(target.url)}; "
                    "only text and HTML pages are fetched"
                )
            limit = self.limits.max_response_bytes
            buf = bytearray()
            truncated = False
            async for chunk in response.aiter_bytes():
                room = limit - len(buf)
                if len(chunk) > room:
                    buf.extend(chunk[:room])
                    truncated = True
                    break
                buf.extend(chunk)
            if not ctype and b"\x00" in bytes(buf[:1024]):
                raise FetchError(f"unsupported binary content at {safe_url(target.url)}")
            return status, headers, bytes(buf), truncated
        finally:
            await response.aclose()
