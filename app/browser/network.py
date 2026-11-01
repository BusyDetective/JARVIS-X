"""Network enforcement for the browser.

EVERY request the page makes (navigations, subresources, redirects) is intercepted and answered by
JARVIS-X itself: the target is validated by `BrowserPolicy` (Phase 6 `UrlValidator` + port/domain rules),
fetched with a single GET that connects to the validated IP (pinning; Host/SNI stay on the original name),
and handed to the browser with `route.fulfill`. The browser therefore never opens its own connection to a
page-chosen host, so redirects to private addresses and DNS rebinding cannot reach internal services.

Design notes (verified against a real Chromium, see tests/test_browser_real.py):
  * Redirects are NEVER returned to the browser: a fulfilled 3xx is followed by Chromium WITHOUT passing
    through the route handler again. Subresource redirects are followed here, hop by hop, validating each;
    a redirecting top-level navigation is aborted and re-issued by the manager, hop by hop.
  * Non-GET/HEAD requests are blocked (no form posts, no XHR writes, no beacons).
  * No cookies are sent or stored; Set-Cookie is dropped.
  * As defence in depth the browser is launched with a dead proxy, so any request that somehow bypasses
    interception fails closed instead of reaching the network.
"""
from __future__ import annotations

import asyncio
import logging
from typing import Any
from urllib.parse import urljoin, urlsplit

import httpx

from app.browser.errors import BlockedURLError, BrowserLimitError, safe_url
from app.browser.models import BrowserLimits
from app.browser.policy import BrowserPolicy
from app.web.urls import ValidatedTarget

logger = logging.getLogger(__name__)

USER_AGENT = "Mozilla/5.0 (compatible; JARVIS-X-browser/1.0; bounded observation)"
_REDIRECT_STATUSES = {301, 302, 303, 307, 308}
_BLOCKED_RESOURCE_TYPES = {
    "websocket", "eventsource", "media", "manifest", "ping", "prefetch", "cspviolationreport",
    "other", "signedexchange", "texttrack",
}
_FORWARD_HEADERS = ("content-type", "content-language")
MAX_BLOCK_LOG = 50


class HopResponse:
    __slots__ = ("status", "headers", "body")

    def __init__(self, status: int, headers: dict[str, str], body: bytes) -> None:
        self.status, self.headers, self.body = status, headers, body


class PinnedFetcher:
    """One GET per call, connecting to a pre-validated IP. Body is size-capped (over the cap is an error,
    never a silent truncation of something the browser would then render)."""

    def __init__(self, limits: BrowserLimits, transport: httpx.AsyncBaseTransport | None = None) -> None:
        self.limits = limits
        self._client = httpx.AsyncClient(
            transport=transport, follow_redirects=False, trust_env=False,
            timeout=httpx.Timeout(limits.navigation_timeout),
        )

    async def aclose(self) -> None:
        await self._client.aclose()

    async def fetch_once(self, target: ValidatedTarget, method: str, accept: str | None,
                         policy: BrowserPolicy) -> HopResponse:
        parts = urlsplit(target.url)
        ip = target.addresses[0]
        ip_host = f"[{ip}]" if ":" in ip else ip
        default_port = 443 if target.scheme == "https" else 80
        netloc = ip_host if target.port == default_port else f"{ip_host}:{target.port}"
        pinned = f"{target.scheme}://{netloc}{parts.path or '/'}" + (f"?{parts.query}" if parts.query else "")
        host_header = target.host if target.port == default_port else f"{target.host}:{target.port}"
        request = self._client.build_request(
            method, pinned,
            headers={"Host": host_header, "User-Agent": USER_AGENT, "Accept": accept or "*/*",
                     "Accept-Encoding": "gzip, deflate"},
            extensions={"sni_hostname": target.host},
        )
        response = await self._client.send(request, stream=True)
        try:
            headers = {k.lower(): v for k, v in response.headers.items()}
            status = response.status_code
            if status in _REDIRECT_STATUSES or method == "HEAD":
                return HopResponse(status, headers, b"")
            if not policy.content_type_allowed(headers.get("content-type"), headers.get("content-disposition")):
                raise BlockedURLError(f"blocked content type or download at {safe_url(target.url)}")
            buf = bytearray()
            async for chunk in response.aiter_bytes():
                buf.extend(chunk)
                if len(buf) > self.limits.max_resource_bytes:
                    raise BrowserLimitError(f"resource too large at {safe_url(target.url)}")
            return HopResponse(status, headers, bytes(buf))
        finally:
            await response.aclose()


class NetworkGuard:
    """Installed on one browser context. Holds per-navigation counters and a bounded, URL-free block log."""

    def __init__(self, policy: BrowserPolicy, fetcher: PinnedFetcher) -> None:
        self.policy = policy
        self.fetcher = fetcher
        self.limits = policy.limits
        self.requests = 0
        self.total_bytes = 0
        self.blocked: list[str] = []
        self.blocked_count = 0
        self.pending_redirect: str | None = None
        self.last_block_reason: str | None = None
        self._inflight: set[asyncio.Task] = set()

    async def cancel_inflight(self) -> None:
        """Called on close: no route handler may outlive the browser."""
        tasks = [t for t in self._inflight if not t.done()]
        for t in tasks:
            t.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

    def begin_navigation(self) -> None:
        self.requests = 0
        self.total_bytes = 0
        self.pending_redirect = None
        self.last_block_reason = None

    async def install(self, context: Any) -> None:
        await context.route("**/*", self.handle)
        route_ws = getattr(context, "route_web_socket", None)
        if route_ws is not None:  # WebSockets bypass page routes; close them all.
            async def _close(ws: Any) -> None:
                self._block("websocket")
                await ws.close()
            await route_ws("**/*", _close)

    def _block(self, reason: str) -> None:
        self.blocked_count += 1
        self.last_block_reason = reason
        if len(self.blocked) < MAX_BLOCK_LOG:
            self.blocked.append(reason)
        logger.info("browser: blocked request reason=%s", reason)

    async def handle(self, route: Any) -> None:
        req = route.request
        task = asyncio.current_task()
        if task is not None:
            self._inflight.add(task)
            task.add_done_callback(self._inflight.discard)
        try:
            await self._handle(route, req)
        except BlockedURLError as exc:
            self._block(str(exc)[:160])
            await _safe_abort(route)
        except BrowserLimitError as exc:
            self._block(str(exc)[:160])
            await _safe_abort(route)
        except httpx.HTTPError as exc:
            self._block(f"network error ({type(exc).__name__})")
            await _safe_abort(route, "failed")
        except Exception as exc:  # noqa: BLE001 — never leave a request hanging or let it fall through
            self._block(f"internal error ({type(exc).__name__})")
            await _safe_abort(route, "failed")

    async def _handle(self, route: Any, req: Any) -> None:
        method = req.method.upper()
        if method not in ("GET", "HEAD"):
            raise BlockedURLError(f"blocked {method} request (only GET/HEAD allowed)")
        if req.resource_type in _BLOCKED_RESOURCE_TYPES:
            raise BlockedURLError(f"blocked resource type {req.resource_type}")
        self.requests += 1
        if self.requests > self.limits.max_requests_per_page:
            raise BrowserLimitError("too many requests for one page")
        is_main_nav = bool(req.is_navigation_request() and req.frame.parent_frame is None)
        url = req.url
        accept = req.headers.get("accept")
        for hop in range(self.limits.max_redirects + 1):
            target = await self.policy.check_url(url)  # every hop
            resp = await self.fetcher.fetch_once(target, method, accept, self.policy)
            if resp.status in _REDIRECT_STATUSES and resp.headers.get("location"):
                nxt = urljoin(target.url, resp.headers["location"])
                if is_main_nav:
                    # Hand the (unvalidated) next hop back to the manager; the browser is never told.
                    self.pending_redirect = nxt
                    await _safe_abort(route)
                    return
                url = nxt
                continue
            break
        else:
            raise BrowserLimitError("too many redirects")
        self.total_bytes += len(resp.body)
        if self.total_bytes > self.limits.max_total_bytes:
            raise BrowserLimitError("page exceeded the total download budget")
        headers = {k: resp.headers[k] for k in _FORWARD_HEADERS if k in resp.headers}
        await route.fulfill(status=resp.status, headers=headers, body=resp.body)


async def _safe_abort(route: Any, code: str = "blockedbyclient") -> None:
    try:
        await route.abort(code)
    except Exception:  # noqa: BLE001 — route already handled / page closed
        pass
