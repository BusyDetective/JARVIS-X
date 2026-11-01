"""Thin engine layer. `PageDriver` is the narrow surface the manager needs; `PlaywrightDriver` implements it.
No JavaScript supplied by the model (or by this code) is ever evaluated: DOM reads use Playwright locator
APIs, which run in Playwright's isolated utility world, so a page cannot lie to the policy by patching DOM APIs."""
from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass
from typing import Any, Protocol

from app.browser.errors import (
    BlockedURLError, BrowserCrashedError, BrowserNavigationError, BrowserStartupError,
    BrowserTimeoutError, BrowserUnavailableError, ElementNotFoundError, ScreenshotError,
)
from app.browser.models import BrowserLimits
from app.browser.network import NetworkGuard, PinnedFetcher, USER_AGENT
from app.browser.policy import BrowserPolicy

logger = logging.getLogger(__name__)


@dataclass
class NavResult:
    redirect_to: str | None = None  # set when the top-level navigation was redirected


@dataclass
class RawLink:
    index: int
    text: str
    href: str
    attrs: dict[str, str]


@dataclass
class RawField:
    index: int
    tag: str
    attrs: dict[str, str]
    label: str | None
    form_key: str | None
    form_method: str | None
    form_has_sensitive: bool


@dataclass
class RawClickable:
    index: int
    tag: str
    attrs: dict[str, str]
    text: str
    in_form: bool


@dataclass
class Shot:
    data: bytes
    mime: str
    width: int
    height: int


class PageDriver(Protocol):
    blocked_count: int

    async def navigate(self, url: str) -> NavResult: ...
    async def url(self) -> str: ...
    async def title(self) -> str: ...
    async def body_text(self) -> str: ...
    async def links(self, limit: int) -> list[RawLink]: ...
    async def fields(self, limit: int) -> list[RawField]: ...
    async def clickables(self, limit: int) -> list[RawClickable]: ...
    async def fill(self, field: RawField, value: str) -> None: ...
    async def click(self, item: RawClickable) -> None: ...
    async def screenshot(self, max_bytes: int) -> Shot: ...
    async def back(self) -> NavResult: ...
    async def forward(self) -> NavResult: ...
    async def is_alive(self) -> bool: ...
    async def close(self) -> None: ...


_FIELD_SELECTOR = "input, textarea, select"
_CLICK_SELECTOR = "button, summary, [role=button], input[type=submit], input[type=button], input[type=image]"
_ATTRS = ("type", "name", "id", "class", "title", "aria-label", "aria-expanded", "aria-controls", "role",
          "autocomplete", "placeholder", "download", "href")


def chromium_args(limits: BrowserLimits) -> list[str]:
    args = [
        "--disable-extensions", "--disable-sync", "--disable-background-networking", "--no-first-run",
        "--disable-component-update", "--disable-default-apps", "--disable-gpu",
        "--force-webrtc-ip-handling-policy=disable_non_proxied_udp",
        # Defence in depth: anything that bypasses request interception fails closed.
        "--proxy-server=http://127.0.0.1:9", "--proxy-bypass-list=<-loopback>",
    ]
    if limits.no_sandbox:
        args += ["--no-sandbox", "--disable-dev-shm-usage"]
    return args


class PlaywrightDriver:
    """One incognito context + one page. Never persists cookies, storage or profiles."""

    def __init__(self, pw: Any, browser: Any, context: Any, page: Any, guard: NetworkGuard,
                 fetcher: PinnedFetcher, limits: BrowserLimits) -> None:
        self._pw, self._browser, self._context, self._page = pw, browser, context, page
        self.guard, self._fetcher, self.limits = guard, fetcher, limits
        self._crashed = False
        self._closed = False
        page.on("crash", lambda *_: self._mark_crashed())
        browser.on("disconnected", lambda *_: self._mark_crashed())
        page.on("dialog", lambda d: asyncio.ensure_future(_dismiss(d)))
        context.on("page", lambda p: asyncio.ensure_future(self._close_popup(p)))

    @property
    def blocked_count(self) -> int:
        return self.guard.blocked_count

    def _mark_crashed(self) -> None:
        self._crashed = True

    async def _close_popup(self, p: Any) -> None:
        if p is not self._page:
            self.guard._block("popup")
            try:
                await p.close()
            except Exception:  # noqa: BLE001
                pass

    # --- construction -----------------------------------------------------------

    @classmethod
    async def launch(cls, limits: BrowserLimits, policy: BrowserPolicy, transport: Any = None) -> "PlaywrightDriver":
        try:
            from playwright.async_api import async_playwright
        except ImportError:
            raise BrowserUnavailableError(
                "Playwright is not installed. Install the optional dependency: pip install -r requirements-browser.txt"
            ) from None
        pw = browser = fetcher = None
        try:
            pw = await async_playwright().start()
            args = chromium_args(limits)
            kwargs: dict[str, Any] = {"headless": True, "args": args}
            if limits.executable_path:
                kwargs["executable_path"] = str(limits.executable_path)
            browser = await pw.chromium.launch(**kwargs)
            context = await browser.new_context(
                viewport={"width": limits.viewport_width, "height": limits.viewport_height},
                java_script_enabled=limits.javascript_enabled, service_workers="block", accept_downloads=False,
                user_agent=USER_AGENT, locale="en-US", permissions=[], ignore_https_errors=False,
            )
            fetcher = PinnedFetcher(limits, transport)
            guard = NetworkGuard(policy, fetcher)
            await guard.install(context)
            page = await context.new_page()
            page.set_default_timeout(limits.action_timeout * 1000)
            return cls(pw, browser, context, page, guard, fetcher, limits)
        except BrowserUnavailableError:
            raise
        except Exception as exc:  # noqa: BLE001
            logger.error("browser: startup failed: %s", type(exc).__name__)
            for closer in (browser and browser.close, pw and pw.stop):
                if closer:
                    try:
                        await closer()
                    except Exception:  # noqa: BLE001
                        pass
            if fetcher is not None:
                await fetcher.aclose()
            raise BrowserStartupError(
                "the browser could not be started (is a browser binary installed? run "
                "`python -m playwright install chromium` or set BROWSER_EXECUTABLE_PATH; "
                "as root/in containers set BROWSER_NO_SANDBOX=true)"
            ) from None

    # --- helpers ----------------------------------------------------------------

    def _check_alive(self) -> None:
        if self._crashed or self._closed:
            raise BrowserCrashedError("the browser page crashed or was closed; open a page again")

    async def _guarded(self, make: Any) -> Any:
        """Run one driver operation (`make` is a zero-arg callable returning a coroutine). Retries ONCE when a
        navigation (e.g. a meta refresh) destroyed the execution context mid-read."""
        self._check_alive()
        for attempt in (1, 2):
            try:
                return await asyncio.wait_for(make(), self.limits.action_timeout + 5)
            except asyncio.TimeoutError:
                raise BrowserTimeoutError("browser operation timed out") from None
            except (BrowserCrashedError, ElementNotFoundError):
                raise
            except Exception as exc:  # noqa: BLE001
                if self._crashed:
                    raise BrowserCrashedError("the browser page crashed; open a page again") from None
                transient = "context was destroyed" in str(exc) or "navigating" in str(exc)
                if attempt == 1 and transient:
                    await asyncio.sleep(0.4)
                    continue
                logger.info("browser: operation failed: %s", type(exc).__name__)
                raise BrowserNavigationError("browser operation failed") from None

    async def _navigate_with(self, op: Any) -> NavResult:
        self._check_alive()
        self.guard.begin_navigation()
        try:
            await asyncio.wait_for(op(), self.limits.navigation_timeout + 5)
        except asyncio.TimeoutError:
            raise BrowserTimeoutError("navigation timed out") from None
        except Exception as exc:  # noqa: BLE001
            if self.guard.pending_redirect:
                return NavResult(redirect_to=self.guard.pending_redirect)
            if self._crashed:
                raise BrowserCrashedError("the browser page crashed; open a page again") from None
            name = type(exc).__name__
            if "Timeout" in name:
                raise BrowserTimeoutError("navigation timed out") from None
            if self.guard.last_block_reason:
                raise BlockedURLError(self.guard.last_block_reason) from None
            logger.info("browser: navigation failed: %s", name)
            raise BrowserNavigationError("navigation failed") from None
        if self.guard.pending_redirect:
            return NavResult(redirect_to=self.guard.pending_redirect)
        return NavResult()

    # --- PageDriver -------------------------------------------------------------

    async def navigate(self, url: str) -> NavResult:
        return await self._navigate_with(lambda: self._page.goto(
            url, wait_until="domcontentloaded", timeout=self.limits.navigation_timeout * 1000))

    async def back(self) -> NavResult:
        async def op() -> None:
            if await self._page.go_back(wait_until="domcontentloaded", timeout=self.limits.navigation_timeout * 1000) is None:
                raise BrowserNavigationError("no earlier page in history")
        return await self._navigate_with(op)

    async def forward(self) -> NavResult:
        async def op() -> None:
            if await self._page.go_forward(wait_until="domcontentloaded", timeout=self.limits.navigation_timeout * 1000) is None:
                raise BrowserNavigationError("no later page in history")
        return await self._navigate_with(op)

    async def url(self) -> str:
        self._check_alive()
        return self._page.url

    async def title(self) -> str:
        return await self._guarded(lambda: self._page.title())

    async def body_text(self) -> str:
        return await self._guarded(lambda: self._page.locator("body").inner_text(timeout=self.limits.action_timeout * 1000))

    async def _attrs(self, loc: Any) -> dict[str, str]:
        out: dict[str, str] = {}
        for name in _ATTRS:
            v = await loc.get_attribute(name, timeout=2000)
            if v is not None:
                out[name] = v[:200]
        return out

    async def links(self, limit: int) -> list[RawLink]:
        async def run() -> list[RawLink]:
            loc = self._page.locator("a[href]")
            n = min(await loc.count(), limit * 4)
            out: list[RawLink] = []
            for i in range(n):
                el = loc.nth(i)
                if not await el.is_visible():
                    continue
                attrs = await self._attrs(el)
                out.append(RawLink(i, ((await el.inner_text(timeout=2000)) or "").strip()[:200], attrs.get("href", ""), attrs))
                if len(out) >= limit:
                    break
            return out
        return await self._guarded(run)

    async def fields(self, limit: int) -> list[RawField]:
        async def run() -> list[RawField]:
            loc = self._page.locator(_FIELD_SELECTOR)
            n = min(await loc.count(), limit * 3)
            out: list[RawField] = []
            for i in range(n):
                el = loc.nth(i)
                tag = await _tag(el)
                attrs = await self._attrs(el)
                if attrs.get("type", "").lower() != "hidden" and not await el.is_visible():
                    continue
                label = attrs.get("aria-label") or await _label(el, attrs)
                form = el.locator("xpath=ancestor::form[1]")
                form_key = form_method = None
                sensitive = False
                if await form.count():
                    form_method = ((await form.get_attribute("method", timeout=2000)) or "get").lower()
                    sensitive = bool(await form.locator(
                        "input[type=password], input[type=file], input[autocomplete^='cc-'], input[autocomplete*='password']"
                    ).count())
                    form_key = (await form.get_attribute("id", timeout=2000)) or (await form.get_attribute("name", timeout=2000)) or "form"
                out.append(RawField(i, tag, attrs, label, form_key, form_method, sensitive))
                if len(out) >= limit:
                    break
            return out
        return await self._guarded(run)

    async def clickables(self, limit: int) -> list[RawClickable]:
        async def run() -> list[RawClickable]:
            loc = self._page.locator(_CLICK_SELECTOR)
            n = min(await loc.count(), limit * 3)
            out: list[RawClickable] = []
            for i in range(n):
                el = loc.nth(i)
                if not await el.is_visible():
                    continue
                attrs = await self._attrs(el)
                tag = await _tag(el)
                text = ((await el.inner_text(timeout=2000)) if tag != "input" else attrs.get("value", "")) or ""
                in_form = bool(await el.locator("xpath=ancestor::form[1]").count())
                out.append(RawClickable(i, tag, attrs, text.strip()[:200], in_form))
                if len(out) >= limit:
                    break
            return out
        return await self._guarded(run)

    async def fill(self, field: RawField, value: str) -> None:
        async def run() -> None:
            el = self._page.locator(_FIELD_SELECTOR).nth(field.index)
            now = await self._attrs(el)
            if now.get("name") != field.attrs.get("name") or now.get("type") != field.attrs.get("type"):
                raise ElementNotFoundError("the page changed; list the form fields again")
            await el.fill(value, timeout=self.limits.action_timeout * 1000)
        await self._guarded(run)

    async def click(self, item: RawClickable) -> None:
        async def run() -> None:
            el = self._page.locator(_CLICK_SELECTOR).nth(item.index)
            if await _tag(el) != item.tag:
                raise ElementNotFoundError("the page changed; list clickable elements again")
            await el.click(timeout=self.limits.action_timeout * 1000, no_wait_after=True)
        await self._guarded(run)

    async def screenshot(self, max_bytes: int) -> Shot:
        self._check_alive()
        data = b""
        for quality in (70, 50, 30):
            try:
                data = await asyncio.wait_for(
                    self._page.screenshot(type="jpeg", quality=quality, full_page=False),
                    self.limits.action_timeout + 5)
            except asyncio.TimeoutError:
                raise ScreenshotError("screenshot timed out") from None
            except Exception as exc:  # noqa: BLE001
                if self._crashed:
                    raise BrowserCrashedError("the browser page crashed; open a page again") from None
                logger.info("browser: screenshot failed: %s", type(exc).__name__)
                raise ScreenshotError("screenshot failed") from None
            if len(data) <= max_bytes:
                return Shot(data, "image/jpeg", self.limits.viewport_width, self.limits.viewport_height)
        raise ScreenshotError("screenshot exceeds the size limit even at low quality")

    async def is_alive(self) -> bool:
        return not (self._crashed or self._closed) and self._browser.is_connected()

    async def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        try:
            await self.guard.cancel_inflight()
        except Exception:  # noqa: BLE001
            pass
        for closer in (self._context.close, self._browser.close, self._pw.stop, self._fetcher.aclose):
            try:
                await asyncio.wait_for(closer(), 10)
            except Exception:  # noqa: BLE001 — cleanup must always continue
                pass


async def _dismiss(dialog: Any) -> None:
    try:
        await dialog.dismiss()
    except Exception:  # noqa: BLE001
        pass


async def _tag(el: Any) -> str:
    """Element name via XPath (evaluated in Playwright's isolated world, not the page's)."""
    for name in ("input", "textarea", "select", "button", "summary", "a"):
        if await el.locator(f"xpath=self::{name}").count():
            return name
    return "other"


async def _label(el: Any, attrs: dict[str, str]) -> str | None:
    ident = attrs.get("id")
    if ident:
        lab = el.page.locator(f"label[for={_css_str(ident)}]")
        if await lab.count():
            return ((await lab.first.inner_text(timeout=2000)) or "").strip()[:120] or None
    return None


def _css_str(value: str) -> str:
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'
