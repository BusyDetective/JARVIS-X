"""BrowserManager: lifecycle + policy + bounded results. START → VALIDATE TARGET → NAVIGATE → INSPECT →
RETURN BOUNDED RESULT → CLEAN UP.

* One incognito browser context at a time (tools carry no conversation identity, so the context is NOT
  isolated per conversation; it is temporary, never persisted, and discarded on close / idle expiry /
  crash / shutdown).
* Operations are serialized with a lock. Navigating/interacting operations spend a bounded action budget.
* Element ids ("l1", "f2", "c3") come from the latest snapshot only; they die on navigation.
"""
from __future__ import annotations

import asyncio
import logging
import re
import secrets
import time
from collections import OrderedDict
from collections.abc import Awaitable, Callable
from typing import Any
from urllib.parse import urljoin

from app.browser.driver import PageDriver, PlaywrightDriver, RawClickable, RawField, RawLink
from app.browser.errors import (
    BlockedURLError, BrowserCrashedError, BrowserError, BrowserLimitError, BrowserNavigationError,
    ElementNotFoundError, PolicyViolationError,
)
from app.browser.models import (
    BrowserLimits, ClickableInfo, FieldInfo, LinkInfo, PageState, ScreenshotInfo,
)
from app.browser.policy import BrowserPolicy

logger = logging.getLogger(__name__)

DriverFactory = Callable[[], Awaitable[PageDriver]]
_CTRL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")


def clean_text(text: str, max_chars: int) -> tuple[str, bool]:
    text = _CTRL.sub("", text.replace("\r", ""))
    text = re.sub(r"[ \t]+", " ", text)
    text = re.sub(r"\n\s*\n\s*\n+", "\n\n", text).strip()
    if len(text) > max_chars:
        return text[:max_chars].rstrip() + "…", True
    return text, False


class BrowserManager:
    def __init__(self, limits: BrowserLimits | None = None, policy: BrowserPolicy | None = None,
                 driver_factory: DriverFactory | None = None, clock: Callable[[], float] = time.monotonic) -> None:
        self.limits = limits or BrowserLimits()
        self.policy = policy or BrowserPolicy(self.limits)
        self._factory = driver_factory or (lambda: PlaywrightDriver.launch(self.limits, self.policy))
        self._clock = clock
        self._lock = asyncio.Lock()
        self._driver: PageDriver | None = None
        self._last_used = 0.0
        self._actions = 0
        self._redirects = 0
        self._history_len = 0
        self._links: dict[str, tuple[LinkInfo, RawLink]] = {}
        self._fields: dict[str, tuple[FieldInfo, RawField]] = {}
        self._clicks: dict[str, tuple[ClickableInfo, RawClickable]] = {}
        self._screens: "OrderedDict[str, tuple[bytes, ScreenshotInfo]]" = OrderedDict()
        self._current_url = ""

    # --- lifecycle ----------------------------------------------------------------

    @property
    def active(self) -> bool:
        return self._driver is not None

    def status(self) -> dict[str, Any]:
        return {"active": self.active, "url": self.policy.display_url(self._current_url) if self._driver else None,
                "actions_used": self._actions, "actions_remaining": max(0, self.limits.max_actions - self._actions)}

    async def close(self) -> None:
        async with self._lock:
            await self._discard()

    async def _discard(self) -> None:
        driver, self._driver = self._driver, None
        self._reset_snapshots()
        self._current_url = ""
        self._actions = self._redirects = self._history_len = 0
        if driver is not None:
            try:
                await driver.close()
            except Exception:  # noqa: BLE001 — cleanup must never raise
                logger.warning("browser: cleanup raised; continuing")

    def _reset_snapshots(self) -> None:
        self._links.clear(); self._fields.clear(); self._clicks.clear()

    async def _ensure(self) -> PageDriver:
        if self._driver is not None:
            expired = self._clock() - self._last_used > self.limits.idle_seconds
            if expired or not await self._driver.is_alive():
                await self._discard()
        if self._driver is None:
            self._driver = await self._factory()
            self._actions = 0
        self._last_used = self._clock()
        return self._driver

    async def _require(self) -> PageDriver:
        """For operations on an EXISTING page: never silently starts a new browser."""
        if self._driver is None:
            raise BrowserNavigationError("no page is open; use browser_open first")
        expired = self._clock() - self._last_used > self.limits.idle_seconds
        if expired or not await self._driver.is_alive():
            await self._discard()
            raise BrowserCrashedError(
                "the browser session ended (it expired or crashed); use browser_open to start a new one")
        self._last_used = self._clock()
        return self._driver

    def _spend(self) -> None:
        if self._actions >= self.limits.max_actions:
            raise BrowserLimitError("action budget for this browser session is used up; close it and open a new one")
        self._actions += 1

    async def _run(self, coro_fn: Callable[[], Awaitable[Any]]) -> Any:
        """Run under the lock; on a crash, discard the session so the next open starts clean."""
        async with self._lock:
            try:
                return await coro_fn()
            except BrowserCrashedError:
                await self._discard()
                raise

    # --- navigation ---------------------------------------------------------------

    async def _navigate(self, driver: PageDriver, url: str, how: str = "goto") -> None:
        self._reset_snapshots()
        redirects = 0
        while True:
            if how == "goto":
                res = await driver.navigate(url)
            elif how == "back":
                res = await driver.back()
            else:
                res = await driver.forward()
            if res.redirect_to is None:
                break
            redirects += 1
            if redirects > self.limits.max_redirects:
                raise BrowserLimitError("too many redirects")
            await self.policy.check_url(res.redirect_to)  # fail fast, before issuing the next navigation
            url, how = res.redirect_to, "goto"
        self._redirects = redirects
        self._current_url = await driver.url()
        if how == "goto":
            self._history_len += 1

    async def open(self, url: str) -> PageState:
        await self.policy.check_url(url)  # validate target BEFORE starting a browser
        async def op() -> PageState:
            driver = await self._ensure()
            self._spend()
            await self._navigate(driver, url)
            return await self._state(driver)
        return await self._run(op)

    async def back(self) -> PageState:
        async def op() -> PageState:
            driver = await self._require()
            self._spend()
            await self._navigate(driver, "", "back")
            return await self._state(driver)
        return await self._run(op)

    async def forward(self) -> PageState:
        async def op() -> PageState:
            driver = await self._require()
            self._spend()
            await self._navigate(driver, "", "forward")
            return await self._state(driver)
        return await self._run(op)

    async def follow_link(self, link_id: str) -> PageState:
        async def op() -> PageState:
            driver = await self._require()
            info, raw = self._lookup(self._links, link_id, "link")
            if not info.allowed:
                raise PolicyViolationError(f"link {link_id} denied: {info.reason}")
            target = urljoin(self._current_url, raw.href)
            await self.policy.check_url(target)
            self._spend()
            await self._navigate(driver, target)
            return await self._state(driver)
        return await self._run(op)

    # --- inspection ---------------------------------------------------------------

    async def _state(self, driver: PageDriver) -> PageState:
        current = await driver.url()
        if not current.startswith(("http://", "https://")):
            raise BrowserNavigationError("the page navigated to a blocked, failed or unsupported address")
        title = (await driver.title()) or ""
        text, truncated = clean_text(await driver.body_text(), self.limits.max_text_chars)
        return PageState(
            url=self.policy.display_url(await driver.url()), title=clean_text(title, 200)[0], text=text,
            text_truncated=truncated, redirects=self._redirects, blocked_requests=driver.blocked_count,
            actions_used=self._actions, actions_remaining=max(0, self.limits.max_actions - self._actions),
            history_length=self._history_len,
        )

    async def get_state(self) -> PageState:
        async def op() -> PageState:
            return await self._state(await self._require())
        return await self._run(op)

    async def list_links(self) -> list[LinkInfo]:
        async def op() -> list[LinkInfo]:
            driver = await self._require()
            self._links.clear()
            out: list[LinkInfo] = []
            for raw in await driver.links(self.limits.max_links):
                abs_href = urljoin(self._current_url, raw.href)
                ok, reason = self.policy.check_link(abs_href, raw.text, raw.attrs)
                info = LinkInfo(id=f"l{len(out) + 1}", text=clean_text(raw.text, 120)[0],
                                href=self.policy.strip_query(abs_href), allowed=ok, reason=reason)
                self._links[info.id] = (info, RawLink(raw.index, raw.text, abs_href, raw.attrs))
                out.append(info)
            return out
        return await self._run(op)

    async def list_fields(self) -> list[FieldInfo]:
        async def op() -> list[FieldInfo]:
            driver = await self._require()
            self._fields.clear()
            out: list[FieldInfo] = []
            for raw in await driver.fields(self.limits.max_form_fields):
                kind = raw.tag if raw.tag in ("textarea", "select") else raw.attrs.get("type", "text").lower() or "text"
                ok, reason = self.policy.check_field(
                    kind, raw.attrs.get("name"), raw.label, raw.attrs.get("placeholder"), raw.form_method,
                    raw.form_has_sensitive, raw.attrs.get("autocomplete"))
                info = FieldInfo(
                    id=f"f{len(out) + 1}", kind=kind, name=_c(raw.attrs.get("name")), label=_c(raw.label),
                    placeholder=_c(raw.attrs.get("placeholder")), form_id=raw.form_key,
                    form_method=raw.form_method, fillable=ok, reason=reason)
                self._fields[info.id] = (info, raw)
                out.append(info)
            return out
        return await self._run(op)

    async def list_clickables(self) -> list[ClickableInfo]:
        async def op() -> list[ClickableInfo]:
            driver = await self._require()
            self._clicks.clear()
            out: list[ClickableInfo] = []
            for raw in await driver.clickables(self.limits.max_form_fields):
                ok, reason = self.policy.check_click(raw.tag, raw.attrs, raw.text, raw.in_form)
                info = ClickableInfo(id=f"c{len(out) + 1}", tag=raw.tag, text=clean_text(raw.text, 120)[0],
                                     allowed=ok, reason=reason)
                self._clicks[info.id] = (info, raw)
                out.append(info)
            return out
        return await self._run(op)

    # --- interaction (deny by default) ----------------------------------------------

    async def fill(self, field_id: str, value: str) -> dict[str, Any]:
        async def op() -> dict[str, Any]:
            driver = await self._require()
            info, raw = self._lookup(self._fields, field_id, "field")
            if not info.fillable:
                raise PolicyViolationError(f"field {field_id} denied: {info.reason}")
            self.policy.check_fill_value(value)
            self._spend()
            await driver.fill(raw, value)
            return {"field_id": field_id, "filled": True, "length": len(value), "submitted": False}
        return await self._run(op)

    async def click(self, element_id: str) -> PageState:
        async def op() -> PageState:
            driver = await self._require()
            info, raw = self._lookup(self._clicks, element_id, "element")
            if not info.allowed:
                raise PolicyViolationError(f"click on {element_id} denied: {info.reason}")
            self._spend()
            await driver.click(raw)
            self._reset_snapshots()
            self._current_url = await driver.url()
            return await self._state(driver)
        return await self._run(op)

    # --- screenshots ----------------------------------------------------------------

    async def screenshot(self) -> ScreenshotInfo:
        async def op() -> ScreenshotInfo:
            driver = await self._require()
            shot = await driver.screenshot(self.limits.screenshot_max_bytes)
            sid = secrets.token_urlsafe(12)
            info = ScreenshotInfo(screenshot_id=sid, mime=shot.mime, width=shot.width, height=shot.height,
                                  bytes=len(shot.data))
            self._screens[sid] = (shot.data, info)
            while len(self._screens) > self.limits.max_screenshots_kept:
                self._screens.popitem(last=False)
            return info
        return await self._run(op)

    def get_screenshot(self, screenshot_id: str) -> tuple[bytes, str] | None:
        item = self._screens.get(screenshot_id)
        return (item[0], item[1].mime) if item else None

    # --- approval context ---------------------------------------------------------------

    def describe(self, tool_name: str, args: dict[str, Any]) -> dict[str, Any] | None:
        """What the human is actually approving (the model only supplies opaque ids)."""
        try:
            if tool_name == "browser_follow_link" and args.get("link_id") in self._links:
                info, _ = self._links[args["link_id"]]
                return {"destination": info.href, "link_text": info.text}
            if tool_name == "browser_fill_field" and args.get("field_id") in self._fields:
                info, _ = self._fields[args["field_id"]]
                return {"field": info.label or info.name or info.id, "kind": info.kind,
                        "value_length": len(str(args.get("value", "")))}
            if tool_name == "browser_click" and args.get("element_id") in self._clicks:
                info, _ = self._clicks[args["element_id"]]
                return {"element": info.tag, "text": info.text}
        except Exception:  # noqa: BLE001
            return None
        return None

    @staticmethod
    def _lookup(table: dict[str, tuple[Any, Any]], key: str, what: str) -> tuple[Any, Any]:
        if key not in table:
            raise ElementNotFoundError(f"unknown {what} id '{key[:20]}'; list the {what}s again (ids reset on navigation)")
        return table[key]


def _c(v: str | None) -> str | None:
    return clean_text(v, 120)[0] if v else None


__all__ = ["BrowserManager", "clean_text", "BrowserError", "BlockedURLError"]
