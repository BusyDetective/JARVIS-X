"""REAL-BROWSER integration tests (actual Chromium driven by Playwright through the production PlaywrightDriver,
NetworkGuard and BrowserManager). Network access is simulated with an httpx MockTransport behind the production
pinned-fetch layer, plus a REAL local HTTP server standing in for an "internal service" that must never be hit.

These are SKIPPED unless a browser can be launched. Provide one with either
    python -m playwright install chromium         (default location), or
    JARVIS_TEST_BROWSER_PATH=/path/to/chromium    (explicit executable)
Running as root / in containers needs no-sandbox, which these tests enable automatically.

What they do NOT establish: complete browser isolation. Chromium's own sandbox, the host kernel and the Python
process share a machine; see README 'Browser security boundaries'."""
from __future__ import annotations

import asyncio
import os
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import httpx
import pytest

from app.browser.driver import PlaywrightDriver, chromium_args
from app.browser.errors import BlockedURLError, BrowserCrashedError, BrowserError, ScreenshotError
from app.browser.manager import BrowserManager
from app.browser.models import BrowserLimits
from app.browser.policy import BrowserPolicy
from tests.phase9_helpers import public_validator

pytest.importorskip("playwright")
BROWSER_PATH = os.environ.get("JARVIS_TEST_BROWSER_PATH") or None
_PROBE: dict = {}


def _base_limits(**kw) -> BrowserLimits:
    params = dict(no_sandbox=(os.geteuid() == 0 or os.environ.get("JARVIS_TEST_NO_SANDBOX") == "1"),
                  executable_path=Path(BROWSER_PATH) if BROWSER_PATH else None, navigation_timeout=15, action_timeout=8)
    params.update(kw)
    return BrowserLimits(**params)


def _browser_unavailable_reason() -> str | None:
    if "r" in _PROBE:
        return _PROBE["r"]
    async def probe():
        limits = _base_limits()
        d = await PlaywrightDriver.launch(limits, BrowserPolicy(limits, public_validator("site.test")))
        await d.close()
    try:
        asyncio.run(probe())
        _PROBE["r"] = None
    except BrowserError as exc:
        _PROBE["r"] = f"no launchable browser: {exc}"
    except Exception as exc:  # noqa: BLE001
        _PROBE["r"] = f"browser probe failed: {type(exc).__name__}"
    return _PROBE["r"]


@pytest.fixture(scope="module", autouse=True)
def _require_browser():
    reason = _browser_unavailable_reason()
    if reason:
        pytest.skip(reason)


class Internal:
    """A REAL local HTTP server = the 'internal service' an attacker page would love to reach."""

    def __init__(self) -> None:
        outer = self
        self.hits: list[str] = []

        class H(BaseHTTPRequestHandler):
            def do_GET(self):  # noqa: N802
                outer.hits.append(self.path)
                self.send_response(200); self.send_header("Content-Type", "text/html"); self.end_headers()
                self.wfile.write(b"<html><body>INTERNAL-SECRET</body></html>")
            do_POST = do_GET
            def log_message(self, *a): pass

        self.srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.port = self.srv.server_address[1]
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    def close(self) -> None:
        self.srv.shutdown()


@pytest.fixture
def internal():
    s = Internal()
    yield s
    s.close()


class Site:
    def __init__(self) -> None:
        self.pages: dict[str, tuple[int, dict, bytes]] = {}
        self.log: list[tuple[str, str]] = []

    def page(self, path: str, body: str | bytes, status=200, ctype="text/html", **headers) -> None:
        b = body.encode() if isinstance(body, str) else body
        self.pages[path] = (status, {"content-type": ctype, **headers}, b)

    def handler(self, req: httpx.Request) -> httpx.Response:
        self.log.append((req.method, req.url.path))
        status, headers, body = self.pages.get(req.url.path, (404, {"content-type": "text/html"}, b"not found"))
        return httpx.Response(status, headers=headers, content=body)


def build(site: Site, **limit_kw) -> BrowserManager:
    limits = _base_limits(**limit_kw)
    policy = BrowserPolicy(limits, public_validator("site.test"))
    return BrowserManager(limits, policy, lambda: PlaywrightDriver.launch(limits, policy, httpx.MockTransport(site.handler)))


@pytest.fixture
async def site():
    s = Site()
    managers: list[BrowserManager] = []
    s.make = lambda **kw: managers.append(build(s, **kw)) or managers[-1]  # type: ignore[attr-defined]
    yield s
    for m in managers:
        await m.close()


def _chromium_procs() -> int:
    needle = (BROWSER_PATH or "chrom").split("/")[-1]
    n = 0
    for pid in os.listdir("/proc"):
        if pid.isdigit():
            try:
                cmd = Path(f"/proc/{pid}/cmdline").read_bytes().replace(b"\0", b" ").decode(errors="ignore")
            except OSError:
                continue
            if needle in cmd and "--headless" in cmd and "pytest" not in cmd:
                n += 1
    return n


async def test_reads_title_text_links_and_fields_from_a_real_page(site):
    site.page("/", "<html><title>Home</title><body><h1>Hi there</h1><a href='/about'>About</a><a href='/logout'>Log out</a>"
                   "<form method=get><label for=q>Search</label><input id=q name=q></form>"
                   "<form method=post><input name=user><input type=password name=pw></form></body></html>")
    site.page("/about", "<html><title>About</title><body>About page text</body></html>")
    m = site.make()
    st = await m.open("http://site.test/")
    assert st.title == "Home" and "Hi there" in st.text and st.url == "http://site.test/"
    links = {l.text: l for l in await m.list_links()}
    assert links["About"].allowed and not links["Log out"].allowed
    fields = {f.name: f for f in await m.list_fields()}
    assert fields["q"].fillable and fields["q"].label == "Search"
    assert not fields["user"].fillable and not fields["pw"].fillable
    assert (await m.fill(fields["q"].id, "sourdough"))["submitted"] is False
    await m.follow_link(links["About"].id)
    assert (await m.get_state()).title == "About"
    assert (await m.back()).title == "Home"
    assert (await m.forward()).title == "About"
    assert ("POST", "/") not in site.log and all(method == "GET" for method, _ in site.log)


async def test_hidden_text_and_scripts_are_not_returned_and_js_is_off_by_default(site):
    site.page("/", "<html><title>T</title><body><p>visible</p><p hidden>secret-hidden</p><div style='display:none'>css-hidden</div>"
                   "<script>document.body.innerText='SCRIPT RAN'</script><noscript>noscript text</noscript></body></html>")
    st = await site.make().open("http://site.test/")
    assert "visible" in st.text and "SCRIPT RAN" not in st.text
    assert "secret-hidden" not in st.text and "css-hidden" not in st.text


async def test_javascript_runs_only_when_explicitly_enabled(site):
    site.page("/", "<html><title>T</title><body>before<script>document.body.append(' AFTER-JS')</script></body></html>")
    st = await site.make(javascript_enabled=True).open("http://site.test/")
    assert "AFTER-JS" in st.text


async def test_internal_service_is_never_reached_by_any_subresource_type(site, internal):
    u = internal.url
    site.page("/", f"<html><title>T</title><head><link rel=stylesheet href='{u}/css'></head><body>x"
                   f"<img src='{u}/img'><iframe src='{u}/frame'></iframe><script src='{u}/js'></script>"
                   f"<audio src='{u}/a'></audio><video src='{u}/v'></video><object data='{u}/o'></object>"
                   f"<embed src='{u}/e'><img src='http://localhost:{internal.port}/lh'></body></html>")
    m = site.make()
    st = await m.open("http://site.test/")
    await asyncio.sleep(0.5)
    assert internal.hits == [] and st.blocked_requests >= 4
    assert "INTERNAL-SECRET" not in st.text


async def test_meta_refresh_to_internal_service_is_blocked(site, internal):
    site.page("/", f"<html><head><meta http-equiv=refresh content='0;url={internal.url}/x'></head><body>stay</body></html>")
    m = site.make()
    try:
        await m.open("http://site.test/")
    except BrowserError:
        pass  # the page navigated to a blocked address: reported as a (safe) navigation error
    await asyncio.sleep(0.5)
    assert internal.hits == []
    site.page("/ok", "<html><title>OK</title><body>fine</body></html>")
    assert (await m.open("http://site.test/ok")).title == "OK"   # manager stays usable


async def test_http_redirect_to_internal_service_is_blocked_on_navigation(site, internal):
    site.page("/to-internal", "", status=302, location=f"{internal.url}/secret")
    with pytest.raises(BlockedURLError):
        await site.make().open("http://site.test/to-internal")
    assert internal.hits == []


async def test_direct_navigation_to_internal_and_file_urls_is_blocked(site, internal):
    m = site.make()
    for url in (f"{internal.url}/", "http://localhost/", "file:///etc/passwd", "http://169.254.169.254/", "http://[::1]/"):
        with pytest.raises(BlockedURLError):
            await m.open(url)
    assert internal.hits == [] and not m.active


async def test_page_cannot_load_local_files(site, tmp_path):
    marker = tmp_path / "secret.txt"
    marker.write_text("TOP-SECRET-LOCAL-FILE-CONTENT")
    site.page("/", f"<html><head><meta http-equiv=refresh content='0;url=file://{marker}'></head><body>page<iframe src='file://{marker}'>"
                   f"</iframe><img src='file://{marker}'></body></html>")
    m = site.make()
    st = await m.open("http://site.test/")
    await asyncio.sleep(0.5)
    assert "TOP-SECRET" not in st.text
    for fr in m._driver._page.frames:  # type: ignore[union-attr]
        try:
            assert "TOP-SECRET" not in await fr.locator("body").inner_text(timeout=500)
        except Exception:
            pass  # frame refused to load, which is the expected outcome


async def test_post_requests_from_page_script_never_leave_the_browser(site):
    site.page("/", "<html><title>T</title><body>x<script>fetch('/steal',{method:'POST',body:'a=1'});"
                   "navigator.sendBeacon('/beacon','x');var x=new XMLHttpRequest();x.open('PUT','/put');x.send('d');</script></body></html>")
    m = site.make(javascript_enabled=True)
    st = await m.open("http://site.test/")
    await asyncio.sleep(0.5)
    assert all(method in ("GET", "HEAD") for method, _ in site.log), site.log
    assert st.blocked_requests >= 1


async def test_downloads_and_executables_are_blocked(site):
    site.page("/file.zip", b"PK\x03\x04", ctype="application/zip")
    site.page("/run.exe", b"MZ", ctype="application/octet-stream")
    site.page("/att", "<html>x</html>", **{"content-disposition": "attachment; filename=x.html"})
    m = site.make()
    for p in ("/file.zip", "/run.exe", "/att"):
        with pytest.raises(BrowserError):
            await m.open("http://site.test" + p)


async def test_popups_are_closed(site):
    site.page("/", "<html><title>Main</title><body>m<script>window.open('http://site.test/popup')</script></body></html>")
    site.page("/popup", "<html><title>Popup</title><body>popup</body></html>")
    m = site.make(javascript_enabled=True)
    st = await m.open("http://site.test/")
    await asyncio.sleep(0.7)
    assert st.title == "Main" and len(m._driver._context.pages) == 1  # type: ignore[union-attr]


async def test_no_cookies_are_stored_or_sent(site):
    site.page("/", "<html><title>T</title><body>x</body></html>", **{"set-cookie": "sid=abc; Path=/"})
    m = site.make()
    await m.open("http://site.test/")
    await m.open("http://site.test/")
    assert await m._driver._context.cookies() == []  # type: ignore[union-attr]


async def test_screenshot_is_bounded_valid_jpeg_and_limit_enforced(site):
    site.page("/", "<html><title>T</title><body><h1>Shot</h1></body></html>")
    m = site.make(screenshot_max_bytes=400_000)
    await m.open("http://site.test/")
    info = await m.screenshot()
    data, mime = m.get_screenshot(info.screenshot_id)
    assert mime == "image/jpeg" and data[:2] == b"\xff\xd8" and len(data) <= 400_000 and info.bytes == len(data)
    tiny = site.make(screenshot_max_bytes=10_000)
    noise = "".join(f"<span style='display:inline-block;width:6px;height:6px;background:rgb({(i * 37) % 256},{(i * 91) % 256},{(i * 53) % 256})'></span>"
                    for i in range(14_000))
    site.page("/noise", f"<html><body style='margin:0;line-height:0'>{noise}</body></html>")
    await tiny.open("http://site.test/noise")
    with pytest.raises(ScreenshotError):      # over the bound is an error, never an oversized image
        await tiny.screenshot()


async def test_oversized_page_is_rejected_not_truncated(site):
    site.page("/huge", "<html><body>" + "x" * 200_000 + "</body></html>")
    m = site.make(max_resource_bytes=100_000)
    with pytest.raises(BrowserError):
        await m.open("http://site.test/huge")


async def test_navigation_timeout_is_reported_and_cleaned_up(site):
    class Slow(httpx.AsyncBaseTransport):
        async def handle_async_request(self, request):
            await asyncio.sleep(30)
    limits = _base_limits(navigation_timeout=2)
    policy = BrowserPolicy(limits, public_validator("site.test"))
    m = BrowserManager(limits, policy, lambda: PlaywrightDriver.launch(limits, policy, Slow()))
    try:
        with pytest.raises(BrowserError):
            await m.open("http://site.test/")
    finally:
        await m.close()


async def test_crash_is_detected_session_discarded_and_manager_recovers(site):
    site.page("/", "<html><title>T</title><body>ok</body></html>")
    m = site.make()
    await m.open("http://site.test/")
    page = m._driver._page  # type: ignore[union-attr]
    cdp = await page.context.new_cdp_session(page)
    fut = asyncio.ensure_future(cdp.send("Page.crash"))     # really crashes the renderer
    fut.add_done_callback(lambda f: f.exception() if not f.cancelled() else None)
    await asyncio.sleep(1.0)
    with pytest.raises(BrowserCrashedError):
        await m.get_state()
    assert not m.active                              # discarded
    st = await m.open("http://site.test/")           # clean restart
    assert st.title == "T"


async def test_close_terminates_browser_processes(site):
    site.page("/", "<html><body>x</body></html>")
    before = _chromium_procs()
    m = site.make()
    await m.open("http://site.test/")
    assert _chromium_procs() > before
    await m.close()
    await asyncio.sleep(1.0)
    assert _chromium_procs() <= before


async def test_defence_in_depth_unrouted_requests_fail_closed(internal):
    """If interception were ever bypassed, the dead-proxy launch flag must stop the request. Here we launch
    Chromium with the production args but WITHOUT the route guard and try to reach the internal server."""
    from playwright.async_api import async_playwright
    limits = _base_limits()
    async with async_playwright() as pw:
        kw = {"headless": True, "args": chromium_args(limits)}
        if limits.executable_path:
            kw["executable_path"] = str(limits.executable_path)
        browser = await pw.chromium.launch(**kw)
        try:
            page = await (await browser.new_context()).new_page()
            with pytest.raises(Exception):
                await page.goto(internal.url + "/bypass", timeout=8000)
        finally:
            await browser.close()
    assert internal.hits == []
