"""REAL-BROWSER test of the dashboard frontend (actual Chromium via Playwright against a live uvicorn server running the
real FastAPI app, real Orchestrator and approval path; only the LLM is scripted). Skipped when no browser is available
(see tests/test_browser_real.py for how to provide one)."""
from __future__ import annotations

import asyncio
import socket
import threading
import time

import pytest

pytest.importorskip("playwright")
pytest.importorskip("uvicorn")

from tests import test_browser_real as real  # noqa: E402
from tests.phase9_helpers import TOKEN, ConfirmTool, ScriptedRouter, _response, call, make_services  # noqa: E402

INJECT = "<img src=x onerror=\"window.__xss=1\"><script>window.__xss=2</script>**bold**"


@pytest.fixture(scope="module", autouse=True)
def _require_browser():
    reason = real._browser_unavailable_reason()
    if reason:
        pytest.skip(reason)


@pytest.fixture
def live(tmp_path):
    import uvicorn
    from app.ui.app import create_app
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    ConfirmTool.executed = 0
    svc = make_services(tmp_path, ScriptedRouter([
        _response(tool_calls=[call("confirm_tool")]), _response(text="Tool finished. " + INJECT)]), extra_tools=[ConfirmTool()])
    svc.port = port
    server = uvicorn.Server(uvicorn.Config(create_app(svc), host="127.0.0.1", port=port, log_level="warning"))
    t = threading.Thread(target=server.run, daemon=True)
    t.start()
    for _ in range(100):
        if server.started:
            break
        time.sleep(0.05)
    yield f"http://127.0.0.1:{port}", svc
    server.should_exit = True
    t.join(timeout=10)


async def wait_text(page, selector: str, needle: str, timeout: float = 15.0, present: bool = True) -> None:
    """Poll a locator (Playwright's wait_for_function would need 'unsafe-eval', which the dashboard's CSP forbids)."""
    end = time.time() + timeout
    while time.time() < end:
        text = await page.inner_text(selector)
        if (needle in text) is present:
            return
        await asyncio.sleep(0.1)
    raise AssertionError(f"{selector!r} never {'contained' if present else 'lost'} {needle!r}")


async def test_dashboard_login_chat_approval_and_safe_rendering(live):
    from playwright.async_api import async_playwright
    base, svc = live
    limits = real._base_limits()
    async with async_playwright() as pw:
        kw = {"headless": True, "args": ["--no-sandbox"] if limits.no_sandbox else []}
        if limits.executable_path:
            kw["executable_path"] = str(limits.executable_path)
        browser = await pw.chromium.launch(**kw)
        try:
            page = await (await browser.new_context()).new_page()
            problems: list[str] = []
            page.on("console", lambda m: problems.append(m.text) if m.type in ("error", "warning") else None)
            page.on("pageerror", lambda e: problems.append(str(e)))
            await page.goto(base)
            await page.wait_for_selector("#login:not(.hidden)")
            await page.fill("#login-token", "wrong-token")
            await page.click("#login-btn")
            await wait_text(page, "#login-error", "invalid token")
            await page.fill("#login-token", TOKEN)
            await page.click("#login-btn")
            await page.wait_for_selector("#app:not(.hidden)")

            # self-improvement disabled is visibly indicated
            await wait_text(page, "#badges", "Self-improvement: DISABLED")

            await page.click("#new-session")
            await page.wait_for_selector("#session-list li.active")
            await page.fill("#input", "please run the confirm tool")
            await page.click("#send")
            await page.wait_for_selector(".msg.user")

            # approval card appears with real tool name; approve through the UI
            await page.wait_for_selector("#tab-approvals .card.warn", timeout=15000)
            card = await page.inner_text("#tab-approvals .card.warn")
            assert "confirm_tool" in card and "[confirm]" in card
            assert ConfirmTool.executed == 0
            await page.click("#tab-approvals .card.warn >> text=Approve")
            await page.wait_for_selector(".msg.assistant", timeout=15000)
            await wait_text(page, "#run-status", "Done")
            assert ConfirmTool.executed == 1

            # tool activity shown; model output rendered as TEXT (no HTML/script injection)
            assert await page.locator("details.tool").count() >= 2
            assistant = await page.inner_text(".msg.assistant:last-of-type")
            assert "<img" in assistant and "**bold**" in assistant
            assert await page.evaluate("window.__xss") is None
            assert await page.locator(".messages img").count() == 0

            # tasks + settings panes populate
            await page.click("button[data-tab=tasks]")
            await page.wait_for_selector("#tab-tasks .card")
            await page.click("button[data-tab=settings]")
            await page.wait_for_selector("#tab-settings .card")
            settings_text = await page.inner_text("#tab-settings")
            assert "DISABLED" in settings_text and "keys are never sent" in settings_text
            assert "Voice never approves actions" in settings_text
            # voice is off => no mic button, and text input still works
            assert await page.locator("#mic").is_hidden()

            # lock returns to the login screen and API access stops
            await page.click("#logout-btn")
            await page.wait_for_selector("#login:not(.hidden)")
            assert (await page.request.get(base + "/api/sessions")).status == 401

            csp = [p for p in problems if "Content Security Policy" in p or "Refused to" in p]
            assert not csp, csp
        finally:
            await browser.close()


# ------------------------------ voice UI (fake microphone device) ------------------------------

def _silent_wav(seconds: float = 0.3) -> bytes:
    import io
    import wave
    buf = io.BytesIO()
    with wave.open(buf, "wb") as w:
        w.setnchannels(1); w.setsampwidth(2); w.setframerate(16000)
        w.writeframes(b"\x00\x00" * int(16000 * seconds))
    return buf.getvalue()


@pytest.fixture
def live_voice(tmp_path):
    import uvicorn
    from app.ui.app import create_app
    from app.voice.models import AudioClip, Transcript
    from app.voice.recognition import SpeechRecognizer
    from app.voice.service import VoiceService
    from app.voice.synthesis import SpeechSynthesizer

    class Rec(SpeechRecognizer):
        name, location = "stub-local", "local"
        received: list[int] = []
        async def transcribe(self, audio, mime, language):
            Rec.received.append(len(audio))
            return Transcript(text="what tasks are open", provider=self.name)

    class Syn(SpeechSynthesizer):
        name, location = "stub-local", "local"
        async def synthesize(self, text):
            return AudioClip(data=_silent_wav(), mime="audio/wav")

    Rec.received = []
    voice = VoiceService(Rec(), Syn(), input_enabled=True, output_enabled=True, max_audio_bytes=5_000_000,
                         speech_max_chars=500, speech_chunk_chars=100)
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    svc = make_services(tmp_path, ScriptedRouter([_response(text="You have no open tasks. Everything is done.")]), voice=voice)
    svc.port = port
    server = uvicorn.Server(uvicorn.Config(create_app(svc), host="127.0.0.1", port=port, log_level="warning"))
    t = threading.Thread(target=server.run, daemon=True)
    t.start()
    for _ in range(100):
        if server.started:
            break
        time.sleep(0.05)
    yield f"http://127.0.0.1:{port}", svc, Rec
    server.should_exit = True
    t.join(timeout=10)


async def test_voice_ui_requires_confirmation_before_sending_and_speaks_replies(live_voice):
    from playwright.async_api import async_playwright
    base, svc, Rec = live_voice
    limits = real._base_limits()
    async with async_playwright() as pw:
        args = ["--use-fake-device-for-media-stream", "--use-fake-ui-for-media-stream", "--autoplay-policy=no-user-gesture-required"]
        kw = {"headless": True, "args": args + (["--no-sandbox"] if limits.no_sandbox else [])}
        if limits.executable_path:
            kw["executable_path"] = str(limits.executable_path)
        browser = await pw.chromium.launch(**kw)
        try:
            ctx = await browser.new_context(permissions=["microphone"])
            page = await ctx.new_page()
            requests: list[str] = []
            page.on("request", lambda r: requests.append(f"{r.method} {r.url.replace(base, '')}"))
            problems: list[str] = []
            page.on("pageerror", lambda e: problems.append(str(e)))
            await page.goto(base)
            await page.fill("#login-token", TOKEN)
            await page.click("#login-btn")
            await page.wait_for_selector("#app:not(.hidden)")
            await wait_text(page, "#badges", "Voice in: stub-local")
            assert await page.locator("#mic").is_visible() and await page.locator("#speak-wrap").is_visible()
            await page.click("#new-session")
            await page.wait_for_selector("#session-list li.active")

            # --- push-to-talk: record, stop, transcript appears as an editable DRAFT; nothing sent yet ---
            await page.click("#mic")
            await asyncio.sleep(1.0)
            await page.click("#mic")
            await page.wait_for_selector("#voice-confirm:not(.hidden)", timeout=15000)
            assert await page.input_value("#voice-text") == "what tasks are open"
            assert Rec.received and Rec.received[0] > 0
            assert await page.locator(".msg.user").count() == 0 and svc.runs.active_count() == 0
            assert svc.task_manager.list_tasks() == []

            # --- discard sends nothing ---
            await page.click("#voice-discard")
            await page.wait_for_selector("#voice-confirm.hidden", state="attached")
            assert await page.locator(".msg.user").count() == 0 and svc.task_manager.list_tasks() == []

            # --- record again, edit transcript, confirm: sent as a normal user message ---
            await page.click("#mic"); await asyncio.sleep(1.0); await page.click("#mic")
            await page.wait_for_selector("#voice-confirm:not(.hidden)", timeout=15000)
            await page.fill("#voice-text", "what tasks are still open")
            await page.check("#speak-toggle")
            await page.click("#voice-send")
            await page.wait_for_selector(".msg.user")
            assert "what tasks are still open" in await page.inner_text(".msg.user")
            await wait_text(page, "#run-status", "Done")
            assert "You have no open tasks" in await page.inner_text(".msg.assistant")      # text stays visible while spoken

            # --- spoken reply: plan + server-side synthesis requested; Stop control available ---
            end = time.time() + 10
            while time.time() < end and not any(r.startswith("POST /api/voice/synthesize") for r in requests):
                await asyncio.sleep(0.1)
            assert any(r.startswith("POST /api/voice/speech-plan") for r in requests)
            assert any(r.startswith("POST /api/voice/synthesize") for r in requests)
            assert not [p for p in problems if "voice" in p.lower()]
            tasks = svc.task_manager.list_tasks()
            assert len(tasks) == 1 and tasks[0].user_request == "what tasks are still open"
        finally:
            await browser.close()
