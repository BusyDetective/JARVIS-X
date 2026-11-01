from __future__ import annotations

import logging
import re
import uuid
from collections.abc import Callable
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException, Query, Request, Response
from fastapi.responses import JSONResponse

from app.capabilities.manager import CapabilityManager
from app.capabilities.registry import CapabilityError
from app.config.settings import settings
from app.security.untrusted import redact_text
from app.sessions.manager import ConversationManager, SessionInactiveError, SessionManager
from app.sessions.models import ConversationMessage, MessageRole
from app.sessions.repository import ConversationNotFoundError, SessionNotFoundError
from app.tasks.manager import TaskManager
from app.tasks.repository import TaskNotFoundError
from app.ui.approvals import (
    ApprovalAlreadyDecidedError, ApprovalNotFoundError, WebApprovalHandler, summarize_arguments,
)
from app.ui.runs import Run, RunConflictError, RunManager
from app.ui.schemas import (
    ApprovalDecisionIn, CapabilityToggleIn, CreateSessionIn, LoginIn, RenameSessionIn, SendMessageIn, SpeakIn,
)
from app.ui.security import COOKIE_NAME, AuthManager, LocalGuardMiddleware, build_allowed_hosts
from app.voice.errors import AudioTooLargeError, SpeechRecognitionError, SpeechSynthesisError, VoiceDisabledError, VoiceError, VoiceUnavailableError
from app.voice.service import VoiceService

logger = logging.getLogger(__name__)
STATIC_DIR = Path(__file__).parent / "static"
SELF_IMPROVEMENT_ID = "self_improvement"
_SID = re.compile(r"^[A-Za-z0-9_-]{8,64}$")


@dataclass
class UIServices:
    session_manager: SessionManager
    conversation_manager: ConversationManager
    task_manager: TaskManager
    capabilities: CapabilityManager
    approvals: WebApprovalHandler
    runs: RunManager
    voice: VoiceService
    auth: AuthManager
    browser: Any | None = None  # BrowserManager (optional)
    browser_unavailable_reason: str | None = None
    improvement_status: Callable[[], dict[str, Any]] | None = None  # READ-ONLY view
    host: str = "127.0.0.1"
    port: int = 8765
    extra_allowed_hosts: str = ""
    max_message_chars: int = 8_000
    cookie_secure: bool = False
    shutdown_hooks: list[Callable[[], Any]] = field(default_factory=list)


def _bound(text: str | None, n: int) -> str:
    text = redact_text(text or "")[0]
    return text if len(text) <= n else text[:n] + "…"


def message_view(m: ConversationMessage) -> dict[str, Any]:
    out: dict[str, Any] = {"sequence": m.sequence, "role": m.role.value, "created_at": m.created_at.isoformat()}
    if m.role == MessageRole.USER:
        out["content"] = m.content[:20_000]
    elif m.role == MessageRole.TOOL:
        out["content"] = _bound(m.content, 2_000)
        out["tool_name"] = str(m.metadata.get("tool_name", ""))[:80]
        out["tool_call_id"] = str(m.metadata.get("tool_call_id", ""))[:80]
    else:
        out["content"] = _bound(m.content, 20_000)
        calls = m.metadata.get("tool_calls") or []
        if calls:
            out["tool_calls"] = [{"id": str(c.get("id", ""))[:80], "name": str(c.get("name", ""))[:80],
                                  "arguments": summarize_arguments(c.get("arguments") or {})} for c in calls[:20]]
        for k in ("provider", "model"):
            if m.metadata.get(k):
                out[k] = str(m.metadata[k])[:80]
    return out


def run_view(r: Run) -> dict[str, Any]:
    return {"id": r.id, "conversation_id": r.conversation_id, "state": r.state, "status": r.status,
            "created_at": r.created_at, "finished_at": r.finished_at, "final_response": _bound(r.final_response, 20_000) if r.final_response else None,
            "error": r.error, "provider": r.provider, "model": r.model, "iterations": r.iterations,
            "tool_calls": r.tool_calls}


def create_app(svc: UIServices) -> FastAPI:
    @asynccontextmanager
    async def lifespan(_: FastAPI):
        yield
        await svc.runs.shutdown()
        if svc.browser is not None:
            await svc.browser.close()
        for hook in svc.shutdown_hooks:
            try:
                r = hook()
                if hasattr(r, "__await__"):
                    await r
            except Exception:  # noqa: BLE001
                logger.warning("shutdown hook failed")

    app = FastAPI(title="JARVIS-X", docs_url=None, redoc_url=None, openapi_url=None, lifespan=lifespan)
    app.add_middleware(LocalGuardMiddleware, auth=svc.auth,
                       allowed_hosts=build_allowed_hosts(svc.host, svc.port, svc.extra_allowed_hosts))

    @app.exception_handler(Exception)
    async def _unhandled(_: Request, exc: Exception) -> JSONResponse:
        logger.error("unhandled error in request: %s", type(exc).__name__)
        return JSONResponse({"error": "internal error"}, status_code=500)

    def err(status: int, msg: str) -> HTTPException:
        return HTTPException(status_code=status, detail=msg)

    @app.exception_handler(HTTPException)
    async def _http(_: Request, exc: HTTPException) -> JSONResponse:
        return JSONResponse({"error": exc.detail}, status_code=exc.status_code)

    from fastapi.exceptions import RequestValidationError

    @app.exception_handler(RequestValidationError)
    async def _validation(_: Request, exc: RequestValidationError) -> JSONResponse:
        problems = [f"{'.'.join(str(p) for p in e['loc'][1:])}: {e['msg']}" for e in exc.errors()[:5]]
        return JSONResponse({"error": "invalid request", "details": problems}, status_code=422)

    def conv_or_404(cid: uuid.UUID):
        try:
            return svc.conversation_manager.get_conversation(cid)
        except (ConversationNotFoundError, SessionNotFoundError):
            raise err(404, "conversation not found") from None

    def session_or_404(sid: uuid.UUID):
        try:
            return svc.session_manager.get_session(sid)
        except SessionNotFoundError:
            raise err(404, "session not found") from None

    def sess_view(s) -> dict[str, Any]:
        return {"id": str(s.id), "title": s.title, "active": s.active,
                "created_at": s.created_at.isoformat(), "updated_at": s.updated_at.isoformat()}

    def conv_view(c) -> dict[str, Any]:
        return {"id": str(c.id), "session_id": str(c.session_id), "created_at": c.created_at.isoformat(),
                "message_count": svc.conversation_manager.count_messages(c.id)}

    # ---- static -------------------------------------------------------------
    assets = {name: (STATIC_DIR / name).read_bytes() for name in ("index.html", "app.js", "style.css")}

    @app.get("/", include_in_schema=False)
    async def index() -> Response:
        return Response(assets["index.html"], media_type="text/html; charset=utf-8")

    @app.get("/static/app.js", include_in_schema=False)
    async def js() -> Response:
        return Response(assets["app.js"], media_type="text/javascript; charset=utf-8")

    @app.get("/static/style.css", include_in_schema=False)
    async def css() -> Response:
        return Response(assets["style.css"], media_type="text/css; charset=utf-8")

    # ---- auth ---------------------------------------------------------------
    @app.get("/api/health")
    async def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.post("/api/auth/login")
    async def login(body: LoginIn, response: Response) -> dict[str, bool]:
        if svc.auth.locked_out():
            raise err(429, "too many failed attempts; wait a minute")
        sid = svc.auth.login(body.token)
        if sid is None:
            raise err(401, "invalid token")
        response.set_cookie(COOKIE_NAME, sid, httponly=True, samesite="strict", secure=svc.cookie_secure,
                            max_age=settings.ui_session_ttl_seconds, path="/")
        return {"authenticated": True}

    @app.post("/api/auth/logout")
    async def logout(request: Request, response: Response) -> dict[str, bool]:
        svc.auth.logout(request.cookies.get(COOKIE_NAME))
        response.delete_cookie(COOKIE_NAME, path="/")
        return {"authenticated": False}

    @app.get("/api/auth/status")
    async def auth_status() -> dict[str, bool]:
        return {"authenticated": True}  # reaching here means the guard accepted the cookie

    # ---- sessions / conversations ------------------------------------------------
    @app.get("/api/sessions")
    async def list_sessions(limit: int = Query(100, ge=1, le=200)) -> dict[str, Any]:
        return {"sessions": [sess_view(s) for s in svc.session_manager.list_sessions(limit=limit)]}

    @app.post("/api/sessions", status_code=201)
    async def create_session(body: CreateSessionIn) -> dict[str, Any]:
        s = svc.session_manager.create_session(title=body.title)
        c = svc.session_manager.create_conversation(s.id)
        return {"session": sess_view(s), "conversation": conv_view(c)}

    @app.get("/api/sessions/{session_id}")
    async def get_session(session_id: uuid.UUID) -> dict[str, Any]:
        s = session_or_404(session_id)
        return {"session": sess_view(s), "conversations": [conv_view(c) for c in svc.session_manager.list_conversations(s.id)]}

    @app.patch("/api/sessions/{session_id}")
    async def rename_session(session_id: uuid.UUID, body: RenameSessionIn) -> dict[str, Any]:
        session_or_404(session_id)
        return {"session": sess_view(svc.session_manager.rename_session(session_id, body.title))}

    @app.post("/api/sessions/{session_id}/deactivate")
    async def deactivate_session(session_id: uuid.UUID) -> dict[str, Any]:
        session_or_404(session_id)
        return {"session": sess_view(svc.session_manager.deactivate_session(session_id))}

    @app.post("/api/sessions/{session_id}/conversations", status_code=201)
    async def new_conversation(session_id: uuid.UUID) -> dict[str, Any]:
        session_or_404(session_id)
        try:
            return {"conversation": conv_view(svc.session_manager.create_conversation(session_id))}
        except SessionInactiveError:
            raise err(409, "session is closed") from None

    @app.get("/api/conversations/{conversation_id}/messages")
    async def get_messages(conversation_id: uuid.UUID, after: int = Query(0, ge=0),
                           limit: int = Query(200, ge=1, le=500)) -> dict[str, Any]:
        conv_or_404(conversation_id)
        msgs = [m for m in svc.conversation_manager.get_history(conversation_id) if m.sequence > after][:limit]
        active = svc.runs.active_for(str(conversation_id))
        return {"messages": [message_view(m) for m in msgs],
                "active_run": run_view(svc.runs.get(active.id)) if active else None}

    @app.post("/api/conversations/{conversation_id}/messages", status_code=202)
    async def send_message(conversation_id: uuid.UUID, body: SendMessageIn) -> dict[str, Any]:
        conv_or_404(conversation_id)
        if len(body.text) > svc.max_message_chars:
            raise err(422, f"message exceeds {svc.max_message_chars} characters")
        if body.source == "voice":
            if not svc.voice.input_enabled:
                raise err(403, "voice input is disabled")
            if not body.confirmed:
                raise err(422, "voice transcripts must be confirmed by the user before sending")
        try:
            svc.conversation_manager.ensure_writable(conversation_id)
        except SessionInactiveError:
            raise err(409, "session is closed") from None
        try:
            run = svc.runs.start(conversation_id, body.text)  # the normal user-message path, via the Orchestrator
        except RunConflictError as exc:
            raise err(409, str(exc)) from None
        return {"run_id": run.id, "conversation_id": str(conversation_id)}

    @app.get("/api/runs/{run_id}")
    async def get_run(run_id: str) -> dict[str, Any]:
        if not _SID.match(run_id):
            raise err(404, "run not found")
        run = svc.runs.get(run_id)
        if run is None:
            raise err(404, "run not found")
        return {"run": run_view(run), "pending_approvals": [p.public() for p in svc.approvals.pending(run_id)]}

    # ---- approvals (authoritative path = the Orchestrator's ApprovalHandler) -----------
    @app.get("/api/approvals")
    async def approvals() -> dict[str, Any]:
        return {"pending": [p.public() for p in svc.approvals.pending()],
                "recent": [p.public() for p in reversed(svc.approvals.history())][:20]}

    @app.post("/api/approvals/{approval_id}/decision")
    async def decide(approval_id: str, body: ApprovalDecisionIn) -> dict[str, Any]:
        if not _SID.match(approval_id):
            raise err(404, "approval not found")
        try:
            item = svc.approvals.decide(approval_id, body.decision == "approve", body.acknowledged)
        except ApprovalNotFoundError:
            raise err(404, "approval not found") from None
        except ApprovalAlreadyDecidedError:
            raise err(409, "approval was already decided or has expired") from None
        except PermissionError as exc:
            raise err(400, str(exc)) from None
        logger.info("approval decided via dashboard id=%s decision=%s", item.id, item.decision)
        return {"id": item.id, "decision": item.decision}

    # ---- tasks ---------------------------------------------------------------
    def task_view(t) -> dict[str, Any]:
        return {"id": str(t.id), "user_request": _bound(t.user_request, 300), "status": t.status.value,
                "created_at": t.created_at.isoformat(),
                "started_at": t.started_at.isoformat() if t.started_at else None,
                "completed_at": t.completed_at.isoformat() if t.completed_at else None,
                "result": _bound(t.result, 500) if t.result else None, "error": _bound(t.error, 300) if t.error else None}

    @app.get("/api/tasks")
    async def tasks(limit: int = Query(30, ge=1, le=100)) -> dict[str, Any]:
        all_tasks = svc.task_manager.list_tasks()
        all_tasks = sorted(all_tasks, key=lambda t: t.created_at, reverse=True)[:limit]
        return {"tasks": [task_view(t) for t in all_tasks]}

    @app.get("/api/tasks/{task_id}")
    async def task_detail(task_id: uuid.UUID) -> dict[str, Any]:
        try:
            t = svc.task_manager.get_task(task_id)
        except TaskNotFoundError:
            raise err(404, "task not found") from None
        runs = [{"iteration": r.iteration, "status": r.status.value, "provider": r.provider, "model": r.model,
                 "error": _bound(r.error, 200) if r.error else None} for r in svc.task_manager.get_task_runs(task_id)]
        tools = [{"name": r.name, "success": r.success, "error": _bound(r.error, 200) if r.error else None,
                  "arguments": summarize_arguments(r.arguments or {}),
                  "result": _bound(str(r.result), 500) if r.result is not None else None}
                 for r in svc.task_manager.get_tool_results(task_id)[:100]]
        return {"task": task_view(t), "runs": runs, "tool_results": tools}

    # ---- capabilities / settings ----------------------------------------------------
    @app.get("/api/capabilities")
    async def capabilities() -> dict[str, Any]:
        snap = svc.capabilities.snapshot()
        return {"enabled": svc.capabilities.enabled, "capabilities": [{
            "id": c.id, "name": c.name, "description": c.description, "enabled": c.enabled,
            "category": c.category.value, "source": c.source.value, "version": c.version,
            "effective_max_permission": c.effective_max_permission.value, "depends_on": c.depends_on,
            "dependencies_satisfied": c.dependency_status.satisfied,
            "tools": [{"name": t.name, "permission_level": t.permission_level.value,
                       "requires_approval": t.requires_approval, "enabled": t.enabled} for t in c.tools],
        } for c in snap.capabilities]}

    @app.post("/api/capabilities/{capability_id}/enabled")
    async def toggle_capability(capability_id: str, body: CapabilityToggleIn) -> dict[str, Any]:
        if not re.fullmatch(r"[a-z0-9_.-]{1,64}", capability_id):
            raise err(404, "capability not found")
        if svc.capabilities.get_capability(capability_id) is None:
            raise err(404, "capability not found")
        if body.enabled and capability_id == SELF_IMPROVEMENT_ID:
            raise err(403, "self-improvement cannot be enabled from the dashboard")
        try:
            cap = svc.capabilities.enable(capability_id) if body.enabled else svc.capabilities.disable(capability_id)
        except CapabilityError as exc:
            raise err(409, str(exc)[:200]) from None
        if not cap.enabled and capability_id == "browser" and svc.browser is not None:
            await svc.browser.close()  # disabling the capability also discards any live browser session
        return {"id": cap.id, "enabled": cap.enabled}

    @app.get("/api/self-improvement")
    async def self_improvement() -> dict[str, Any]:
        installed = svc.capabilities.get_capability(SELF_IMPROVEMENT_ID) is not None
        enabled = installed and svc.capabilities.is_enabled(SELF_IMPROVEMENT_ID)
        out: dict[str, Any] = {
            "config_enabled": bool(settings.self_improvement_enabled), "capability_installed": installed,
            "capability_enabled": enabled,
            "message": ("Self-improvement is DISABLED (SELF_IMPROVEMENT_ENABLED=false). No candidate can be created, "
                        "validated or promoted." if not settings.self_improvement_enabled else
                        "Self-improvement is configured. Promotion and rollback decisions arrive as approval requests; "
                        "this dashboard cannot modify releases, manifests or isolation policy."),
            "read_only": True}
        if svc.improvement_status is not None and installed:
            try:
                st = svc.improvement_status()
                out["status"] = {"current_version": st.get("current_version"),
                                 "rollback_available": st.get("rollback_available"),
                                 "improvements": st.get("improvements", [])[:20]}
            except Exception:  # noqa: BLE001
                out["status"] = None
        return out

    @app.get("/api/settings")
    async def public_settings() -> dict[str, Any]:
        return {
            "ui": {"host": svc.host, "port": svc.port, "auth": "local token", "max_message_chars": svc.max_message_chars,
                   "streaming": False, "approval_timeout_seconds": settings.ui_approval_timeout_seconds},
            "providers": {"order": settings.provider_order_list,
                          "configured": {"gemini": bool(settings.gemini_api_key),
                                         "openrouter": bool(settings.openrouter_api_key), "ollama": True}},
            "limits": {"max_iterations": settings.max_iterations, "max_tool_calls": settings.max_tool_calls},
            "browser": {"config_enabled": settings.browser_enabled, "available": svc.browser is not None,
                        "reason": svc.browser_unavailable_reason, "javascript_enabled": settings.browser_javascript_enabled},
            "voice": svc.voice.status(),
        }

    # ---- browser ----------------------------------------------------------------
    @app.get("/api/browser/status")
    async def browser_status() -> dict[str, Any]:
        if svc.browser is None:
            return {"available": False, "reason": svc.browser_unavailable_reason or "browser is disabled"}
        return {"available": True, **svc.browser.status()}

    @app.post("/api/browser/close")
    async def browser_close() -> dict[str, bool]:
        if svc.browser is not None:
            await svc.browser.close()
        return {"closed": True}

    @app.get("/api/browser/screenshots/{screenshot_id}")
    async def screenshot(screenshot_id: str) -> Response:
        if svc.browser is None or not _SID.match(screenshot_id):
            raise err(404, "screenshot not found")
        item = svc.browser.get_screenshot(screenshot_id)
        if item is None:
            raise err(404, "screenshot not found")
        return Response(item[0], media_type=item[1], headers={"Content-Disposition": "inline"})

    # ---- voice (a transcript is only ever a draft; there is no voice path to approvals) ----
    @app.get("/api/voice/status")
    async def voice_status() -> dict[str, Any]:
        return svc.voice.status()

    def voice_error(exc: VoiceError) -> HTTPException:
        if isinstance(exc, VoiceDisabledError):
            return err(403, str(exc))
        if isinstance(exc, AudioTooLargeError):
            return err(413, str(exc))
        if isinstance(exc, VoiceUnavailableError):
            return err(501, str(exc))
        if isinstance(exc, (SpeechRecognitionError, SpeechSynthesisError)):
            return err(502, str(exc))
        return err(400, str(exc))

    @app.post("/api/voice/transcribe")
    async def transcribe(request: Request) -> dict[str, Any]:
        if not svc.voice.input_enabled:
            raise err(403, "voice input is disabled")
        buf = bytearray()
        async for chunk in request.stream():
            buf.extend(chunk)
            if len(buf) > svc.voice.max_audio_bytes:
                raise err(413, "audio is too large")
        mime = (request.headers.get("content-type") or "application/octet-stream").split(";")[0]
        try:
            t = await svc.voice.transcribe(bytes(buf), mime)
        except VoiceError as exc:
            raise voice_error(exc) from None
        return {"transcript": t.text, "provider": t.provider, "confirmed": False,
                "note": "This is a draft. Review it and confirm before sending."}

    @app.post("/api/voice/speech-plan")
    async def speech_plan(body: SpeakIn) -> dict[str, Any]:
        try:
            plan = svc.voice.speech_plan(body.text)
        except VoiceError as exc:
            raise voice_error(exc) from None
        return {"chunks": plan.chunks, "truncated": plan.truncated, "client_side": svc.voice.synthesizer.client_side}

    @app.post("/api/voice/synthesize")
    async def synthesize(body: SpeakIn) -> Response:
        try:
            clip = await svc.voice.synthesize(body.text)
        except VoiceError as exc:
            raise voice_error(exc) from None
        return Response(clip.data, media_type=clip.mime)

    return app
