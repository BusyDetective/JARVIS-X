"""Dashboard API behaviour over the REAL SessionManager/ConversationManager/TaskManager/Orchestrator/approval path."""
from __future__ import annotations

import json
import uuid

import pytest

from app.config.settings import settings
from app.providers.schemas import ProviderError, ProviderErrorType
from app.voice.models import AudioClip, Transcript
from app.voice.recognition import SpeechRecognizer
from app.voice.service import VoiceService
from app.voice.synthesis import SpeechSynthesizer
from tests.phase9_helpers import (
    ConfirmTool, DangerTool, ScriptedRouter, _response, call, client_ctx, make_services, new_conversation,
    wait_pending, wait_run,
)


def svc_with(tmp_path, outcomes, **kw):
    return make_services(tmp_path, ScriptedRouter(outcomes), **kw)


# ------------------------------ sessions & conversations ------------------------------

def test_session_create_list_get_rename_close(tmp_path):
    with client_ctx(svc_with(tmp_path, [])) as c:
        sid, cid = new_conversation(c, "My session")
        assert [s["title"] for s in c.get("/api/sessions").json()["sessions"]] == ["My session"]
        got = c.get(f"/api/sessions/{sid}").json()
        assert got["session"]["active"] is True and [x["id"] for x in got["conversations"]] == [cid]
        assert c.patch(f"/api/sessions/{sid}", json={"title": "Renamed"}).json()["session"]["title"] == "Renamed"
        assert c.post(f"/api/sessions/{sid}/deactivate", json={}).json()["session"]["active"] is False
        assert c.post(f"/api/sessions/{sid}/conversations", json={}).status_code == 409      # closed session
        r = c.post(f"/api/conversations/{cid}/messages", json={"text": "hi"})
        assert r.status_code == 409


def test_new_conversation_in_active_session(tmp_path):
    with client_ctx(svc_with(tmp_path, [])) as c:
        sid, cid = new_conversation(c)
        c2 = c.post(f"/api/sessions/{sid}/conversations", json={}).json()["conversation"]["id"]
        assert c2 != cid and len(c.get(f"/api/sessions/{sid}").json()["conversations"]) == 2


@pytest.mark.parametrize("path", ["/api/sessions/{u}", "/api/conversations/{u}/messages"])
def test_unknown_ids_are_404_and_malformed_ids_422(tmp_path, path):
    with client_ctx(svc_with(tmp_path, [])) as c:
        assert c.get(path.format(u=uuid.uuid4())).status_code == 404
        assert c.get(path.format(u="not-a-uuid")).status_code == 422
        assert c.get(path.format(u="../../etc/passwd")).status_code in (404, 422)


def test_conversations_are_isolated(tmp_path):
    outcomes = [_response(text="answer A"), _response(text="answer B")]
    with client_ctx(svc_with(tmp_path, outcomes)) as c:
        _, a = new_conversation(c, "A")
        _, b = new_conversation(c, "B")
        wait_run(c, c.post(f"/api/conversations/{a}/messages", json={"text": "question A"}).json()["run_id"])
        wait_run(c, c.post(f"/api/conversations/{b}/messages", json={"text": "question B"}).json()["run_id"])
        ma = [m["content"] for m in c.get(f"/api/conversations/{a}/messages").json()["messages"]]
        mb = [m["content"] for m in c.get(f"/api/conversations/{b}/messages").json()["messages"]]
        assert ma == ["question A", "answer A"] and mb == ["question B", "answer B"]


def test_message_history_persists_in_the_existing_database_and_supports_after(tmp_path):
    svc = svc_with(tmp_path, [_response(text="one"), _response(text="two")])
    with client_ctx(svc) as c:
        _, cid = new_conversation(c)
        wait_run(c, c.post(f"/api/conversations/{cid}/messages", json={"text": "first"}).json()["run_id"])
        wait_run(c, c.post(f"/api/conversations/{cid}/messages", json={"text": "second"}).json()["run_id"])
        allm = c.get(f"/api/conversations/{cid}/messages").json()["messages"]
        assert [m["sequence"] for m in allm] == [1, 2, 3, 4]
        assert [m["content"] for m in c.get(f"/api/conversations/{cid}/messages?after=2").json()["messages"]] == ["second", "two"]
    # the SAME conversation store (no second conversation database) holds the history
    assert [m.content for m in svc.conversation_manager.get_history(uuid.UUID(cid))] == ["first", "one", "second", "two"]


# ------------------------------ validation ------------------------------

@pytest.mark.parametrize("body", [{}, {"text": ""}, {"text": "   \n "}, {"text": "x" * 50_001}, {"text": "hi", "extra": 1},
                                  {"text": "hi", "source": "telepathy"}, {"text": 5}, {"text": "hi", "confirmed": "maybe"}, {"text": "hi", "source": "voice", "confirmed": "true"}])
def test_message_validation_rejects_bad_bodies(tmp_path, body):
    with client_ctx(svc_with(tmp_path, [])) as c:
        _, cid = new_conversation(c)
        r = c.post(f"/api/conversations/{cid}/messages", json=body)
        assert r.status_code == 422 and "error" in r.json()


def test_message_length_limit_from_settings(tmp_path):
    svc = svc_with(tmp_path, [_response(text="ok")])
    svc.max_message_chars = 20
    with client_ctx(svc) as c:
        _, cid = new_conversation(c)
        assert c.post(f"/api/conversations/{cid}/messages", json={"text": "x" * 21}).status_code == 422
        assert c.post(f"/api/conversations/{cid}/messages", json={"text": "x" * 20}).status_code == 202


def test_session_title_validation(tmp_path):
    with client_ctx(svc_with(tmp_path, [])) as c:
        assert c.post("/api/sessions", json={"title": "x" * 121}).status_code == 422
        assert c.post("/api/sessions", json={"nope": 1}).status_code == 422
        sid, _ = new_conversation(c)
        assert c.patch(f"/api/sessions/{sid}", json={"title": "   "}).status_code == 422


def test_malformed_json_is_422_not_500(tmp_path):
    with client_ctx(svc_with(tmp_path, [])) as c:
        r = c.post("/api/sessions", content=b"{not json", headers={"Content-Type": "application/json"})
        assert r.status_code == 422


def test_only_one_active_run_per_conversation(tmp_path):
    svc = svc_with(tmp_path, [_response(tool_calls=[call("confirm_tool")]), _response(text="done")], extra_tools=[ConfirmTool()])
    with client_ctx(svc) as c:
        _, cid = new_conversation(c)
        run = c.post(f"/api/conversations/{cid}/messages", json={"text": "go"}).json()["run_id"]
        wait_pending(c)
        assert c.post(f"/api/conversations/{cid}/messages", json={"text": "again"}).status_code == 409
        c.post(f"/api/approvals/{wait_pending(c)['id']}/decision", json={"decision": "deny"})
        wait_run(c, run)


# ------------------------------ runs & errors ------------------------------

def test_run_returns_final_response_and_task_is_tracked(tmp_path):
    svc = svc_with(tmp_path, [_response(text="Hello!", provider="gemini", model="m1")])
    with client_ctx(svc) as c:
        _, cid = new_conversation(c)
        run = wait_run(c, c.post(f"/api/conversations/{cid}/messages", json={"text": "hi"}).json()["run_id"])
        assert run["state"] == "completed" and run["final_response"] == "Hello!" and run["provider"] == "gemini"
        tasks = c.get("/api/tasks").json()["tasks"]
        assert len(tasks) == 1 and tasks[0]["status"] == "completed" and tasks[0]["user_request"] == "hi"
        detail = c.get(f"/api/tasks/{tasks[0]['id']}").json()
        assert detail["task"]["id"] == tasks[0]["id"] and detail["runs"][0]["status"] == "completed"
        assert c.get(f"/api/tasks/{uuid.uuid4()}").status_code == 404


def test_orchestrator_failure_is_reported_without_internal_details(tmp_path):
    err = ProviderError(ProviderErrorType.AUTHENTICATION, "bad key sk-abcdefghijklmnopqrstuvwxyz123456 at /srv/app", "gemini")
    with client_ctx(svc_with(tmp_path, [err])) as c:
        _, cid = new_conversation(c)
        run = wait_run(c, c.post(f"/api/conversations/{cid}/messages", json={"text": "hi"}).json()["run_id"])
        assert run["state"] == "failed"
        assert "sk-abcdefghijklmnopqrstuvwxyz" not in json.dumps(run)
        assert c.get("/api/tasks").json()["tasks"][0]["status"] == "failed"


def test_unexpected_orchestrator_exception_is_masked(tmp_path):
    svc = svc_with(tmp_path, [])
    async def boom(*a, **k):
        raise RuntimeError("SECRET-STACK /home/user/.env")
    svc.runs.orchestrator.run = boom
    with client_ctx(svc) as c:
        _, cid = new_conversation(c)
        run = wait_run(c, c.post(f"/api/conversations/{cid}/messages", json={"text": "hi"}).json()["run_id"])
        assert run["state"] == "failed" and "SECRET" not in json.dumps(run) and run["error"] == "the run failed due to an internal error"


def test_unknown_run_is_404(tmp_path):
    with client_ctx(svc_with(tmp_path, [])) as c:
        assert c.get("/api/runs/doesnotexist1").status_code == 404
        assert c.get("/api/runs/..%2f..%2fetc").status_code in (404, 422)


def test_tool_activity_visible_in_messages_with_bounded_redacted_output(tmp_path):
    from pydantic import BaseModel
    from app.tools.base import Tool

    class Leaky(Tool):
        name, description = "leaky", "returns a lot incl. a secret"
        class A(BaseModel): pass
        args_model = A
        async def execute(self, args): return {"blob": "z" * 9000, "key": "sk-abcdefghijklmnopqrstuvwxyz123456"}
    svc = svc_with(tmp_path, [_response(tool_calls=[call("leaky")]), _response(text="finished")], extra_tools=[Leaky()])
    with client_ctx(svc) as c:
        _, cid = new_conversation(c)
        wait_run(c, c.post(f"/api/conversations/{cid}/messages", json={"text": "run it"}).json()["run_id"])
        msgs = c.get(f"/api/conversations/{cid}/messages").json()["messages"]
        assert [m["role"] for m in msgs] == ["user", "assistant", "tool", "assistant"]
        assert msgs[1]["tool_calls"][0]["name"] == "leaky"
        tool = msgs[2]
        assert tool["tool_name"] == "leaky" and len(tool["content"]) <= 2001 and "sk-abcdefghijklmnopqrstuvwxyz" not in tool["content"]


# ------------------------------ approvals ------------------------------

def test_approval_approve_executes_tool(tmp_path):
    ConfirmTool.executed = 0
    svc = svc_with(tmp_path, [_response(tool_calls=[call("confirm_tool")]), _response(text="done")], extra_tools=[ConfirmTool()])
    with client_ctx(svc) as c:
        _, cid = new_conversation(c)
        run = c.post(f"/api/conversations/{cid}/messages", json={"text": "do it"}).json()["run_id"]
        p = wait_pending(c)
        assert p["tool_name"] == "confirm_tool" and p["level"] == "confirm" and p["run_id"] == run
        assert c.get(f"/api/runs/{run}").json()["run"]["state"] == "awaiting_approval"
        assert c.post(f"/api/approvals/{p['id']}/decision", json={"decision": "approve"}).json()["decision"] == "approved"
        assert wait_run(c, run)["state"] == "completed" and ConfirmTool.executed == 1
        assert c.get("/api/approvals").json()["recent"][0]["decision"] == "approved"


def test_approval_deny_blocks_execution(tmp_path):
    ConfirmTool.executed = 0
    svc = svc_with(tmp_path, [_response(tool_calls=[call("confirm_tool")]), _response(text="ok denied")], extra_tools=[ConfirmTool()])
    with client_ctx(svc) as c:
        _, cid = new_conversation(c)
        run = c.post(f"/api/conversations/{cid}/messages", json={"text": "do it"}).json()["run_id"]
        c.post(f"/api/approvals/{wait_pending(c)['id']}/decision", json={"decision": "deny"})
        r = wait_run(c, run)
        assert ConfirmTool.executed == 0 and r["tool_calls"][0]["success"] is False and "not approved" in r["tool_calls"][0]["error"]


def test_approval_timeout_denies(tmp_path):
    ConfirmTool.executed = 0
    svc = svc_with(tmp_path, [_response(tool_calls=[call("confirm_tool")]), _response(text="fine")], extra_tools=[ConfirmTool()], approval_timeout=0.3)
    with client_ctx(svc) as c:
        _, cid = new_conversation(c)
        run = c.post(f"/api/conversations/{cid}/messages", json={"text": "do it"}).json()["run_id"]
        wait_run(c, run)
        assert ConfirmTool.executed == 0
        assert c.get("/api/approvals").json()["recent"][0]["decision"] == "expired"


def test_dangerous_approval_requires_explicit_acknowledgement(tmp_path):
    DangerTool.executed = 0
    svc = svc_with(tmp_path, [_response(tool_calls=[call("danger_tool")]), _response(text="done")], extra_tools=[DangerTool()])
    with client_ctx(svc) as c:
        _, cid = new_conversation(c)
        run = c.post(f"/api/conversations/{cid}/messages", json={"text": "do it"}).json()["run_id"]
        p = wait_pending(c)
        assert p["requires_acknowledgement"] is True
        assert c.post(f"/api/approvals/{p['id']}/decision", json={"decision": "approve"}).status_code == 400
        assert c.get("/api/approvals").json()["pending"], "still pending after refused approve"
        assert c.post(f"/api/approvals/{p['id']}/decision", json={"decision": "approve", "acknowledged": True}).status_code == 200
        wait_run(c, run)
        assert DangerTool.executed == 1


def test_double_decision_and_unknown_approval(tmp_path):
    svc = svc_with(tmp_path, [_response(tool_calls=[call("confirm_tool")]), _response(text="x")], extra_tools=[ConfirmTool()])
    with client_ctx(svc) as c:
        _, cid = new_conversation(c)
        run = c.post(f"/api/conversations/{cid}/messages", json={"text": "go"}).json()["run_id"]
        aid = wait_pending(c)["id"]
        assert c.post(f"/api/approvals/{aid}/decision", json={"decision": "deny"}).status_code == 200
        wait_run(c, run)
        assert c.post(f"/api/approvals/{aid}/decision", json={"decision": "approve"}).status_code == 409
        assert c.post("/api/approvals/neverexisted1/decision", json={"decision": "approve"}).status_code == 404
        assert c.post(f"/api/approvals/{aid}/decision", json={"decision": "maybe"}).status_code == 422


def test_approval_arguments_are_redacted_and_bounded(tmp_path):
    from pydantic import BaseModel
    from app.tools.base import Tool
    from app.security.permissions import PermissionLevel

    class WithArgs(Tool):
        name, description = "with_args", "x"
        permission_level = PermissionLevel.CONFIRM
        class A(BaseModel):
            token: str
            note: str
        args_model = A
        async def execute(self, args): return "ok"
    svc = svc_with(tmp_path, [_response(tool_calls=[call("with_args", token="sk-abcdefghijklmnopqrstuvwxyz123456", note="n" * 5000)]), _response(text="x")],
                   extra_tools=[WithArgs()])
    with client_ctx(svc) as c:
        _, cid = new_conversation(c)
        run = c.post(f"/api/conversations/{cid}/messages", json={"text": "go"}).json()["run_id"]
        p = wait_pending(c)
        assert "sk-abcdefghijklmnopqrstuvwxyz" not in json.dumps(p) and len(p["arguments"]["note"]) <= 301
        c.post(f"/api/approvals/{p['id']}/decision", json={"decision": "deny"})
        wait_run(c, run)


def test_shutdown_denies_pending_approvals(tmp_path):
    ConfirmTool.executed = 0
    svc = svc_with(tmp_path, [_response(tool_calls=[call("confirm_tool")]), _response(text="x")], extra_tools=[ConfirmTool()])
    with client_ctx(svc) as c:
        _, cid = new_conversation(c)
        c.post(f"/api/conversations/{cid}/messages", json={"text": "go"})
        wait_pending(c)
    assert ConfirmTool.executed == 0 and not svc.approvals.pending()     # lifespan shutdown denied it


# ------------------------------ capabilities / settings ------------------------------

def test_capabilities_listing_and_toggle(tmp_path):
    svc = svc_with(tmp_path, [], extra_tools=[])
    from tests.phase9_helpers import FakeDriver, make_manager
    mgr, _ = make_manager(FakeDriver())
    svc = make_services(tmp_path, ScriptedRouter([]), browser=mgr)
    with client_ctx(svc) as c:
        caps = {x["id"]: x for x in c.get("/api/capabilities").json()["capabilities"]}
        assert caps["browser"]["enabled"] and {t["name"] for t in caps["browser"]["tools"]} >= {"browser_open", "browser_click"}
        assert all("input_schema" not in t for t in caps["browser"]["tools"])
        assert c.post("/api/capabilities/browser/enabled", json={"enabled": False}).json() == {"id": "browser", "enabled": False}
        assert svc.capabilities.tool_registry.get("browser_open") is None
        assert c.post("/api/capabilities/browser/enabled", json={"enabled": True}).json()["enabled"] is True
        assert c.post("/api/capabilities/nope/enabled", json={"enabled": True}).status_code == 404
        assert c.post("/api/capabilities/BAD ID/enabled", json={"enabled": True}).status_code in (404, 422)
        assert c.post("/api/capabilities/browser/enabled", json={"enabled": "yes"}).status_code == 422


def test_disabling_browser_capability_closes_live_session(tmp_path):
    from tests.phase9_helpers import FakeDriver, make_manager
    import asyncio
    d = FakeDriver()
    mgr, _ = make_manager(d)
    svc = make_services(tmp_path, ScriptedRouter([]), browser=mgr)
    asyncio.run(mgr.open("https://site.test/"))
    with client_ctx(svc) as c:
        assert mgr.active
        c.post("/api/capabilities/browser/enabled", json={"enabled": False})
        assert not mgr.active and d.closed


def test_settings_endpoint_never_leaks_secrets(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "gemini_api_key", "AIzaSyFAKE-GEMINI-KEY-1234567890abcdef")
    monkeypatch.setattr(settings, "openrouter_api_key", "sk-or-v1-FAKEOPENROUTERKEY0123456789abcdef")
    monkeypatch.setattr(settings, "github_token", "ghp_FAKEGITHUBTOKEN0123456789abcdefghij")
    monkeypatch.setattr(settings, "brave_search_api_key", "BSAFAKEBRAVEKEY0123456789")
    with client_ctx(svc_with(tmp_path, [])) as c:
        bodies = [c.get(p).text for p in ("/api/settings", "/api/capabilities", "/api/self-improvement", "/api/browser/status",
                                          "/api/voice/status", "/api/sessions", "/api/tasks", "/api/approvals")]
        blob = "\n".join(bodies)
        for secret in ("FAKE-GEMINI", "FAKEOPENROUTER", "FAKEGITHUB", "FAKEBRAVE", "AIzaSy", "ghp_", "sk-or-"):
            assert secret not in blob
        s = c.get("/api/settings").json()
        assert s["providers"]["configured"]["gemini"] is True and s["providers"]["configured"]["openrouter"] is True
        assert TOKEN_NOT_IN(blob)


def TOKEN_NOT_IN(text: str) -> bool:
    from tests.phase9_helpers import TOKEN
    return TOKEN not in text


def test_self_improvement_status_is_disabled_by_default_and_read_only(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "self_improvement_enabled", False)
    with client_ctx(svc_with(tmp_path, [])) as c:
        si = c.get("/api/self-improvement").json()
        assert si["config_enabled"] is False and si["capability_installed"] is False and "DISABLED" in si["message"] and si["read_only"] is True
        assert c.post("/api/capabilities/self_improvement/enabled", json={"enabled": True}).status_code == 404


def test_dashboard_cannot_enable_self_improvement_even_if_installed(tmp_path):
    from app.capabilities.models import Capability, CapabilityCategory, CapabilitySource
    from app.security.permissions import PermissionLevel
    svc = svc_with(tmp_path, [])
    svc.capabilities.install(Capability(id="self_improvement", name="si", description="d", version="1.0.0", category=CapabilityCategory.DEVELOPMENT,
                                        source=CapabilitySource.BUILTIN, max_permission=PermissionLevel.CONFIRM, tool_names=(), enabled=False), [])
    with client_ctx(svc) as c:
        r = c.post("/api/capabilities/self_improvement/enabled", json={"enabled": True})
        assert r.status_code == 403 and svc.capabilities.is_enabled("self_improvement") is False


def test_no_privileged_or_generic_routes_exist(tmp_path):
    svc = svc_with(tmp_path, [])
    from app.ui.app import create_app
    paths = {r.path for r in create_app(svc).routes}
    banned = ("promote", "rollback", "release", "manifest", "pointer", "shell", "exec", "command", "patch", "isolation", "candidate", "sandbox", "eval", "upload")
    assert not [p for p in paths if any(b in p.lower() for b in banned)], paths
    methods = {(m, r.path) for r in create_app(svc).routes for m in getattr(r, "methods", set())}
    assert not [x for x in methods if x[0] in ("PUT", "DELETE")]


# ------------------------------ voice endpoints ------------------------------

class _Rec(SpeechRecognizer):
    name, location = "stub", "local"
    def __init__(self): self.calls = 0
    async def transcribe(self, audio, mime, language):
        self.calls += 1
        return Transcript(text="please summarise my tasks", provider="stub")


class _Syn(SpeechSynthesizer):
    name, location = "stub", "local"
    async def synthesize(self, text): return AudioClip(data=b"RIFFwav", mime="audio/wav")


def voice_svc(rec=None, syn=None, i=True, o=True):
    return VoiceService(rec or _Rec(), syn or _Syn(), input_enabled=i, output_enabled=o, max_audio_bytes=100,
                        speech_max_chars=200, speech_chunk_chars=60)


def test_voice_transcribe_returns_draft_and_does_not_submit_or_store(tmp_path):
    svc = svc_with(tmp_path, [], voice=voice_svc())
    with client_ctx(svc) as c:
        _, cid = new_conversation(c)
        r = c.post("/api/voice/transcribe", content=b"audiobytes", headers={"Content-Type": "audio/webm"})
        assert r.status_code == 200 and r.json()["transcript"] == "please summarise my tasks" and r.json()["confirmed"] is False
        assert c.get(f"/api/conversations/{cid}/messages").json()["messages"] == []           # nothing was sent
        assert c.get("/api/tasks").json()["tasks"] == []


def test_voice_transcribe_limits_and_disabled(tmp_path):
    with client_ctx(svc_with(tmp_path, [], voice=voice_svc())) as c:
        assert c.post("/api/voice/transcribe", content=b"x" * 101, headers={"Content-Type": "audio/webm"}).status_code == 413
        assert c.post("/api/voice/transcribe", content=b"", headers={"Content-Type": "audio/webm"}).status_code == 400
        assert c.post("/api/voice/transcribe", content=b"x", headers={"Content-Type": "text/plain"}).status_code == 415
    with client_ctx(svc_with(tmp_path / "off", [], voice=voice_svc(i=False))) as c:
        assert c.post("/api/voice/transcribe", content=b"x", headers={"Content-Type": "audio/webm"}).status_code == 403


def test_voice_recognition_failure_is_graceful(tmp_path):
    from app.voice.errors import SpeechRecognitionError
    class Bad(_Rec):
        async def transcribe(self, *a): raise SpeechRecognitionError("no speech was recognized")
    with client_ctx(svc_with(tmp_path, [], voice=voice_svc(rec=Bad()))) as c:
        r = c.post("/api/voice/transcribe", content=b"x", headers={"Content-Type": "audio/webm"})
        assert r.status_code == 502 and r.json()["error"] == "no speech was recognized"
        assert c.get("/api/sessions").status_code == 200        # app still healthy


def test_voice_message_requires_confirmation_and_enabled_voice(tmp_path):
    svc = svc_with(tmp_path, [_response(text="Here are your tasks.")], voice=voice_svc())
    with client_ctx(svc) as c:
        _, cid = new_conversation(c)
        unconfirmed = c.post(f"/api/conversations/{cid}/messages", json={"text": "delete everything", "source": "voice"})
        assert unconfirmed.status_code == 422 and "confirmed" in unconfirmed.json()["error"]
        assert c.get("/api/tasks").json()["tasks"] == []
        ok = c.post(f"/api/conversations/{cid}/messages", json={"text": "summarise my tasks", "source": "voice", "confirmed": True})
        assert ok.status_code == 202
        wait_run(c, ok.json()["run_id"])
        msgs = c.get(f"/api/conversations/{cid}/messages").json()["messages"]
        assert [(m["role"], m["content"]) for m in msgs] == [("user", "summarise my tasks"), ("assistant", "Here are your tasks.")]
    with client_ctx(svc_with(tmp_path / "off", [])) as c:
        _, cid = new_conversation(c)
        assert c.post(f"/api/conversations/{cid}/messages", json={"text": "hi", "source": "voice", "confirmed": True}).status_code == 403


def test_speech_plan_and_synthesize_endpoints(tmp_path):
    with client_ctx(svc_with(tmp_path, [], voice=voice_svc())) as c:
        plan = c.post("/api/voice/speech-plan", json={"text": "Hello there. " * 40}).json()
        assert plan["truncated"] is True and plan["client_side"] is False and all(len(x) <= 60 for x in plan["chunks"][:-1])
        r = c.post("/api/voice/synthesize", json={"text": "Hello"})
        assert r.status_code == 200 and r.headers["content-type"] == "audio/wav" and r.content == b"RIFFwav"
        assert c.post("/api/voice/speech-plan", json={"text": ""}).status_code == 422
    with client_ctx(svc_with(tmp_path / "off", [], voice=voice_svc(o=False))) as c:
        assert c.post("/api/voice/speech-plan", json={"text": "hi"}).status_code == 403
        assert c.post("/api/voice/synthesize", json={"text": "hi"}).status_code == 403


def test_voice_status_exposes_no_approval_path(tmp_path):
    with client_ctx(svc_with(tmp_path, [], voice=voice_svc())) as c:
        st = c.get("/api/voice/status").json()
        assert st["voice_can_approve_actions"] is False and st["stores_audio"] is False
    from app.ui.app import create_app
    voice_paths = [r.path for r in create_app(svc_with(tmp_path / "x", [])).routes if "/voice/" in r.path]
    assert not [p for p in voice_paths if "approv" in p or "decision" in p]
