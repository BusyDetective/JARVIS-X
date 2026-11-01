"""Voice abstractions: recognition, synthesis, speech text preparation, configuration."""
from __future__ import annotations


import pytest

from app.config.settings import settings
from app.voice.errors import (
    AudioTooLargeError, SpeechRecognitionError, VoiceDisabledError, VoiceError, VoiceUnavailableError,
)
from app.voice.recognition import BrowserRecognizer, FasterWhisperRecognizer, NullRecognizer, SpeechRecognizer
from app.voice.service import VoiceService, build_voice_service
from app.voice.speech_text import prepare_speech
from app.voice.synthesis import BrowserSynthesizer, NullSynthesizer, SpeechSynthesizer
from app.voice.models import AudioClip, Transcript


class FakeSeg:
    def __init__(self, text): self.text = text


class FakeModel:
    def __init__(self, text="hello jarvis", raise_exc=None, delay=0.0):
        self.text, self.raise_exc, self.delay, self.received = text, raise_exc, delay, None
    def transcribe(self, audio, **kw):
        import time; time.sleep(self.delay)
        if self.raise_exc: raise self.raise_exc
        self.received = audio
        return ([FakeSeg(self.text)] if self.text else []), object()


class StubRecognizer(SpeechRecognizer):
    name, location = "stub", "local"
    async def transcribe(self, audio, mime, language): return Transcript(text="open the pod bay doors", provider="stub")


class StubSynth(SpeechSynthesizer):
    name, location = "stub", "local"
    def __init__(self): self.spoken = []
    async def synthesize(self, text): self.spoken.append(text); return AudioClip(data=b"RIFFxxxx", mime="audio/wav")


def svc(rec=None, syn=None, i=True, o=True, max_audio=100):
    return VoiceService(rec or StubRecognizer(), syn or StubSynth(), input_enabled=i, output_enabled=o, max_audio_bytes=max_audio,
                        speech_max_chars=200, speech_chunk_chars=50, input_reason="off", output_reason="off")


async def test_transcribe_returns_draft_transcript():
    t = await svc().transcribe(b"audio", "audio/webm")
    assert t.text == "open the pod bay doors" and t.provider == "stub"


async def test_disabled_input_refuses():
    with pytest.raises(VoiceDisabledError):
        await svc(i=False).transcribe(b"a", "audio/webm")


async def test_empty_and_oversized_audio_rejected():
    with pytest.raises(VoiceError):
        await svc().transcribe(b"", "audio/webm")
    with pytest.raises(AudioTooLargeError):
        await svc(max_audio=10).transcribe(b"x" * 11, "audio/webm")


async def test_null_and_browser_recognizers_cannot_transcribe_server_side():
    for r in (NullRecognizer(), BrowserRecognizer()):
        with pytest.raises(VoiceUnavailableError):
            await r.transcribe(b"x", "audio/webm", None)


async def test_faster_whisper_recognizer_uses_memory_only_and_local():
    model = FakeModel()
    r = FasterWhisperRecognizer("base", None, False, 5, model_factory=lambda: model)
    t = await r.transcribe(b"RIFF....", "audio/wav", "en")
    assert t.text == "hello jarvis" and r.location == "local"
    assert hasattr(model.received, "read")            # BytesIO, not a file path: nothing written to disk


async def test_recognition_errors_map_to_safe_messages():
    r = FasterWhisperRecognizer("b", None, False, 5, model_factory=lambda: FakeModel(raise_exc=RuntimeError("/secret/path boom")))
    with pytest.raises(SpeechRecognitionError) as ei:
        await r.transcribe(b"x", "audio/wav", None)
    assert "/secret/path" not in str(ei.value)
    with pytest.raises(SpeechRecognitionError):
        await FasterWhisperRecognizer("b", None, False, 5, model_factory=lambda: FakeModel(text="")).transcribe(b"x", "a", None)


async def test_recognition_timeout():
    r = FasterWhisperRecognizer("b", None, False, 0.2, model_factory=lambda: FakeModel(delay=1.0))
    with pytest.raises(SpeechRecognitionError, match="timed out"):
        await r.transcribe(b"x", "audio/wav", None)


async def test_missing_faster_whisper_is_unavailable_not_a_crash(monkeypatch):
    import builtins
    real = builtins.__import__
    def fake(name, *a, **k):
        if name.startswith("faster_whisper"): raise ImportError
        return real(name, *a, **k)
    monkeypatch.setattr(builtins, "__import__", fake)
    with pytest.raises(VoiceUnavailableError, match="requirements-voice"):
        await FasterWhisperRecognizer("base", None, False, 5).transcribe(b"x", "audio/wav", None)


async def test_synthesis_disabled_and_client_side_providers():
    with pytest.raises(VoiceDisabledError):
        svc(o=False).speech_plan("hi")
    with pytest.raises(VoiceDisabledError):
        await svc(o=False).synthesize("hi")
    for s in (NullSynthesizer(), BrowserSynthesizer()):
        with pytest.raises(VoiceUnavailableError):
            await s.synthesize("x")
    with pytest.raises(VoiceUnavailableError):
        await svc(syn=BrowserSynthesizer()).synthesize("hi")


async def test_server_synthesis_speaks_a_single_bounded_chunk():
    syn = StubSynth()
    clip = await svc(syn=syn).synthesize("word " * 100)
    assert clip.mime == "audio/wav" and len(syn.spoken) == 1 and len(syn.spoken[0]) <= 50


def test_speech_text_strips_code_urls_markdown_and_secrets():
    plan = prepare_speech("# Title\n```python\nprint(1)\n```\nSee [docs](https://x.test/a?t=1) or https://y.test/z. "
                          "Key sk-abcdefghijklmnopqrstuvwxyz123456 end.", 500, 100)
    joined = " ".join(plan.chunks)
    assert "print(1)" not in joined and "https://" not in joined and "sk-abc" not in joined and "code omitted" in joined
    assert "docs" in joined and "#" not in joined


def test_long_responses_are_truncated_chunked_and_point_to_screen():
    plan = prepare_speech(("This is a sentence. " * 200), 300, 80)
    assert plan.truncated and plan.chunks[-1] == "The rest of the response is on screen."
    assert all(len(c) <= 80 for c in plan.chunks[:-1]) and sum(len(c) for c in plan.chunks[:-1]) <= 300 + len(plan.chunks)


def test_unbroken_long_text_is_hard_split():
    plan = prepare_speech("a" * 1000, 2000, 100)
    assert all(len(c) <= 100 for c in plan.chunks) and len(plan.chunks) == 10


def test_status_never_claims_voice_can_approve_and_reports_privacy():
    st = svc(rec=BrowserRecognizer(), syn=BrowserSynthesizer()).status()
    assert st["voice_can_approve_actions"] is False and st["stores_audio"] is False
    assert st["input"]["client_side"] and "vendor" in st["input"]["privacy_note"]
    assert st["output"]["location"] == "client"
    off = svc(i=False, o=False).status()
    assert off["input"]["enabled"] is False and off["input"]["provider"] == "none" and off["input"]["reason"] == "off"


# ---- configuration ----

def _cfg(monkeypatch, **kw):
    for k, v in kw.items():
        monkeypatch.setattr(settings, k, v)
    return build_voice_service()


def test_default_config_leaves_voice_disabled(monkeypatch):
    s = _cfg(monkeypatch)
    assert not s.input_enabled and not s.output_enabled


def test_unknown_providers_disable_with_reason_not_crash(monkeypatch):
    s = _cfg(monkeypatch, voice_input_enabled=True, voice_stt_provider="cloudy", speech_output_enabled=True, speech_synthesis_provider="elevenx")
    assert not s.input_enabled and "cloudy" in s.status()["input"]["reason"]
    assert not s.output_enabled and "elevenx" in s.status()["output"]["reason"]


def test_browser_providers_enabled_by_config(monkeypatch):
    s = _cfg(monkeypatch, voice_input_enabled=True, voice_stt_provider="browser", speech_output_enabled=True, speech_synthesis_provider="browser")
    assert s.input_enabled and s.output_enabled and s.recognizer.client_side and s.synthesizer.client_side


def test_provider_name_without_enable_flag_stays_off(monkeypatch):
    s = _cfg(monkeypatch, voice_input_enabled=False, voice_stt_provider="browser")
    assert not s.input_enabled


def test_missing_local_recognition_dependency_disables_cleanly(monkeypatch):
    import importlib.util
    monkeypatch.setattr(importlib.util, "find_spec", lambda name, *a, **k: None)
    s = _cfg(monkeypatch, voice_input_enabled=True, voice_stt_provider="faster_whisper")
    assert not s.input_enabled and "faster-whisper" in s.status()["input"]["reason"]


def test_cli_based_synthesis_is_not_offered(monkeypatch):
    s = _cfg(monkeypatch, speech_output_enabled=True, speech_synthesis_provider="espeak")
    assert not s.output_enabled and "'browser'" in s.status()["output"]["reason"]
