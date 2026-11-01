from __future__ import annotations

import logging
from typing import Any

from app.voice.errors import AudioTooLargeError, VoiceDisabledError, VoiceError, VoiceUnavailableError
from app.voice.models import AudioClip, SpeechPlan, Transcript
from app.voice.recognition import BrowserRecognizer, FasterWhisperRecognizer, NullRecognizer, SpeechRecognizer
from app.voice.speech_text import prepare_speech
from app.voice.synthesis import BrowserSynthesizer, NullSynthesizer, SpeechSynthesizer

logger = logging.getLogger(__name__)


class VoiceService:
    """Facade used by the dashboard. It can transcribe and synthesize — it cannot submit messages or
    decide approvals; transcripts are returned as DRAFTS for the user to confirm."""

    def __init__(self, recognizer: SpeechRecognizer, synthesizer: SpeechSynthesizer, *, input_enabled: bool,
                 output_enabled: bool, max_audio_bytes: int, speech_max_chars: int, speech_chunk_chars: int,
                 language: str | None = None, input_reason: str | None = None, output_reason: str | None = None) -> None:
        self.recognizer, self.synthesizer = recognizer, synthesizer
        self.input_enabled, self.output_enabled = input_enabled, output_enabled
        self.max_audio_bytes = max_audio_bytes
        self.speech_max_chars, self.speech_chunk_chars = speech_max_chars, speech_chunk_chars
        self.language = language
        self._input_reason, self._output_reason = input_reason, output_reason

    def status(self) -> dict[str, Any]:
        def side(enabled: bool, provider: Any, reason: str | None) -> dict[str, Any]:
            return {"enabled": enabled, "provider": provider.name if enabled else "none",
                    "location": provider.location if enabled else "none",
                    "client_side": bool(provider.client_side) if enabled else False,
                    "privacy_note": provider.privacy_note if enabled else "", "reason": None if enabled else reason}
        return {"input": side(self.input_enabled, self.recognizer, self._input_reason),
                "output": side(self.output_enabled, self.synthesizer, self._output_reason),
                "max_audio_bytes": self.max_audio_bytes, "stores_audio": False,
                "voice_can_approve_actions": False}

    async def transcribe(self, audio: bytes, mime: str) -> Transcript:
        if not self.input_enabled:
            raise VoiceDisabledError("voice input is disabled")
        if not audio:
            raise VoiceError("no audio was received")
        if len(audio) > self.max_audio_bytes:
            raise AudioTooLargeError("audio is too large")
        return await self.recognizer.transcribe(audio, mime, self.language)

    def speech_plan(self, text: str) -> SpeechPlan:
        if not self.output_enabled:
            raise VoiceDisabledError("spoken responses are disabled")
        return prepare_speech(text, self.speech_max_chars, self.speech_chunk_chars)

    async def synthesize(self, text: str) -> AudioClip:
        if not self.output_enabled:
            raise VoiceDisabledError("spoken responses are disabled")
        if self.synthesizer.client_side:
            raise VoiceUnavailableError("this provider speaks in the browser")
        plan = prepare_speech(text, self.speech_chunk_chars, self.speech_chunk_chars)
        if not plan.chunks:
            raise VoiceError("nothing to speak")
        return await self.synthesizer.synthesize(plan.chunks[0])


def build_voice_service() -> VoiceService:
    """Config-driven. Anything misconfigured or unavailable leaves that direction DISABLED with a reason;
    it never raises, so a voice problem cannot break the dashboard or the agent."""
    from app.config.settings import settings as s

    recognizer: SpeechRecognizer = NullRecognizer()
    in_ok, in_reason = False, None
    if s.voice_input_enabled:
        p = s.voice_stt_provider.lower()
        if p == "browser":
            recognizer, in_ok = BrowserRecognizer(), True
        elif p == "faster_whisper":
            try:
                import importlib.util
                if importlib.util.find_spec("faster_whisper") is None:
                    raise VoiceUnavailableError("faster-whisper is not installed (pip install -r requirements-voice.txt)")
                recognizer = FasterWhisperRecognizer(
                    s.voice_stt_model, str(s.voice_stt_model_path) if s.voice_stt_model_path else None,
                    s.voice_stt_allow_download, s.voice_stt_timeout)
                in_ok = True
            except VoiceError as exc:
                in_reason = str(exc)
        else:
            in_reason = f"VOICE_STT_PROVIDER '{s.voice_stt_provider}' is not 'browser' or 'faster_whisper'"
    else:
        in_reason = "VOICE_INPUT_ENABLED is false"

    synth: SpeechSynthesizer = NullSynthesizer()
    out_ok, out_reason = False, None
    if s.speech_output_enabled:
        p = s.speech_synthesis_provider.lower()
        if p == "browser":
            synth, out_ok = BrowserSynthesizer(), True
        else:
            out_reason = f"SPEECH_SYNTHESIS_PROVIDER '{s.speech_synthesis_provider}' is not 'browser'"
    else:
        out_reason = "SPEECH_OUTPUT_ENABLED is false"

    return VoiceService(recognizer, synth, input_enabled=in_ok, output_enabled=out_ok,
                        max_audio_bytes=s.voice_max_audio_bytes, speech_max_chars=s.speech_max_chars,
                        speech_chunk_chars=s.speech_chunk_chars, language=s.voice_stt_language,
                        input_reason=in_reason, output_reason=out_reason)
