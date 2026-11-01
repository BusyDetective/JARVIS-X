from __future__ import annotations

import asyncio
import io
import logging
import time
from abc import ABC, abstractmethod
from typing import Any

from app.voice.errors import SpeechRecognitionError, VoiceUnavailableError
from app.voice.models import Transcript

logger = logging.getLogger(__name__)
MAX_TRANSCRIPT_CHARS = 4000


class SpeechRecognizer(ABC):
    name: str
    # where audio is processed: "client" (in the user's browser), "local" (this machine), "external"
    location: str
    client_side: bool = False
    privacy_note: str = ""

    @abstractmethod
    async def transcribe(self, audio: bytes, mime: str, language: str | None) -> Transcript: ...


class NullRecognizer(SpeechRecognizer):
    name, location = "none", "none"

    async def transcribe(self, audio: bytes, mime: str, language: str | None) -> Transcript:
        raise VoiceUnavailableError("no speech recognition provider is configured")


class BrowserRecognizer(SpeechRecognizer):
    """Recognition happens in the user's browser (Web Speech API). The server never receives audio.
    NOTE: Chrome/Edge implement that API by sending audio to the browser vendor's cloud service."""

    name, location, client_side = "browser", "client", True
    privacy_note = ("Uses your browser's built-in speech recognition. In Chrome and Edge this sends audio to the "
                    "browser vendor's servers; JARVIS-X itself never receives or stores the audio.")

    async def transcribe(self, audio: bytes, mime: str, language: str | None) -> Transcript:
        raise VoiceUnavailableError("this provider runs in the browser; the server does not transcribe audio")


class FasterWhisperRecognizer(SpeechRecognizer):
    """Local, offline recognition (optional dependency `faster-whisper`). Audio is processed in memory
    (never written to disk by this code, never uploaded). Models are NOT downloaded unless
    VOICE_STT_ALLOW_DOWNLOAD=true; otherwise point VOICE_STT_MODEL_PATH at a local model directory."""

    name, location = "faster_whisper", "local"
    privacy_note = "Audio is transcribed locally in memory and discarded. No audio is uploaded or stored."

    def __init__(self, model: str, model_path: str | None, allow_download: bool, timeout: float,
                 model_factory: Any = None) -> None:
        self._model_name, self._model_path = model, model_path
        self._allow_download, self._timeout = allow_download, timeout
        self._factory = model_factory
        self._model: Any = None

    def _load(self) -> Any:
        if self._model is None:
            if self._factory is not None:
                self._model = self._factory()
            else:
                try:
                    from faster_whisper import WhisperModel
                except ImportError:
                    raise VoiceUnavailableError(
                        "faster-whisper is not installed (pip install -r requirements-voice.txt)") from None
                try:
                    self._model = WhisperModel(self._model_path or self._model_name, device="cpu",
                                               compute_type="int8", local_files_only=not self._allow_download)
                except Exception:  # noqa: BLE001
                    raise VoiceUnavailableError(
                        "the local speech model could not be loaded (set VOICE_STT_MODEL_PATH to a local model "
                        "or VOICE_STT_ALLOW_DOWNLOAD=true)") from None
        return self._model

    def _run(self, audio: bytes, language: str | None) -> str:
        model = self._load()
        segments, _info = model.transcribe(io.BytesIO(audio), language=language, vad_filter=True, beam_size=1)
        return " ".join(s.text.strip() for s in segments).strip()

    async def transcribe(self, audio: bytes, mime: str, language: str | None) -> Transcript:
        started = time.monotonic()
        try:
            text = await asyncio.wait_for(asyncio.to_thread(self._run, audio, language), self._timeout)
        except asyncio.TimeoutError:
            raise SpeechRecognitionError("speech recognition timed out") from None
        except VoiceUnavailableError:
            raise
        except Exception as exc:  # noqa: BLE001
            logger.warning("speech recognition failed: %s", type(exc).__name__)
            raise SpeechRecognitionError("speech recognition failed (unsupported or corrupt audio?)") from None
        logger.info("speech recognition ok duration=%.2fs chars=%d", time.monotonic() - started, len(text))
        if not text:
            raise SpeechRecognitionError("no speech was recognized")
        return Transcript(text=text[:MAX_TRANSCRIPT_CHARS], provider=self.name, language=language)
