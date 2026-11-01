from __future__ import annotations

import logging
from abc import ABC, abstractmethod

from app.voice.errors import VoiceUnavailableError
from app.voice.models import AudioClip

logger = logging.getLogger(__name__)


class SpeechSynthesizer(ABC):
    """Extension point. Server-side providers must run IN-PROCESS: the Phase 8 invariant (tests/test_sandbox.py) forbids any
    module other than the container wrapper from starting host processes, so a CLI-based engine (e.g. espeak-ng) is not offered."""

    name: str
    location: str  # "client" | "local" | "external"
    client_side: bool = False
    privacy_note: str = ""

    @abstractmethod
    async def synthesize(self, text: str) -> AudioClip: ...


class NullSynthesizer(SpeechSynthesizer):
    name, location = "none", "none"

    async def synthesize(self, text: str) -> AudioClip:
        raise VoiceUnavailableError("no speech synthesis provider is configured")


class BrowserSynthesizer(SpeechSynthesizer):
    """Playback happens in the user's browser (speechSynthesis). The server only supplies sanitized text."""

    name, location, client_side = "browser", "client", True
    privacy_note = ("Uses your browser's built-in speech synthesis. Most operating-system voices are local, but some "
                    "browser voices (e.g. 'Google ...' voices in Chrome) are network voices that send the text out.")

    async def synthesize(self, text: str) -> AudioClip:
        raise VoiceUnavailableError("this provider speaks in the browser; the server does not synthesize audio")
