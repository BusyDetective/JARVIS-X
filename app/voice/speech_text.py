"""Turn an assistant message into speakable, bounded, secret-free chunks."""
from __future__ import annotations

import re

from app.security.untrusted import redact_text
from app.voice.models import SpeechPlan

_FENCE = re.compile(r"```.*?```", re.DOTALL)
_LINK = re.compile(r"\[([^\]]+)\]\((?:[^)]+)\)")
_URL = re.compile(r"https?://\S+")
_MD = re.compile(r"[#*_>|~`]+")
_SENT = re.compile(r"(?<=[.!?])\s+")


def prepare_speech(text: str, max_chars: int, chunk_chars: int) -> SpeechPlan:
    t = _FENCE.sub(" (code omitted) ", text)
    t = _LINK.sub(r"\1", t)
    t = _URL.sub("link", t)
    t = _MD.sub(" ", t)
    t = redact_text(t)[0]
    t = re.sub(r"\s+", " ", t).strip()
    truncated = False
    if len(t) > max_chars:
        cut = t[:max_chars]
        boundary = max(cut.rfind(". "), cut.rfind("! "), cut.rfind("? "))
        t = (cut[: boundary + 1] if boundary > max_chars // 2 else cut).strip()
        truncated = True
    chunks: list[str] = []
    cur = ""
    for sent in _SENT.split(t):
        while len(sent) > chunk_chars:  # very long sentence: hard split on spaces
            head, sent = sent[:chunk_chars], sent[chunk_chars:]
            if " " in head:
                head, rest = head.rsplit(" ", 1)
                sent = rest + sent
            if cur:
                chunks.append(cur); cur = ""
            chunks.append(head.strip())
        if cur and len(cur) + 1 + len(sent) > chunk_chars:
            chunks.append(cur); cur = sent
        else:
            cur = f"{cur} {sent}".strip()
    if cur:
        chunks.append(cur)
    chunks = [c for c in chunks if c]
    if truncated:
        chunks.append("The rest of the response is on screen.")
    return SpeechPlan(chunks=chunks, truncated=truncated)
