from __future__ import annotations

from pydantic import BaseModel, Field


class Transcript(BaseModel):
    text: str = Field(max_length=4000)
    provider: str
    language: str | None = None


class AudioClip(BaseModel):
    model_config = {"arbitrary_types_allowed": True}
    data: bytes
    mime: str


class SpeechPlan(BaseModel):
    chunks: list[str]
    truncated: bool = False
