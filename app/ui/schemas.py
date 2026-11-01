from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, StrictBool, field_validator


class _In(BaseModel):
    model_config = ConfigDict(extra="forbid")


class LoginIn(_In):
    token: str = Field(min_length=1, max_length=256)


class CreateSessionIn(_In):
    title: str | None = Field(default=None, max_length=120)

    @field_validator("title")
    @classmethod
    def _blank_is_none(cls, v: str | None) -> str | None:
        return v.strip() or None if v is not None else None


class RenameSessionIn(_In):
    title: str = Field(min_length=1, max_length=120)

    @field_validator("title")
    @classmethod
    def _strip(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("title cannot be blank")
        return v


class SendMessageIn(_In):
    text: str = Field(min_length=1, max_length=50_000)
    source: Literal["text", "voice"] = "text"
    # Voice transcripts are DRAFTS: the dashboard must show the transcript and the user must confirm it.
    confirmed: StrictBool = False

    @field_validator("text")
    @classmethod
    def _clean(cls, v: str) -> str:
        v = v.replace("\x00", "").strip()
        if not v:
            raise ValueError("message is empty")
        return v


class ApprovalDecisionIn(_In):
    decision: Literal["approve", "deny"]
    acknowledged: StrictBool = False


class CapabilityToggleIn(_In):
    enabled: StrictBool


class SpeakIn(_In):
    text: str = Field(min_length=1, max_length=20_000)
