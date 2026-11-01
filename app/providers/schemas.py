from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class ProviderErrorType(str, Enum):
    """Typed failure categories so the ModelRouter can decide, per error,
    whether falling back to the next provider is appropriate."""

    AUTHENTICATION = "authentication"
    QUOTA_EXCEEDED = "quota_exceeded"
    TIMEOUT = "timeout"
    NETWORK = "network"
    INVALID_RESPONSE = "invalid_response"
    UNSUPPORTED_FEATURE = "unsupported_feature"
    UNKNOWN = "unknown"


class ProviderError(Exception):
    """Raised by any AIProvider implementation on failure.

    `retryable` defaults by error_type but can be overridden per-raise, e.g.
    an AUTHENTICATION error is not "retryable" against the same provider,
    but the router may still choose to fall back to a *different* provider.
    """

    _DEFAULT_RETRYABLE = {
        ProviderErrorType.QUOTA_EXCEEDED: True,
        ProviderErrorType.TIMEOUT: True,
        ProviderErrorType.NETWORK: True,
        ProviderErrorType.AUTHENTICATION: False,
        ProviderErrorType.INVALID_RESPONSE: False,
        ProviderErrorType.UNSUPPORTED_FEATURE: False,
        ProviderErrorType.UNKNOWN: False,
    }

    def __init__(
        self,
        error_type: ProviderErrorType,
        message: str,
        provider: str,
        retryable: bool | None = None,
    ) -> None:
        self.error_type = error_type
        self.message = message
        self.provider = provider
        self.retryable = (
            retryable if retryable is not None else self._DEFAULT_RETRYABLE[error_type]
        )
        super().__init__(f"[{provider}] {error_type.value}: {message}")


@dataclass
class ToolSchema:
    """Describes a tool to the model. `parameters` is a JSON Schema object,
    the same shape every provider's native function-calling format expects."""

    name: str
    description: str
    parameters: dict[str, Any]


@dataclass
class ToolCall:
    """A model's request to invoke a tool.

    OWNERSHIP OF `id`: JARVIS-X owns this identifier, not the provider.
    Every ToolCall must be constructed via `ToolCall.new()`, which mints a
    fresh internal id (`call_<uuid hex>`) regardless of what, if anything,
    the provider returned. The rest of the application — permission checks,
    tool execution, ToolResult matching, memory/task persistence — must
    always reference this `id`. It is stable across providers: code that
    matches a ToolResult to its ToolCall never needs to know or care
    whether the call originated from Gemini, OpenRouter, or Ollama.

    `provider_call_id` optionally preserves a provider's own native call
    identifier (e.g. OpenRouter/OpenAI-style `call_...` ids returned in
    their response payload), purely for provider-side bookkeeping or
    debugging. It is never used for internal matching and may be None —
    Gemini and Ollama, for instance, typically don't return one.
    """

    id: str
    name: str
    arguments: dict[str, Any]
    provider_call_id: str | None = None

    @staticmethod
    def new(
        name: str,
        arguments: dict[str, Any],
        provider_call_id: str | None = None,
    ) -> "ToolCall":
        return ToolCall(
            id=f"call_{uuid.uuid4().hex[:12]}",
            name=name,
            arguments=arguments,
            provider_call_id=provider_call_id,
        )


@dataclass
class ToolResult:
    """The outcome of executing a ToolCall — the single canonical record of
    a tool execution, whatever its outcome (success, validation failure,
    permission denial, timeout, exception, ...). Fed back to the model as
    a role="tool" Message, and also what the orchestrator surfaces to
    callers for diagnostics/display.

    `arguments` holds the validated argument representation that was
    actually (or would have been) executed — i.e. after Pydantic
    validation, not the raw model-provided dict — for any outcome where
    validation succeeded. For outcomes where validation itself failed, or
    the tool couldn't even be looked up, this falls back to the raw
    model-provided arguments, since no validated form exists.
    """

    tool_call_id: str
    name: str
    success: bool
    result: Any = None
    error: str | None = None
    arguments: dict[str, Any] = field(default_factory=dict)


@dataclass
class Message:
    """A single turn in the conversation, in JARVIS-X's internal format.

    role: "system" | "user" | "assistant" | "tool"
    For role="assistant" messages that requested tools, populate tool_calls.
    For role="tool" messages (a tool's result being reported back), populate
    tool_call_id and name, with `content` holding the (stringified) result.
    """

    role: str
    content: str | None = None
    tool_calls: list[ToolCall] = field(default_factory=list)
    tool_call_id: str | None = None
    name: str | None = None


@dataclass
class ModelResponse:
    """What every AIProvider returns, regardless of backend. The rest of
    JARVIS-X only ever sees this shape — never a provider's raw payload."""

    text: str | None
    tool_calls: list[ToolCall] = field(default_factory=list)
    provider: str = ""
    model: str = ""
    raw: Any = None
