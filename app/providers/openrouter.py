from __future__ import annotations

import json
import logging

import httpx

from app.config.settings import settings
from app.providers.base import AIProvider
from app.providers.schemas import (
    Message,
    ModelResponse,
    ProviderError,
    ProviderErrorType,
    ToolCall,
    ToolSchema,
)

logger = logging.getLogger(__name__)

CHAT_COMPLETIONS_URL = "https://openrouter.ai/api/v1/chat/completions"
MODELS_URL = "https://openrouter.ai/api/v1/models"


class OpenRouterProvider(AIProvider):
    """OpenRouter speaks the OpenAI chat-completions format. All of that
    stays inside this module — the rest of JARVIS-X only sees normalized
    schemas."""

    name = "openrouter"

    def __init__(self, api_key: str | None = None, model: str | None = None) -> None:
        self.api_key = api_key or settings.openrouter_api_key
        self.model_name = model or settings.openrouter_model

    def _require_key(self) -> None:
        if not self.api_key:
            raise ProviderError(
                ProviderErrorType.AUTHENTICATION,
                "OPENROUTER_API_KEY is not configured",
                self.name,
                retryable=False,
            )

    def _headers(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self.api_key}", "Content-Type": "application/json"}

    @staticmethod
    def _to_openai_messages(messages: list[Message]) -> list[dict]:
        out: list[dict] = []
        for m in messages:
            if m.role == "tool":
                out.append(
                    {
                        "role": "tool",
                        "tool_call_id": m.tool_call_id,
                        "name": m.name,
                        "content": m.content or "",
                    }
                )
                continue
            entry: dict = {"role": m.role, "content": m.content}
            if m.tool_calls:
                entry["tool_calls"] = [
                    {
                        "id": tc.id,
                        "type": "function",
                        "function": {"name": tc.name, "arguments": json.dumps(tc.arguments)},
                    }
                    for tc in m.tool_calls
                ]
            out.append(entry)
        return out

    @staticmethod
    def _to_openai_tools(tools: list[ToolSchema]) -> list[dict] | None:
        if not tools:
            return None
        return [
            {
                "type": "function",
                "function": {
                    "name": t.name,
                    "description": t.description,
                    "parameters": t.parameters,
                },
            }
            for t in tools
        ]

    async def _call(
        self, messages: list[Message], tools: list[ToolSchema] | None
    ) -> ModelResponse:
        self._require_key()
        payload: dict = {"model": self.model_name, "messages": self._to_openai_messages(messages)}
        oa_tools = self._to_openai_tools(tools or [])
        if oa_tools:
            payload["tools"] = oa_tools

        try:
            async with httpx.AsyncClient(timeout=settings.request_timeout_seconds) as client:
                response = await client.post(
                    CHAT_COMPLETIONS_URL, headers=self._headers(), json=payload
                )
        except httpx.TimeoutException as exc:
            raise ProviderError(
                ProviderErrorType.TIMEOUT, "OpenRouter request timed out", self.name
            ) from exc
        except httpx.NetworkError as exc:
            raise ProviderError(ProviderErrorType.NETWORK, str(exc), self.name) from exc

        if response.status_code == 401:
            raise ProviderError(
                ProviderErrorType.AUTHENTICATION, response.text, self.name, retryable=False
            )
        if response.status_code == 429:
            raise ProviderError(ProviderErrorType.QUOTA_EXCEEDED, response.text, self.name)
        if response.status_code >= 500:
            raise ProviderError(ProviderErrorType.NETWORK, response.text, self.name)
        if response.status_code >= 400:
            raise ProviderError(
                ProviderErrorType.INVALID_RESPONSE, response.text, self.name, retryable=False
            )

        try:
            data = response.json()
            choice_message = data["choices"][0]["message"]
        except (KeyError, IndexError, ValueError) as exc:
            raise ProviderError(
                ProviderErrorType.INVALID_RESPONSE, "Malformed OpenRouter response", self.name
            ) from exc

        tool_calls: list[ToolCall] = []
        for tc in choice_message.get("tool_calls") or []:
            fn = tc.get("function", {})
            fn_name = fn.get("name", "")
            raw_args = fn.get("arguments", "")
            try:
                args = json.loads(raw_args) if raw_args else {}
            except (ValueError, TypeError) as exc:
                # Do NOT silently fall back to {} — an empty-but-"valid"
                # argument set would let the orchestrator execute the tool
                # with arguments the model never actually produced. Malformed
                # tool-call arguments are a provider response defect, not a
                # recoverable state: raise typed and non-retryable so the
                # orchestrator never sees — let alone runs — a fabricated
                # ToolCall for this turn.
                raise ProviderError(
                    ProviderErrorType.INVALID_RESPONSE,
                    f"OpenRouter returned malformed tool-call arguments for "
                    f"'{fn_name or '?'}': {raw_args!r}",
                    self.name,
                    retryable=False,
                ) from exc
            tool_calls.append(
                ToolCall.new(name=fn_name, arguments=args, provider_call_id=tc.get("id"))
            )

        return ModelResponse(
            text=choice_message.get("content"),
            tool_calls=tool_calls,
            provider=self.name,
            model=self.model_name,
            raw=data,
        )

    async def generate(self, messages: list[Message]) -> ModelResponse:
        return await self._call(messages, tools=None)

    async def generate_with_tools(
        self, messages: list[Message], tools: list[ToolSchema]
    ) -> ModelResponse:
        return await self._call(messages, tools=tools)

    async def health_check(self) -> bool:
        if not self.api_key:
            return False
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                response = await client.get(MODELS_URL, headers=self._headers())
            return response.status_code == 200
        except Exception:  # noqa: BLE001 — health check is best-effort
            return False
