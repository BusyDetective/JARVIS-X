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


class OllamaProvider(AIProvider):
    """Local, optional provider. Must never prevent cloud providers from
    working when Ollama isn't installed/running — failures here are plain
    NETWORK errors the ModelRouter can route around."""

    name = "ollama"

    def __init__(self, base_url: str | None = None, model: str | None = None) -> None:
        self.base_url = (base_url or settings.ollama_base_url).rstrip("/")
        self.model_name = model or settings.ollama_model

    @staticmethod
    def _to_ollama_messages(messages: list[Message]) -> list[dict]:
        out: list[dict] = []
        for m in messages:
            if m.role == "tool":
                out.append({"role": "tool", "content": m.content or ""})
                continue
            entry: dict = {"role": m.role, "content": m.content or ""}
            if m.tool_calls:
                entry["tool_calls"] = [
                    {"function": {"name": tc.name, "arguments": tc.arguments}}
                    for tc in m.tool_calls
                ]
            out.append(entry)
        return out

    @staticmethod
    def _to_ollama_tools(tools: list[ToolSchema]) -> list[dict] | None:
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
        payload: dict = {
            "model": self.model_name,
            "messages": self._to_ollama_messages(messages),
            "stream": False,
        }
        ol_tools = self._to_ollama_tools(tools or [])
        if ol_tools:
            payload["tools"] = ol_tools

        try:
            async with httpx.AsyncClient(timeout=settings.request_timeout_seconds) as client:
                response = await client.post(f"{self.base_url}/api/chat", json=payload)
        except httpx.TimeoutException as exc:
            raise ProviderError(
                ProviderErrorType.TIMEOUT, "Ollama request timed out", self.name
            ) from exc
        except httpx.ConnectError as exc:
            raise ProviderError(
                ProviderErrorType.NETWORK, f"Cannot reach Ollama at {self.base_url}", self.name
            ) from exc
        except httpx.NetworkError as exc:
            raise ProviderError(ProviderErrorType.NETWORK, str(exc), self.name) from exc

        if response.status_code == 404:
            raise ProviderError(
                ProviderErrorType.INVALID_RESPONSE,
                f"Model '{self.model_name}' not found locally "
                f"(try `ollama pull {self.model_name}`)",
                self.name,
                retryable=False,
            )
        if response.status_code >= 500:
            raise ProviderError(ProviderErrorType.NETWORK, response.text, self.name)
        if response.status_code >= 400:
            raise ProviderError(
                ProviderErrorType.INVALID_RESPONSE, response.text, self.name, retryable=False
            )

        try:
            data = response.json()
            message = data["message"]
        except (KeyError, ValueError) as exc:
            raise ProviderError(
                ProviderErrorType.INVALID_RESPONSE, "Malformed Ollama response", self.name
            ) from exc

        tool_calls: list[ToolCall] = []
        for tc in message.get("tool_calls") or []:
            fn = tc.get("function", {})
            fn_name = fn.get("name", "")
            raw_args = fn.get("arguments", {})
            if isinstance(raw_args, str):
                try:
                    args = json.loads(raw_args) if raw_args else {}
                except (ValueError, TypeError) as exc:
                    # Do NOT silently fall back to {} — see the identical
                    # guard in openrouter.py. A malformed argument string is
                    # a provider response defect, not a recoverable state:
                    # raise typed and non-retryable so the orchestrator
                    # never executes a tool with fabricated arguments.
                    raise ProviderError(
                        ProviderErrorType.INVALID_RESPONSE,
                        f"Ollama returned malformed tool-call arguments for "
                        f"'{fn_name or '?'}': {raw_args!r}",
                        self.name,
                        retryable=False,
                    ) from exc
            elif isinstance(raw_args, dict):
                args = raw_args
            else:
                raise ProviderError(
                    ProviderErrorType.INVALID_RESPONSE,
                    f"Ollama returned tool-call arguments of unexpected type "
                    f"{type(raw_args).__name__} for '{fn_name or '?'}': {raw_args!r}",
                    self.name,
                    retryable=False,
                )
            tool_calls.append(
                ToolCall.new(name=fn_name, arguments=args, provider_call_id=tc.get("id"))
            )

        return ModelResponse(
            text=message.get("content") or None,
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
        try:
            async with httpx.AsyncClient(timeout=3.0) as client:
                response = await client.get(f"{self.base_url}/api/tags")
            return response.status_code == 200
        except Exception:  # noqa: BLE001 — health check is best-effort
            return False
