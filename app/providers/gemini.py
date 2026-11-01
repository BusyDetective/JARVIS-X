from __future__ import annotations

import asyncio
import logging

from google import genai
from google.genai import errors as genai_errors
from google.genai import types as genai_types

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


class GeminiProvider(AIProvider):
    """Uses the current `google-genai` SDK (the `google-generativeai`
    package it replaces is fully deprecated/EOL). Native async support via
    `client.aio`, native function-calling via `types.FunctionDeclaration`."""

    name = "gemini"

    def __init__(self, api_key: str | None = None, model: str | None = None) -> None:
        self.api_key = api_key or settings.gemini_api_key
        self.model_name = model or settings.gemini_model
        self._client: genai.Client | None = genai.Client(api_key=self.api_key) if self.api_key else None

    def _require_client(self) -> genai.Client:
        if not self._client:
            raise ProviderError(
                ProviderErrorType.AUTHENTICATION,
                "GEMINI_API_KEY is not configured",
                self.name,
                retryable=False,
            )
        return self._client

    @staticmethod
    def _to_gemini_contents(messages: list[Message]) -> tuple[str | None, list[genai_types.Content]]:
        """Convert internal Messages into Gemini `Content` turns.

        This preserves the exact multi-turn shape Gemini's own SDK uses for
        automatic function calling (see `google.genai.models`, where a
        function-calling turn is replayed as the model's original
        `function_call` content followed by a `user`-role `function_response`
        content):

            user            -> role="user",  Part(text=...)
            assistant        -> role="model", Part(function_call=...) for each
            (with tool_calls)    ToolCall, in order, plus a text Part if the
                                  model also returned text alongside the call(s)
            tool (result)     -> role="user",  Part(function_response=...)

        An assistant tool-call turn is NEVER flattened down to a plain text
        message — the `function_call` part(s) must round-trip unchanged, or
        Gemini has no way to associate the following `function_response`
        with anything, and the conversation becomes incoherent.
        """
        system_instruction: str | None = None
        contents: list[genai_types.Content] = []
        for m in messages:
            if m.role == "system":
                system_instruction = (system_instruction or "") + (m.content or "")
                continue

            if m.role == "tool":
                contents.append(
                    genai_types.Content(
                        role="user",
                        parts=[
                            genai_types.Part(
                                function_response=genai_types.FunctionResponse(
                                    id=m.tool_call_id,
                                    name=m.name or "",
                                    response={"result": m.content},
                                )
                            )
                        ],
                    )
                )
                continue

            if m.role == "assistant":
                parts: list[genai_types.Part] = []
                if m.content:
                    parts.append(genai_types.Part(text=m.content))
                for tc in m.tool_calls:
                    parts.append(
                        genai_types.Part(
                            function_call=genai_types.FunctionCall(
                                id=tc.id, name=tc.name, args=tc.arguments
                            )
                        )
                    )
                if not parts:
                    # An assistant turn must carry at least one part; this
                    # only happens for a genuinely empty assistant message.
                    parts.append(genai_types.Part(text=""))
                contents.append(genai_types.Content(role="model", parts=parts))
                continue

            # role == "user"
            contents.append(
                genai_types.Content(role="user", parts=[genai_types.Part(text=m.content or "")])
            )
        return system_instruction, contents

    @staticmethod
    def _to_gemini_tools(tools: list[ToolSchema]) -> list[genai_types.Tool] | None:
        if not tools:
            return None
        declarations = [
            genai_types.FunctionDeclaration(
                name=t.name, description=t.description, parameters=t.parameters
            )
            for t in tools
        ]
        return [genai_types.Tool(function_declarations=declarations)]

    async def _call(
        self, messages: list[Message], tools: list[ToolSchema] | None
    ) -> ModelResponse:
        client = self._require_client()
        system_instruction, contents = self._to_gemini_contents(messages)
        gemini_tools = self._to_gemini_tools(tools or [])

        config = genai_types.GenerateContentConfig(
            system_instruction=system_instruction,
            tools=gemini_tools,
        )

        try:
            response = await asyncio.wait_for(
                client.aio.models.generate_content(
                    model=self.model_name, contents=contents, config=config
                ),
                timeout=settings.request_timeout_seconds,
            )
        except asyncio.TimeoutError as exc:
            raise ProviderError(
                ProviderErrorType.TIMEOUT, "Gemini request timed out", self.name
            ) from exc
        except genai_errors.ClientError as exc:
            status = getattr(exc, "code", None)
            if status == 401 or status == 403:
                raise ProviderError(
                    ProviderErrorType.AUTHENTICATION, str(exc), self.name, retryable=False
                ) from exc
            if status == 429:
                raise ProviderError(ProviderErrorType.QUOTA_EXCEEDED, str(exc), self.name) from exc
            raise ProviderError(
                ProviderErrorType.INVALID_RESPONSE, str(exc), self.name, retryable=False
            ) from exc
        except genai_errors.ServerError as exc:
            raise ProviderError(ProviderErrorType.NETWORK, str(exc), self.name) from exc
        except genai_errors.APIError as exc:
            raise ProviderError(ProviderErrorType.NETWORK, str(exc), self.name) from exc
        except Exception as exc:  # noqa: BLE001 — unexpected SDK error, surface typed
            raise ProviderError(ProviderErrorType.UNKNOWN, str(exc), self.name) from exc

        try:
            candidate = response.candidates[0]
        except (IndexError, AttributeError, TypeError) as exc:
            raise ProviderError(
                ProviderErrorType.INVALID_RESPONSE, "No candidates in Gemini response", self.name
            ) from exc

        text_parts: list[str] = []
        tool_calls: list[ToolCall] = []
        for part in candidate.content.parts or []:
            if getattr(part, "text", None):
                text_parts.append(part.text)
            fc = getattr(part, "function_call", None)
            if fc and fc.name:
                tool_calls.append(
                    ToolCall.new(
                        name=fc.name,
                        arguments=dict(fc.args or {}),
                        provider_call_id=getattr(fc, "id", None),
                    )
                )

        return ModelResponse(
            text="".join(text_parts) or None,
            tool_calls=tool_calls,
            provider=self.name,
            model=self.model_name,
            raw=response,
        )

    async def generate(self, messages: list[Message]) -> ModelResponse:
        return await self._call(messages, tools=None)

    async def generate_with_tools(
        self, messages: list[Message], tools: list[ToolSchema]
    ) -> ModelResponse:
        return await self._call(messages, tools=tools)

    async def health_check(self) -> bool:
        if not self._client:
            return False
        try:
            await asyncio.wait_for(
                self._client.aio.models.list(),
                timeout=5.0,
            )
            return True
        except Exception:  # noqa: BLE001 — health check is best-effort
            return False
