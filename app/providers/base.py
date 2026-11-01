from __future__ import annotations

from abc import ABC, abstractmethod

from app.providers.schemas import Message, ModelResponse, ToolSchema


class AIProvider(ABC):
    """Common interface every LLM backend must implement.

    JARVIS-X's core never imports a provider-specific type — only this
    interface and the normalized schemas in `schemas.py`. Adding a new
    provider means implementing this class; nothing else changes.
    """

    name: str

    @abstractmethod
    async def generate(self, messages: list[Message]) -> ModelResponse:
        """Plain generation, no tools offered."""
        ...

    @abstractmethod
    async def generate_with_tools(
        self, messages: list[Message], tools: list[ToolSchema]
    ) -> ModelResponse:
        """Generation with tool-calling enabled. May return tool_calls
        instead of (or alongside) text, per the provider's native support."""
        ...

    @abstractmethod
    async def health_check(self) -> bool:
        """Lightweight, explicit check of provider reachability/credentials.
        Never called implicitly before a normal generate() — only at startup
        or when the operator explicitly asks (e.g. a future `/status` CLI
        command)."""
        ...
