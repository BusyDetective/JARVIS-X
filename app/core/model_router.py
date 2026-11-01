from __future__ import annotations

import logging

from app.config.settings import settings
from app.providers.base import AIProvider
from app.providers.schemas import Message, ModelResponse, ProviderError, ProviderErrorType, ToolSchema

logger = logging.getLogger(__name__)

# Error types that justify trying the next provider in the chain.
# Deliberately includes AUTHENTICATION: a missing/invalid key for one
# provider should not crash the whole system if another provider is
# configured — it should just move on. INVALID_RESPONSE and
# UNSUPPORTED_FEATURE are NOT fallback-eligible: those indicate a real
# problem (bad request shape, provider genuinely can't do this) rather than
# "try someone else", and are surfaced immediately instead of being masked.
FALLBACK_ELIGIBLE = {
    ProviderErrorType.QUOTA_EXCEEDED,
    ProviderErrorType.TIMEOUT,
    ProviderErrorType.NETWORK,
    ProviderErrorType.AUTHENTICATION,
}


class AllProvidersFailedError(Exception):
    """Raised when every provider in the configured chain failed."""

    def __init__(self, attempts: list[ProviderError]) -> None:
        self.attempts = attempts
        summary = "; ".join(f"{e.provider}: {e.error_type.value}" for e in attempts)
        super().__init__(f"All configured providers failed: {summary}")


class ModelRouter:
    """Selects a provider and falls back on failure.

    Does NOT run a health check before every request — that would add an
    unnecessary API call to every single generation. Instead it tries the
    preferred provider directly and only consults the next one if the
    attempt actually fails with a fallback-eligible error. Use
    `health_check_all()` explicitly (e.g. at startup or a `/status` command)
    when you actually want to probe availability.
    """

    def __init__(self, providers: dict[str, AIProvider], order: list[str] | None = None) -> None:
        self.providers = providers
        self.order = order or settings.provider_order_list
        unknown = [name for name in self.order if name not in self.providers]
        if unknown:
            raise ValueError(f"provider_order references unknown providers: {unknown}")

    def _chain(self) -> list[AIProvider]:
        return [self.providers[name] for name in self.order]

    async def generate(self, messages: list[Message]) -> ModelResponse:
        return await self._run("generate", messages)

    async def generate_with_tools(
        self, messages: list[Message], tools: list[ToolSchema]
    ) -> ModelResponse:
        return await self._run("generate_with_tools", messages, tools)

    async def _run(
        self,
        method: str,
        messages: list[Message],
        tools: list[ToolSchema] | None = None,
    ) -> ModelResponse:
        attempts: list[ProviderError] = []
        for provider in self._chain():
            try:
                if method == "generate":
                    logger.info("model_router: attempting provider=%s", provider.name)
                    return await provider.generate(messages)
                logger.info("model_router: attempting provider=%s (with tools)", provider.name)
                return await provider.generate_with_tools(messages, tools or [])
            except ProviderError as exc:
                attempts.append(exc)
                if exc.error_type in FALLBACK_ELIGIBLE:
                    logger.warning(
                        "model_router: provider=%s failed (%s), falling back",
                        provider.name,
                        exc.error_type.value,
                    )
                    continue
                logger.error(
                    "model_router: provider=%s failed with non-fallback error (%s)",
                    provider.name,
                    exc.error_type.value,
                )
                raise
        raise AllProvidersFailedError(attempts)

    async def health_check_all(self) -> dict[str, bool]:
        """Explicit, on-demand health check across every configured
        provider. Never called implicitly before a generation request."""
        results: dict[str, bool] = {}
        for name, provider in self.providers.items():
            results[name] = await provider.health_check()
        return results

    def active_chain_description(self) -> str:
        return " -> ".join(self.order)
