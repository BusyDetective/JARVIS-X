import pytest

from app.core.model_router import AllProvidersFailedError, ModelRouter
from app.providers.base import AIProvider
from app.providers.schemas import Message, ModelResponse, ProviderError, ProviderErrorType


class FakeProvider(AIProvider):
    """Minimal AIProvider for exercising ModelRouter without real network calls."""

    def __init__(self, name: str, fail_with: ProviderError | None = None, text: str = "ok"):
        self.name = name
        self._fail_with = fail_with
        self._text = text
        self.calls = 0

    async def generate(self, messages):
        self.calls += 1
        if self._fail_with:
            raise self._fail_with
        return ModelResponse(text=self._text, provider=self.name)

    async def generate_with_tools(self, messages, tools):
        return await self.generate(messages)

    async def health_check(self):
        return self._fail_with is None


def test_router_rejects_unknown_provider_in_order():
    gemini = FakeProvider("gemini")
    with pytest.raises(ValueError):
        ModelRouter({"gemini": gemini}, order=["gemini", "nonexistent"])


def test_active_chain_description():
    gemini, openrouter, ollama = FakeProvider("gemini"), FakeProvider("openrouter"), FakeProvider("ollama")
    router = ModelRouter(
        {"gemini": gemini, "openrouter": openrouter, "ollama": ollama},
        order=["gemini", "openrouter", "ollama"],
    )
    assert router.active_chain_description() == "gemini -> openrouter -> ollama"


async def test_router_uses_preferred_provider_when_it_succeeds():
    gemini = FakeProvider("gemini")
    openrouter = FakeProvider("openrouter")
    router = ModelRouter({"gemini": gemini, "openrouter": openrouter}, order=["gemini", "openrouter"])
    result = await router.generate([Message(role="user", content="hi")])
    assert result.provider == "gemini"
    assert gemini.calls == 1
    assert openrouter.calls == 0


async def test_router_falls_back_on_quota_exceeded():
    gemini = FakeProvider(
        "gemini", fail_with=ProviderError(ProviderErrorType.QUOTA_EXCEEDED, "limit", "gemini")
    )
    openrouter = FakeProvider("openrouter")
    router = ModelRouter({"gemini": gemini, "openrouter": openrouter}, order=["gemini", "openrouter"])
    result = await router.generate([Message(role="user", content="hi")])
    assert result.provider == "openrouter"
    assert gemini.calls == 1
    assert openrouter.calls == 1


async def test_router_falls_back_on_missing_credentials():
    gemini = FakeProvider(
        "gemini",
        fail_with=ProviderError(
            ProviderErrorType.AUTHENTICATION, "no key configured", "gemini", retryable=False
        ),
    )
    ollama = FakeProvider("ollama")
    router = ModelRouter({"gemini": gemini, "ollama": ollama}, order=["gemini", "ollama"])
    result = await router.generate([Message(role="user", content="hi")])
    assert result.provider == "ollama"


async def test_router_does_not_fall_back_on_invalid_response():
    gemini = FakeProvider(
        "gemini", fail_with=ProviderError(ProviderErrorType.INVALID_RESPONSE, "bad json", "gemini")
    )
    ollama = FakeProvider("ollama")
    router = ModelRouter({"gemini": gemini, "ollama": ollama}, order=["gemini", "ollama"])
    with pytest.raises(ProviderError) as exc_info:
        await router.generate([Message(role="user", content="hi")])
    assert exc_info.value.error_type == ProviderErrorType.INVALID_RESPONSE
    assert ollama.calls == 0


async def test_router_raises_when_every_provider_fails():
    gemini = FakeProvider(
        "gemini", fail_with=ProviderError(ProviderErrorType.NETWORK, "down", "gemini")
    )
    openrouter = FakeProvider(
        "openrouter", fail_with=ProviderError(ProviderErrorType.NETWORK, "down", "openrouter")
    )
    router = ModelRouter({"gemini": gemini, "openrouter": openrouter}, order=["gemini", "openrouter"])
    with pytest.raises(AllProvidersFailedError) as exc_info:
        await router.generate([Message(role="user", content="hi")])
    assert len(exc_info.value.attempts) == 2


async def test_router_health_check_all_is_explicit_and_separate_from_generate():
    gemini = FakeProvider("gemini")
    broken = FakeProvider(
        "openrouter", fail_with=ProviderError(ProviderErrorType.AUTHENTICATION, "no key", "openrouter")
    )
    router = ModelRouter({"gemini": gemini, "openrouter": broken}, order=["gemini", "openrouter"])
    results = await router.health_check_all()
    assert results == {"gemini": True, "openrouter": False}
    # health_check_all must not itself have triggered generate() calls
    assert gemini.calls == 0
    assert broken.calls == 0
