from app.providers.schemas import ProviderError, ProviderErrorType, ToolCall


def test_tool_call_ids_are_unique():
    a = ToolCall.new("calculator", {"expr": "1+1"})
    b = ToolCall.new("calculator", {"expr": "1+1"})
    assert a.id != b.id
    assert a.id.startswith("call_")
    assert a.name == "calculator"
    assert a.arguments == {"expr": "1+1"}


def test_tool_call_id_is_normalized_regardless_of_provider_call_id():
    # JARVIS-X mints `id` itself; a provider's own id is only ever stored
    # separately and never substituted in as the normalized id.
    tc = ToolCall.new("calculator", {"expr": "1+1"}, provider_call_id="call_raw_from_provider")
    assert tc.id != "call_raw_from_provider"
    assert tc.id.startswith("call_")
    assert tc.provider_call_id == "call_raw_from_provider"


def test_tool_call_provider_call_id_defaults_to_none():
    tc = ToolCall.new("current_time", {})
    assert tc.provider_call_id is None


def test_provider_error_default_retryable_by_type():
    quota = ProviderError(ProviderErrorType.QUOTA_EXCEEDED, "limit hit", "gemini")
    assert quota.retryable is True

    auth = ProviderError(ProviderErrorType.AUTHENTICATION, "bad key", "gemini")
    assert auth.retryable is False

    invalid = ProviderError(ProviderErrorType.INVALID_RESPONSE, "bad json", "openrouter")
    assert invalid.retryable is False


def test_provider_error_retryable_override():
    err = ProviderError(ProviderErrorType.AUTHENTICATION, "bad key", "gemini", retryable=True)
    assert err.retryable is True


def test_provider_error_message_format():
    err = ProviderError(ProviderErrorType.NETWORK, "connection refused", "ollama")
    assert str(err) == "[ollama] network: connection refused"
