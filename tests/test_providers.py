import httpx
import pytest
import respx

from app.providers.ollama import OllamaProvider
from app.providers.openrouter import OpenRouterProvider
from app.providers.schemas import Message, ProviderError, ProviderErrorType, ToolCall, ToolSchema


# --- OpenRouter: message/tool conversion (no network) ---------------------


def test_openrouter_message_conversion_includes_tool_calls():
    tc = ToolCall.new("current_time", {})
    messages = [
        Message(role="user", content="what time is it?"),
        Message(role="assistant", content=None, tool_calls=[tc]),
        Message(role="tool", content="12:00", tool_call_id=tc.id, name="current_time"),
    ]
    converted = OpenRouterProvider._to_openai_messages(messages)
    assert converted[1]["tool_calls"][0]["id"] == tc.id
    assert converted[1]["tool_calls"][0]["function"]["name"] == "current_time"
    assert converted[2]["role"] == "tool"
    assert converted[2]["tool_call_id"] == tc.id


def test_openrouter_tool_schema_conversion():
    tools = [ToolSchema(name="calculator", description="adds numbers", parameters={"type": "object"})]
    converted = OpenRouterProvider._to_openai_tools(tools)
    assert converted[0]["type"] == "function"
    assert converted[0]["function"]["name"] == "calculator"


def test_openrouter_requires_api_key():
    provider = OpenRouterProvider(api_key=None)
    with pytest.raises(ProviderError) as exc_info:
        import asyncio

        asyncio.run(provider.generate([Message(role="user", content="hi")]))
    assert exc_info.value.error_type == ProviderErrorType.AUTHENTICATION
    assert exc_info.value.retryable is False


# --- OpenRouter: HTTP behavior (mocked) ------------------------------------


@respx.mock
async def test_openrouter_generate_success():
    respx.post("https://openrouter.ai/api/v1/chat/completions").mock(
        return_value=httpx.Response(
            200, json={"choices": [{"message": {"role": "assistant", "content": "Hello!"}}]}
        )
    )
    provider = OpenRouterProvider(api_key="test-key", model="test-model")
    result = await provider.generate([Message(role="user", content="hi")])
    assert result.text == "Hello!"
    assert result.provider == "openrouter"
    assert result.tool_calls == []


@respx.mock
async def test_openrouter_generate_with_tool_call():
    respx.post("https://openrouter.ai/api/v1/chat/completions").mock(
        return_value=httpx.Response(
            200,
            json={
                "choices": [
                    {
                        "message": {
                            "role": "assistant",
                            "content": None,
                            "tool_calls": [
                                {
                                    "id": "call_abc123",
                                    "function": {
                                        "name": "calculator",
                                        "arguments": '{"expr": "2+2"}',
                                    },
                                }
                            ],
                        }
                    }
                ]
            },
        )
    )
    provider = OpenRouterProvider(api_key="test-key", model="test-model")
    tools = [
        ToolSchema(name="calculator", description="adds numbers", parameters={"type": "object"})
    ]
    result = await provider.generate_with_tools([Message(role="user", content="2+2?")], tools)
    assert len(result.tool_calls) == 1
    tc = result.tool_calls[0]
    # `id` is JARVIS-X's own normalized identifier, not OpenRouter's raw id —
    # the rest of the app must never depend on a provider-specific id.
    assert tc.id != "call_abc123"
    assert tc.id.startswith("call_")
    assert tc.provider_call_id == "call_abc123"
    assert tc.name == "calculator"
    assert tc.arguments == {"expr": "2+2"}


@respx.mock
async def test_openrouter_malformed_tool_arguments_raises_invalid_response():
    respx.post("https://openrouter.ai/api/v1/chat/completions").mock(
        return_value=httpx.Response(
            200,
            json={
                "choices": [
                    {
                        "message": {
                            "role": "assistant",
                            "content": None,
                            "tool_calls": [
                                {
                                    "id": "call_bad",
                                    "function": {
                                        "name": "calculator",
                                        "arguments": "{not valid json",
                                    },
                                }
                            ],
                        }
                    }
                ]
            },
        )
    )
    provider = OpenRouterProvider(api_key="test-key", model="test-model")
    tools = [
        ToolSchema(name="calculator", description="adds numbers", parameters={"type": "object"})
    ]
    with pytest.raises(ProviderError) as exc_info:
        await provider.generate_with_tools([Message(role="user", content="2+2?")], tools)
    assert exc_info.value.error_type == ProviderErrorType.INVALID_RESPONSE
    assert exc_info.value.retryable is False


@respx.mock
async def test_openrouter_auth_error_is_typed():
    respx.post("https://openrouter.ai/api/v1/chat/completions").mock(
        return_value=httpx.Response(401, text="unauthorized")
    )
    provider = OpenRouterProvider(api_key="bad-key", model="test-model")
    with pytest.raises(ProviderError) as exc_info:
        await provider.generate([Message(role="user", content="hi")])
    assert exc_info.value.error_type == ProviderErrorType.AUTHENTICATION


@respx.mock
async def test_openrouter_rate_limit_is_typed():
    respx.post("https://openrouter.ai/api/v1/chat/completions").mock(
        return_value=httpx.Response(429, text="rate limited")
    )
    provider = OpenRouterProvider(api_key="test-key", model="test-model")
    with pytest.raises(ProviderError) as exc_info:
        await provider.generate([Message(role="user", content="hi")])
    assert exc_info.value.error_type == ProviderErrorType.QUOTA_EXCEEDED
    assert exc_info.value.retryable is True


@respx.mock
async def test_openrouter_malformed_response_is_typed():
    respx.post("https://openrouter.ai/api/v1/chat/completions").mock(
        return_value=httpx.Response(200, json={"unexpected": "shape"})
    )
    provider = OpenRouterProvider(api_key="test-key", model="test-model")
    with pytest.raises(ProviderError) as exc_info:
        await provider.generate([Message(role="user", content="hi")])
    assert exc_info.value.error_type == ProviderErrorType.INVALID_RESPONSE


# --- Ollama: HTTP behavior (mocked) ----------------------------------------


@respx.mock
async def test_ollama_generate_success():
    respx.post("http://localhost:11434/api/chat").mock(
        return_value=httpx.Response(
            200, json={"message": {"role": "assistant", "content": "hi there"}}
        )
    )
    provider = OllamaProvider(base_url="http://localhost:11434", model="llama3.1")
    result = await provider.generate([Message(role="user", content="hello")])
    assert result.text == "hi there"
    assert result.provider == "ollama"


@respx.mock
async def test_ollama_connection_error_is_network_type():
    respx.post("http://localhost:11434/api/chat").mock(side_effect=httpx.ConnectError("refused"))
    provider = OllamaProvider(base_url="http://localhost:11434", model="llama3.1")
    with pytest.raises(ProviderError) as exc_info:
        await provider.generate([Message(role="user", content="hi")])
    assert exc_info.value.error_type == ProviderErrorType.NETWORK
    assert exc_info.value.retryable is True


@respx.mock
async def test_ollama_model_not_found_is_not_retryable():
    respx.post("http://localhost:11434/api/chat").mock(
        return_value=httpx.Response(404, text="model not found")
    )
    provider = OllamaProvider(base_url="http://localhost:11434", model="nonexistent-model")
    with pytest.raises(ProviderError) as exc_info:
        await provider.generate([Message(role="user", content="hi")])
    assert exc_info.value.error_type == ProviderErrorType.INVALID_RESPONSE
    assert exc_info.value.retryable is False


@respx.mock
async def test_ollama_generate_with_tool_call():
    respx.post("http://localhost:11434/api/chat").mock(
        return_value=httpx.Response(
            200,
            json={
                "message": {
                    "role": "assistant",
                    "content": None,
                    "tool_calls": [
                        {"function": {"name": "current_time", "arguments": {}}},
                    ],
                }
            },
        )
    )
    provider = OllamaProvider(base_url="http://localhost:11434", model="llama3.1")
    tools = [ToolSchema(name="current_time", description="returns time", parameters={"type": "object"})]
    result = await provider.generate_with_tools([Message(role="user", content="what time?")], tools)
    assert len(result.tool_calls) == 1
    assert result.tool_calls[0].name == "current_time"
    assert result.tool_calls[0].id.startswith("call_")


@respx.mock
async def test_ollama_tool_call_with_valid_json_string_arguments():
    respx.post("http://localhost:11434/api/chat").mock(
        return_value=httpx.Response(
            200,
            json={
                "message": {
                    "role": "assistant",
                    "content": None,
                    "tool_calls": [
                        {
                            "id": "ollama_call_1",
                            "function": {
                                "name": "calculator",
                                "arguments": '{"a": 3, "b": 4}',
                            },
                        }
                    ],
                }
            },
        )
    )
    provider = OllamaProvider(base_url="http://localhost:11434", model="llama3.1")
    tools = [ToolSchema(name="calculator", description="adds numbers", parameters={"type": "object"})]
    result = await provider.generate_with_tools([Message(role="user", content="3+4?")], tools)

    assert len(result.tool_calls) == 1
    tc = result.tool_calls[0]
    assert tc.name == "calculator"
    assert tc.arguments == {"a": 3, "b": 4}


@respx.mock
async def test_ollama_tool_call_with_already_parsed_dict_arguments():
    # Ollama's /api/chat commonly returns arguments as an already-parsed
    # dict rather than a JSON string — this must work without any json.loads.
    respx.post("http://localhost:11434/api/chat").mock(
        return_value=httpx.Response(
            200,
            json={
                "message": {
                    "role": "assistant",
                    "content": None,
                    "tool_calls": [
                        {
                            "id": "ollama_call_2",
                            "function": {"name": "calculator", "arguments": {"a": 5, "b": 6}},
                        }
                    ],
                }
            },
        )
    )
    provider = OllamaProvider(base_url="http://localhost:11434", model="llama3.1")
    tools = [ToolSchema(name="calculator", description="adds numbers", parameters={"type": "object"})]
    result = await provider.generate_with_tools([Message(role="user", content="5+6?")], tools)

    assert len(result.tool_calls) == 1
    tc = result.tool_calls[0]
    assert tc.name == "calculator"
    assert tc.arguments == {"a": 5, "b": 6}


@respx.mock
async def test_ollama_malformed_tool_arguments_raises_invalid_response():
    respx.post("http://localhost:11434/api/chat").mock(
        return_value=httpx.Response(
            200,
            json={
                "message": {
                    "role": "assistant",
                    "content": None,
                    "tool_calls": [
                        {
                            "id": "ollama_call_bad",
                            "function": {
                                "name": "calculator",
                                "arguments": "{not valid json",
                            },
                        }
                    ],
                }
            },
        )
    )
    provider = OllamaProvider(base_url="http://localhost:11434", model="llama3.1")
    tools = [ToolSchema(name="calculator", description="adds numbers", parameters={"type": "object"})]
    with pytest.raises(ProviderError) as exc_info:
        await provider.generate_with_tools([Message(role="user", content="2+2?")], tools)
    assert exc_info.value.error_type == ProviderErrorType.INVALID_RESPONSE
    assert exc_info.value.retryable is False


@respx.mock
async def test_ollama_tool_call_id_is_normalized_and_preserves_provider_call_id():
    respx.post("http://localhost:11434/api/chat").mock(
        return_value=httpx.Response(
            200,
            json={
                "message": {
                    "role": "assistant",
                    "content": None,
                    "tool_calls": [
                        {
                            "id": "ollama_raw_id_123",
                            "function": {"name": "calculator", "arguments": {"a": 1, "b": 2}},
                        }
                    ],
                }
            },
        )
    )
    provider = OllamaProvider(base_url="http://localhost:11434", model="llama3.1")
    tools = [ToolSchema(name="calculator", description="adds numbers", parameters={"type": "object"})]
    result = await provider.generate_with_tools([Message(role="user", content="1+2?")], tools)

    tc = result.tool_calls[0]
    # `id` is JARVIS-X's own normalized identifier, never the provider's raw id.
    assert tc.id != "ollama_raw_id_123"
    assert tc.id.startswith("call_")
    assert tc.provider_call_id == "ollama_raw_id_123"


@respx.mock
async def test_ollama_tool_call_without_provider_id_has_none_provider_call_id():
    # Ollama frequently omits an id on tool_calls entirely — provider_call_id
    # must gracefully default to None rather than error.
    respx.post("http://localhost:11434/api/chat").mock(
        return_value=httpx.Response(
            200,
            json={
                "message": {
                    "role": "assistant",
                    "content": None,
                    "tool_calls": [
                        {"function": {"name": "current_time", "arguments": {}}},
                    ],
                }
            },
        )
    )
    provider = OllamaProvider(base_url="http://localhost:11434", model="llama3.1")
    tools = [ToolSchema(name="current_time", description="returns time", parameters={"type": "object"})]
    result = await provider.generate_with_tools([Message(role="user", content="time?")], tools)

    assert result.tool_calls[0].provider_call_id is None
