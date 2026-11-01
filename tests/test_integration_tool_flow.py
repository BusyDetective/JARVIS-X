"""Provider-agnostic integration tests.

The same `_run_tool_round` function drives Gemini, OpenRouter, and Ollama
below. It is written entirely against AIProvider / Message / ToolCall /
ToolResult — it has no import, branch, or type check for any specific
provider. This demonstrates that JARVIS-X's core can produce a full
ModelResponse -> ToolCall -> ToolResult -> next-request round trip without
ever needing to know which backend actually answered.
"""

from __future__ import annotations

from types import SimpleNamespace

import httpx
import respx

from app.providers.base import AIProvider
from app.providers.gemini import GeminiProvider
from app.providers.ollama import OllamaProvider
from app.providers.openrouter import OpenRouterProvider
from app.providers.schemas import Message, ToolResult, ToolSchema

CALCULATOR_TOOL = ToolSchema(
    name="calculator",
    description="Adds two numbers",
    parameters={
        "type": "object",
        "properties": {"a": {"type": "number"}, "b": {"type": "number"}},
    },
)


async def _run_tool_round(provider: AIProvider, first_messages: list[Message]):
    """Provider-agnostic round: generate_with_tools -> execute -> generate.

    Nothing in this function knows or cares which AIProvider implementation
    it was given — it only ever touches the normalized interface.
    """
    response = await provider.generate_with_tools(first_messages, [CALCULATOR_TOOL])
    assert response.tool_calls, "expected the model to request the calculator tool"
    call = response.tool_calls[0]
    assert call.name == "calculator"

    # Stand-in for a real Tool.run() — operates only on normalized fields.
    computed = call.arguments.get("a", 0) + call.arguments.get("b", 0)
    result = ToolResult(tool_call_id=call.id, name=call.name, success=True, result=computed)

    follow_up = [
        *first_messages,
        Message(role="assistant", content=response.text, tool_calls=response.tool_calls),
        Message(
            role="tool",
            content=str(result.result),
            tool_call_id=result.tool_call_id,
            name=result.name,
        ),
    ]
    final = await provider.generate(follow_up)
    return call, result, final


# --- OpenRouter -------------------------------------------------------------


@respx.mock
async def test_openrouter_provider_agnostic_tool_round_trip():
    respx.post("https://openrouter.ai/api/v1/chat/completions").mock(
        side_effect=[
            httpx.Response(
                200,
                json={
                    "choices": [
                        {
                            "message": {
                                "role": "assistant",
                                "content": None,
                                "tool_calls": [
                                    {
                                        "id": "call_xyz",
                                        "function": {
                                            "name": "calculator",
                                            "arguments": '{"a": 3, "b": 4}',
                                        },
                                    }
                                ],
                            }
                        }
                    ]
                },
            ),
            httpx.Response(
                200,
                json={"choices": [{"message": {"role": "assistant", "content": "The answer is 7."}}]},
            ),
        ]
    )
    provider = OpenRouterProvider(api_key="test-key", model="test-model")
    messages = [Message(role="user", content="what is 3+4?")]

    call, result, final = await _run_tool_round(provider, messages)

    assert call.arguments == {"a": 3, "b": 4}
    assert call.provider_call_id == "call_xyz"
    assert result.result == 7
    assert final.text == "The answer is 7."


# --- Ollama -------------------------------------------------------------


@respx.mock
async def test_ollama_provider_agnostic_tool_round_trip():
    respx.post("http://localhost:11434/api/chat").mock(
        side_effect=[
            httpx.Response(
                200,
                json={
                    "message": {
                        "role": "assistant",
                        "content": None,
                        "tool_calls": [
                            {"function": {"name": "calculator", "arguments": {"a": 3, "b": 4}}}
                        ],
                    }
                },
            ),
            httpx.Response(
                200, json={"message": {"role": "assistant", "content": "The answer is 7."}}
            ),
        ]
    )
    provider = OllamaProvider(base_url="http://localhost:11434", model="llama3.1")
    messages = [Message(role="user", content="what is 3+4?")]

    call, result, final = await _run_tool_round(provider, messages)

    assert call.arguments == {"a": 3, "b": 4}
    assert result.result == 7
    assert final.text == "The answer is 7."


# --- Gemini -------------------------------------------------------------


def _gemini_response(*, text: str | None = None, function_call: dict | None = None):
    parts = []
    if function_call:
        parts.append(
            SimpleNamespace(
                text=None,
                function_call=SimpleNamespace(
                    name=function_call["name"], args=function_call["args"], id=None
                ),
                function_response=None,
            )
        )
    if text is not None:
        parts.append(SimpleNamespace(text=text, function_call=None, function_response=None))
    content = SimpleNamespace(parts=parts)
    return SimpleNamespace(candidates=[SimpleNamespace(content=content)])


class _FakeGeminiModels:
    def __init__(self, responses):
        self._responses = list(responses)
        self.calls: list[dict] = []

    async def generate_content(self, *, model, contents, config):
        self.calls.append({"model": model, "contents": contents, "config": config})
        return self._responses.pop(0)


class _FakeGeminiClient:
    def __init__(self, responses):
        self.aio = SimpleNamespace(models=_FakeGeminiModels(responses))


async def test_gemini_provider_agnostic_tool_round_trip():
    provider = GeminiProvider(api_key="test-key", model="test-model")
    fake_client = _FakeGeminiClient(
        [
            _gemini_response(function_call={"name": "calculator", "args": {"a": 3, "b": 4}}),
            _gemini_response(text="The answer is 7."),
        ]
    )
    provider._client = fake_client  # inject fake transport, same public interface
    messages = [Message(role="user", content="what is 3+4?")]

    call, result, final = await _run_tool_round(provider, messages)

    assert call.arguments == {"a": 3, "b": 4}
    assert result.result == 7
    assert final.text == "The answer is 7."

    # The second request's reconstructed history must carry the real
    # function_call/function_response turns, not a flattened substitute —
    # this is the Gemini-specific guarantee, observed here through the
    # exact same provider-agnostic round-trip every other provider used.
    second_call_contents = fake_client.aio.models.calls[1]["contents"]
    roles = [c.role for c in second_call_contents]
    assert roles == ["user", "model", "user"]
    assert second_call_contents[1].parts[0].function_call.name == "calculator"
    assert second_call_contents[2].parts[0].function_response.name == "calculator"
