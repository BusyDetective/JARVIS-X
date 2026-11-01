"""Tests for GeminiProvider's internal Message -> Gemini Content conversion.

These specifically guard the multi-turn tool-calling sequence:

    user -> model(function_call) -> user(function_response) -> ...

The previous assistant tool-call turn must preserve the real function_call
part(s) (name + arguments). It must NEVER be flattened to an empty/plain
text message, or Gemini has nothing to associate the following
function_response with.
"""

from __future__ import annotations

from app.providers.gemini import GeminiProvider
from app.providers.schemas import Message, ToolCall


def test_plain_user_then_assistant_turn_has_no_function_parts():
    messages = [
        Message(role="user", content="hi"),
        Message(role="assistant", content="hello!"),
    ]
    _, contents = GeminiProvider._to_gemini_contents(messages)

    assert len(contents) == 2
    assert contents[0].role == "user"
    assert contents[0].parts[0].text == "hi"
    assert contents[1].role == "model"
    assert contents[1].parts[0].text == "hello!"
    assert contents[1].parts[0].function_call is None


def test_full_tool_call_sequence_preserves_function_call_and_response():
    call = ToolCall.new("calculator", {"a": 3, "b": 4})
    messages = [
        Message(role="user", content="what is 3+4?"),
        Message(role="assistant", content=None, tool_calls=[call]),
        Message(role="tool", content="7", tool_call_id=call.id, name="calculator"),
    ]
    system, contents = GeminiProvider._to_gemini_contents(messages)

    assert system is None
    assert len(contents) == 3

    # Turn 1: the user's question
    assert contents[0].role == "user"
    assert contents[0].parts[0].text == "what is 3+4?"

    # Turn 2: the model's ORIGINAL function_call turn — must be preserved,
    # not reduced to empty/plain text.
    assert contents[1].role == "model"
    fc_parts = [p for p in contents[1].parts if p.function_call is not None]
    assert len(fc_parts) == 1
    assert fc_parts[0].function_call.name == "calculator"
    assert dict(fc_parts[0].function_call.args) == {"a": 3, "b": 4}
    # No stray empty text part where the call should be.
    assert not any(p.text == "" for p in contents[1].parts)

    # Turn 3: the corresponding function_response, correctly ordered after
    # the function_call it answers.
    assert contents[2].role == "user"
    fr_parts = [p for p in contents[2].parts if p.function_response is not None]
    assert len(fr_parts) == 1
    assert fr_parts[0].function_response.name == "calculator"
    assert fr_parts[0].function_response.response == {"result": "7"}


def test_assistant_turn_preserves_text_alongside_function_call():
    call = ToolCall.new("calculator", {"a": 1, "b": 2})
    messages = [
        Message(role="user", content="add 1 and 2"),
        Message(role="assistant", content="Let me calculate that.", tool_calls=[call]),
    ]
    _, contents = GeminiProvider._to_gemini_contents(messages)

    assert contents[1].role == "model"
    texts = [p.text for p in contents[1].parts if p.text]
    assert texts == ["Let me calculate that."]
    fc_names = [p.function_call.name for p in contents[1].parts if p.function_call]
    assert fc_names == ["calculator"]


def test_multiple_function_calls_and_responses_preserve_order():
    call_a = ToolCall.new("calculator", {"a": 1, "b": 1})
    call_b = ToolCall.new("current_time", {})
    messages = [
        Message(role="user", content="do two things"),
        Message(role="assistant", content=None, tool_calls=[call_a, call_b]),
        Message(role="tool", content="2", tool_call_id=call_a.id, name="calculator"),
        Message(role="tool", content="12:00", tool_call_id=call_b.id, name="current_time"),
    ]
    _, contents = GeminiProvider._to_gemini_contents(messages)

    assert len(contents) == 4
    assert contents[1].role == "model"
    names_in_order = [p.function_call.name for p in contents[1].parts if p.function_call]
    assert names_in_order == ["calculator", "current_time"]

    assert contents[2].role == "user"
    assert contents[2].parts[0].function_response.name == "calculator"
    assert contents[2].parts[0].function_response.response == {"result": "2"}

    assert contents[3].role == "user"
    assert contents[3].parts[0].function_response.name == "current_time"
    assert contents[3].parts[0].function_response.response == {"result": "12:00"}


def test_multi_turn_sequence_continues_after_function_response():
    """user -> function_call -> function_response -> user -> model(final text)

    Verifies the reconstructed history stays coherent for a second round of
    reasoning after the tool result has already been incorporated once.
    """
    call = ToolCall.new("calculator", {"a": 3, "b": 4})
    messages = [
        Message(role="user", content="what is 3+4?"),
        Message(role="assistant", content=None, tool_calls=[call]),
        Message(role="tool", content="7", tool_call_id=call.id, name="calculator"),
        Message(role="assistant", content="The answer is 7."),
        Message(role="user", content="now multiply that by 2"),
    ]
    _, contents = GeminiProvider._to_gemini_contents(messages)

    roles = [c.role for c in contents]
    assert roles == ["user", "model", "user", "model", "user"]
    assert contents[1].parts[0].function_call.name == "calculator"
    assert contents[2].parts[0].function_response.name == "calculator"
    assert contents[3].parts[0].text == "The answer is 7."
    assert contents[3].parts[0].function_call is None
    assert contents[4].parts[0].text == "now multiply that by 2"
