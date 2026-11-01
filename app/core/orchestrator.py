from __future__ import annotations

import asyncio
import json
import logging
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from pydantic import ValidationError

from app.config.settings import settings
from app.context.manager import ContextManager, context_bundle_to_messages
from app.context.models import ContextItem, ContextPriority, ContextSource
from app.core.model_router import AllProvidersFailedError, ModelRouter
from app.providers.schemas import Message, ProviderError, ToolCall, ToolResult
from app.security.approval import ApprovalHandler
from app.sessions.manager import ConversationManager
from app.security.permissions import PermissionLevel, requires_approval
from app.tasks.manager import TaskManager
from app.tasks.models import Task
from app.tools.registry import ToolRegistry

logger = logging.getLogger(__name__)


class TaskStatus(str, Enum):
    """Outcome of an orchestrator run, for CLI/UI display and control flow.

    Deliberately lightweight — this is NOT the persisted Task/SQLite
    system described in the long-term architecture (that's a later
    phase). It's just enough structure for `OrchestratorResult` to be
    meaningful on its own.
    """

    COMPLETED = "completed"
    FAILED = "failed"
    MAX_ITERATIONS_REACHED = "max_iterations_reached"
    MAX_TOOL_CALLS_REACHED = "max_tool_calls_reached"


@dataclass
class OrchestratorResult:
    """What `Orchestrator.run()` returns. A normalized object — never a
    bare dict — so a future CLI/UI has a stable shape to render.

    `tool_calls` uses the canonical `ToolResult` (from
    `app.providers.schemas`) for every tool call processed during the run
    — whether it actually executed, was denied, was blocked, failed
    validation, or errored. There is deliberately no separate
    orchestrator-local result type competing with `ToolResult`; it already
    carries everything needed (`tool_call_id`, `name`, `success`, `result`,
    `error`, `arguments`), keyed by the normalized `ToolCall.id`.
    """

    status: TaskStatus
    final_response: str | None
    provider: str | None
    model: str | None
    tool_calls: list[ToolResult] = field(default_factory=list)
    iterations: int = 0
    error: str | None = None


def _serialize_tool_output(result: ToolResult) -> str:
    """Render a ToolResult's outcome as the string content of a tool-role
    Message.

    Always a JSON object so the model can parse it uniformly; `result` may
    itself be a string, dict, list, number, or None — json.dumps handles
    all of those directly. `default=str` is a last-resort fallback for any
    type that isn't natively JSON-serializable, so a tool's unusual return
    value can never crash the loop.
    """
    if result.success:
        payload: dict[str, Any] = {"success": True, "result": result.result}
    else:
        payload = {"success": False, "error": result.error}
    return json.dumps(payload, default=str)


class Orchestrator:
    """The provider-agnostic agent execution loop.

    USER REQUEST -> context -> ModelRouter -> ModelResponse
       -> tool calls? no -> final response
       -> tool calls? yes -> for each: lookup -> validate -> permission
          check -> (approval if required) -> execute with timeout ->
          ToolResult -> append to context -> repeat

    This class deliberately knows NOTHING about which AIProvider answered
    a request. It only ever touches:

      - ModelRouter (not any concrete AIProvider)
      - Message / ModelResponse / ToolCall / ToolSchema (normalized schemas)
      - ToolRegistry (not any concrete Tool)
      - ApprovalHandler (not any concrete UI/CLI)

    No Gemini/OpenRouter/Ollama-specific logic, HTTP code, or API keys
    belong here, and none exist here — see test_orchestrator.py's static
    source check.

    PERSISTENCE (optional): an injected `task_manager` (`TaskManager`) adds
    durable task tracking around the same loop, without changing its
    control flow. When `task_manager` is None (the default), `run()`
    behaves exactly as before — fully in-memory, no database touched, so
    every existing orchestrator test keeps working unmodified. When
    supplied, `run()`:

      1. creates and persists a Task, then marks it RUNNING,
      2. creates exactly one TaskRun per iteration (one model round-trip),
         status=RUNNING with started_at set immediately BEFORE that
         iteration's model call — then updates that same run (never a new
         one) to COMPLETED or FAILED once the call returns or raises,
      3. records every ToolResult against that iteration's TaskRun,
      4. maps the final OrchestratorResult onto the Task's terminal
         status — COMPLETED stays COMPLETED; FAILED,
         MAX_ITERATIONS_REACHED, and MAX_TOOL_CALLS_REACHED all map to the
         Task life-cycle's FAILED (it has no partial/limit-reached state),
      5. on a genuinely unexpected exception (not a typed provider error or
         a tool failure — both are already handled as controlled results),
         makes a best-effort attempt to mark the active TaskRun FAILED,
         then does the same for the Task, before re-raising the original
         exception unchanged.

    Persistence logic lives only in this optional layer — the provider
    layer and ToolRegistry/Tool abstraction know nothing about it.

    CONTEXT (optional): an injected `context_manager` (`ContextManager`)
    replaces how the SEED messages for a run are built — see
    `_build_seed_messages`. With none (the default), it's the original
    system+user Message pair. With one, system instructions, this
    request, and any relevant long-term memory are assembled into a
    ContextBundle and converted to Messages instead. This affects ONLY
    the starting messages; the iteration loop, tool-call handling, and
    TaskRun persistence that follow are identical either way and
    completely unaware context management exists.

    CONVERSATIONS (optional): an injected `conversation_manager` makes
    `run(..., conversation_id=...)` persist the exchange. Per run:

      1. the incoming user message is persisted FIRST (so it survives any
         later failure),
      2. context is built FROM the persisted history (which already
         contains that message — it is never passed to the context layer a
         second time),
      3. each assistant turn that requests tools is persisted BEFORE its
         tools run (content + tool calls in metadata); each tool outcome
         is persisted as a TOOL message right after execution (rendered
         exactly as the in-memory tool message; ToolResult stays canonical
         in tool_results); a final text answer is persisted last.

    Failure semantics: only events that actually happened are persisted.
    A provider failure persists no assistant message; a tool failure is
    persisted as the (failed) TOOL message the model would have seen; an
    empty final model response persists nothing. TaskRun/Task semantics
    are untouched. Messages carry `task_id` metadata when a task exists.
    The system prompt is never persisted. With no conversation_manager
    (the default) none of this runs. If given without a context_manager, a
    minimal ContextManager is created; if the supplied context_manager has
    no conversation_manager, it is wired to this one.
    """

    def __init__(
        self,
        router: ModelRouter,
        registry: ToolRegistry,
        approval_handler: ApprovalHandler,
        system_prompt: str | None = None,
        max_iterations: int | None = None,
        max_tool_calls: int | None = None,
        task_manager: TaskManager | None = None,
        context_manager: ContextManager | None = None,
        conversation_manager: ConversationManager | None = None,
    ) -> None:
        self.router = router
        self.registry = registry
        self.approval_handler = approval_handler
        self.system_prompt = system_prompt
        self.max_iterations = (
            max_iterations if max_iterations is not None else settings.max_iterations
        )
        self.max_tool_calls = (
            max_tool_calls if max_tool_calls is not None else settings.max_tool_calls
        )
        self.task_manager = task_manager
        self.conversation_manager = conversation_manager
        if conversation_manager is not None:
            if context_manager is None:
                context_manager = ContextManager(conversation_manager=conversation_manager)
            elif context_manager.conversation_manager is None:
                context_manager.conversation_manager = conversation_manager
            elif context_manager.conversation_manager is not conversation_manager:
                raise ValueError(
                    "context_manager and orchestrator use different conversation managers"
                )
        self.context_manager = context_manager

    async def run(
        self, user_request: str, conversation_id: uuid.UUID | None = None
    ) -> OrchestratorResult:
        """Entry point. With no `task_manager`, this just runs the loop.
        With one, it wraps the loop with task creation/status bookkeeping
        and a best-effort FAILED-on-crash safety net — see the class
        docstring's PERSISTENCE section. `conversation_id` is required
        exactly when a conversation_manager is configured."""
        if self.conversation_manager is None:
            if conversation_id is not None:
                raise ValueError("conversation_id given but no conversation_manager is configured")
        else:
            if conversation_id is None:
                raise ValueError("conversation_id is required when a conversation_manager is set")
            # Fail fast (unknown conversation / inactive session) before any
            # side effects such as creating a Task.
            self.conversation_manager.ensure_writable(conversation_id)

        if self.task_manager is None:
            return await self._run_loop(user_request, task=None, conversation_id=conversation_id)

        task = self.task_manager.create_task(user_request)
        task = self.task_manager.start_task(task.id)
        try:
            return await self._run_loop(user_request, task=task, conversation_id=conversation_id)
        except Exception as exc:
            # Reaching here means something genuinely unexpected happened —
            # ProviderError/AllProvidersFailedError and every tool-execution
            # failure mode are already caught inside _run_loop and turned
            # into controlled OrchestratorResults. This is a real bug (or a
            # task_manager failure itself). Best-effort mark the task
            # FAILED, then re-raise the ORIGINAL exception unchanged —
            # persistence must never hide what actually went wrong.
            try:
                self.task_manager.fail_task(task.id, f"Unexpected error: {exc}")
            except Exception:  # noqa: BLE001 — persistence failure must not mask the original error
                logger.exception(
                    "orchestrator: failed to persist FAILED status for task=%s "
                    "after an unexpected error",
                    task.id,
                )
            raise

    async def _run_loop(
        self,
        user_request: str,
        task: Task | None,
        conversation_id: uuid.UUID | None = None,
    ) -> OrchestratorResult:
        base_meta: dict[str, Any] = {"task_id": str(task.id)} if task is not None else {}
        if conversation_id is not None:
            self.conversation_manager.append_user_message(
                conversation_id, user_request, metadata=base_meta
            )
        messages: list[Message] = self._build_seed_messages(user_request, conversation_id)

        executed_tool_calls: list[ToolResult] = []
        tool_calls_used = 0
        provider_used: str | None = None
        model_used: str | None = None

        for iteration in range(1, self.max_iterations + 1):
            tool_schemas = self.registry.schemas()

            # One TaskRun per iteration (one model round-trip), created
            # RUNNING with started_at set immediately before the model
            # call — not after it succeeds. Its eventual COMPLETED/FAILED
            # status reflects only whether THIS model call succeeded, not
            # whether any tool calls it requests later succeed: per the
            # class docstring's rule, only the final orchestration outcome
            # determines the Task's own terminal state, and a tool failure
            # must never retroactively flip an already-successful model
            # round-trip to FAILED.
            current_run = None
            if task is not None:
                current_run = self.task_manager.start_task_run(task.id, iteration)

            try:
                if tool_schemas:
                    response = await self.router.generate_with_tools(messages, tool_schemas)
                else:
                    response = await self.router.generate(messages)
            except (ProviderError, AllProvidersFailedError) as exc:
                logger.error("orchestrator: provider error on iteration=%s: %s", iteration, exc)
                if task is not None:
                    self.task_manager.fail_task_run(current_run, str(exc))
                    self.task_manager.fail_task(task.id, f"Provider error: {exc}")
                return OrchestratorResult(
                    status=TaskStatus.FAILED,
                    final_response=None,
                    provider=provider_used,
                    model=model_used,
                    tool_calls=executed_tool_calls,
                    iterations=iteration,
                    error=f"Provider error: {exc}",
                )
            except Exception as exc:
                # Not a typed ProviderError — a genuinely unexpected
                # failure during the model call itself (e.g. a bug). The
                # TaskRun is still RUNNING at this point; best-effort mark
                # IT failed before re-raising. The outer run() wrapper
                # handles marking the TASK failed once this propagates —
                # persistence here must never hide the original exception.
                if task is not None and current_run is not None:
                    try:
                        self.task_manager.fail_task_run(current_run, f"Unexpected error: {exc}")
                    except Exception:  # noqa: BLE001 — must not mask the original error
                        logger.exception(
                            "orchestrator: failed to persist FAILED status for "
                            "task_run=%s after an unexpected error",
                            current_run.id,
                        )
                raise

            provider_used = response.provider or provider_used
            model_used = response.model or model_used

            if task is not None:
                current_run = self.task_manager.complete_task_run(
                    current_run, provider=provider_used, model=model_used
                )

            if not response.tool_calls:
                # Final answer. response.text may legitimately be None/empty
                # (e.g. an empty model turn) — that's not an error, just an
                # empty result; never crash on it.
                if conversation_id is not None:
                    if response.text and response.text.strip():
                        self.conversation_manager.append_assistant_message(
                            conversation_id,
                            response.text,
                            metadata={**base_meta, "provider": provider_used, "model": model_used},
                        )
                    else:
                        logger.info("orchestrator: empty final response; nothing to persist")
                if task is not None:
                    self.task_manager.complete_task(task.id, result=response.text)
                return OrchestratorResult(
                    status=TaskStatus.COMPLETED,
                    final_response=response.text,
                    provider=provider_used,
                    model=model_used,
                    tool_calls=executed_tool_calls,
                    iterations=iteration,
                )

            # The model wants to call one or more tools. Record its turn
            # (preserving every ToolCall exactly as returned, including
            # normalized ids) before executing anything, so the
            # conversation stays coherent even if we stop mid-batch.
            messages.append(
                Message(role="assistant", content=response.text, tool_calls=response.tool_calls)
            )
            if conversation_id is not None:
                self.conversation_manager.append_assistant_message(
                    conversation_id,
                    response.text,
                    tool_calls=response.tool_calls,
                    metadata={**base_meta, "provider": provider_used, "model": model_used},
                )

            for tc in response.tool_calls:
                if tool_calls_used >= self.max_tool_calls:
                    logger.warning(
                        "orchestrator: max_tool_calls=%s reached on iteration=%s",
                        self.max_tool_calls,
                        iteration,
                    )
                    error_message = (
                        f"Stopped: reached the maximum of {self.max_tool_calls} "
                        "tool calls allowed for this task."
                    )
                    if task is not None:
                        self.task_manager.fail_task(task.id, error_message)
                    return OrchestratorResult(
                        status=TaskStatus.MAX_TOOL_CALLS_REACHED,
                        final_response=None,
                        provider=provider_used,
                        model=model_used,
                        tool_calls=executed_tool_calls,
                        iterations=iteration,
                        error=error_message,
                    )
                tool_calls_used += 1

                executed = await self._execute_tool_call(tc)
                executed_tool_calls.append(executed)

                if task is not None:
                    self.task_manager.record_tool_result(
                        task.id,
                        executed,
                        task_run_id=current_run.id if current_run is not None else None,
                    )

                # Tool output is UNTRUSTED DATA: it only ever becomes the
                # content of a role="tool" message, matched to its call by
                # the normalized id. It is never written into, appended to,
                # or otherwise allowed to influence the system message —
                # the system prompt set at the top of this method is the
                # only system-role content for the entire run.
                tool_content = _serialize_tool_output(executed)
                messages.append(
                    Message(
                        role="tool",
                        content=tool_content,
                        tool_call_id=executed.tool_call_id,
                        name=executed.name,
                    )
                )
                if conversation_id is not None:
                    self.conversation_manager.append_tool_message(
                        conversation_id,
                        tool_content,
                        tool_call_id=executed.tool_call_id,
                        tool_name=executed.name,
                        metadata={**base_meta, "success": executed.success},
                    )

        logger.warning("orchestrator: max_iterations=%s reached", self.max_iterations)
        if task is not None:
            self.task_manager.fail_task(
                task.id,
                f"Stopped: reached the maximum of {self.max_iterations} iterations for this task.",
            )
        return OrchestratorResult(
            status=TaskStatus.MAX_ITERATIONS_REACHED,
            final_response=None,
            provider=provider_used,
            model=model_used,
            tool_calls=executed_tool_calls,
            iterations=self.max_iterations,
            error=(
                f"Stopped: reached the maximum of {self.max_iterations} "
                "iterations for this task."
            ),
        )

    def _build_seed_messages(
        self, user_request: str, conversation_id: uuid.UUID | None = None
    ) -> list[Message]:
        """Builds the messages list the agent loop starts from.

        With no `context_manager` (the default), this is byte-for-byte
        the original Phase 1/2 behavior: an optional system Message, then
        a user Message — nothing else changes. With one, it builds a
        ContextBundle (system instructions + this request as a USER
        ContextItem + any relevant memory, via ContextManager) and
        converts it to Messages instead. Everything AFTER this point —
        the iteration loop, tool-call handling, TaskRun persistence — is
        identical in both cases and untouched by this method.
        """
        if self.context_manager is None:
            messages: list[Message] = []
            if self.system_prompt:
                messages.append(Message(role="system", content=self.system_prompt))
            messages.append(Message(role="user", content=user_request))
            return messages

        if conversation_id is not None:
            # The user message is already persisted and arrives via history;
            # passing it again would duplicate it.
            bundle = self.context_manager.build_context(
                system_instructions=self.system_prompt,
                conversation_id=conversation_id,
                memory_query=user_request,
            )
            return context_bundle_to_messages(bundle)

        bundle = self.context_manager.build_context(
            system_instructions=self.system_prompt,
            conversation_items=[
                ContextItem(
                    content=user_request,
                    source=ContextSource.USER,
                    priority=ContextPriority.HIGH,
                )
            ],
            memory_query=user_request,
        )
        return context_bundle_to_messages(bundle)

    async def _execute_tool_call(self, tc: ToolCall) -> ToolResult:
        """Process a single ToolCall through lookup -> validation ->
        permission check -> (approval) -> execution -> result, per the
        contract in the module docstring. Never lets a tool's own
        exception, a timeout, or a missing/blocked tool propagate out of
        this method — everything becomes a controlled ToolResult.

        The flow is strictly: raw model arguments -> Pydantic validation ->
        validated arguments -> permission/approval -> execution. Both the
        ApprovalHandler and the eventual `ToolResult.arguments` always see
        the VALIDATED representation (`validated_args.model_dump()`) once
        validation has succeeded — never the raw, unvalidated dict the
        model produced — so the approval request represents exactly what
        will execute. Only the two failure modes that occur before
        validation can succeed (unknown tool, invalid arguments) fall back
        to the raw arguments, since no validated form exists for them.
        """

        tool = self.registry.get(tc.name)
        if tool is None:
            logger.info("orchestrator: unknown tool requested: %s", tc.name)
            return self._failed(tc, f"Tool '{tc.name}' is not available.", tc.arguments)

        # Validate BEFORE any permission check or execution — untrusted
        # model-generated arguments must never reach Python code unvalidated.
        try:
            validated_args = tool.args_model.model_validate(tc.arguments)
        except ValidationError as exc:
            logger.info("orchestrator: invalid arguments for tool=%s: %s", tc.name, exc)
            return self._failed(tc, f"Invalid arguments for '{tc.name}': {exc}", tc.arguments)

        # From here on, this validated dict is the single source of truth
        # for what "the arguments" are — passed to approval and recorded
        # on the final ToolResult, never the raw tc.arguments again.
        validated_arguments = validated_args.model_dump()

        level = tool.permission_level

        if level == PermissionLevel.BLOCKED:
            logger.warning("orchestrator: blocked tool requested: %s", tc.name)
            return self._failed(
                tc, f"Tool '{tc.name}' is blocked and cannot be executed.", validated_arguments
            )

        if requires_approval(level):
            approved = await self.approval_handler.approve(tc.name, validated_arguments, level)
            if not approved:
                logger.info("orchestrator: approval denied for tool=%s", tc.name)
                return self._failed(
                    tc, f"Execution of '{tc.name}' was not approved.", validated_arguments
                )

        try:
            result = await asyncio.wait_for(
                tool.execute(validated_args), timeout=tool.timeout_seconds
            )
        except asyncio.TimeoutError:
            logger.warning(
                "orchestrator: tool=%s timed out after %ss", tc.name, tool.timeout_seconds
            )
            return self._failed(
                tc,
                f"Tool '{tc.name}' timed out after {tool.timeout_seconds}s.",
                validated_arguments,
            )
        except Exception as exc:  # noqa: BLE001 — any tool failure becomes a controlled result
            logger.warning("orchestrator: tool=%s raised: %s", tc.name, exc)
            return self._failed(
                tc, f"Tool '{tc.name}' raised an error: {exc}", validated_arguments
            )

        return ToolResult(
            tool_call_id=tc.id,
            name=tc.name,
            success=True,
            result=result,
            arguments=validated_arguments,
        )

    @staticmethod
    def _failed(tc: ToolCall, message: str, arguments: dict[str, Any]) -> ToolResult:
        return ToolResult(
            tool_call_id=tc.id,
            name=tc.name,
            success=False,
            error=message,
            arguments=arguments,
        )
