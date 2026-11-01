from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, ClassVar

from pydantic import BaseModel

from app.providers.schemas import ToolSchema
from app.security.permissions import PermissionLevel


class Tool(ABC):
    """Base class every tool implementation subclasses.

    A Tool owns its own Pydantic input model (`args_model`). That one model
    does double duty, so the schema concept is never duplicated:

    - `to_tool_schema()` turns it into the normalized `ToolSchema` (JSON
      Schema) the AIProvider layer sends to the model.
    - the orchestrator uses it to validate a model-produced ToolCall's raw
      `arguments` dict BEFORE any of it reaches `execute()` — untrusted
      model output must never be passed into Python code unvalidated.

    This phase defines the abstraction only. No concrete tool (filesystem,
    terminal, browser, ...) lives here yet — those are later phases.
    """

    name: ClassVar[str]
    description: ClassVar[str]
    args_model: ClassVar[type[BaseModel]]
    permission_level: ClassVar[PermissionLevel] = PermissionLevel.SAFE
    timeout_seconds: ClassVar[float] = 30.0
    # Descriptive metadata only (semver-like string); never used for
    # dispatch or permission decisions.
    version: ClassVar[str] = "1.0.0"

    def to_tool_schema(self) -> ToolSchema:
        """The normalized ToolSchema describing this tool to the model."""
        parameters = self.args_model.model_json_schema()
        # Pydantic's top-level "title" is the Python class name — an
        # implementation detail the model has no use for.
        parameters.pop("title", None)
        return ToolSchema(
            name=self.name,
            description=self.description,
            parameters=parameters,
        )

    @abstractmethod
    async def execute(self, args: BaseModel) -> Any:
        """Run the tool with already-validated arguments (an instance of
        `args_model`). Return any JSON-serializable value — str, dict,
        list, number, None, etc. The orchestrator wraps the return value
        (or any exception raised here) into a ToolResult; a tool never
        needs to construct a ToolResult itself, and should let exceptions
        propagate rather than swallowing them — the orchestrator converts
        them into a controlled failure result.
        """
        ...
