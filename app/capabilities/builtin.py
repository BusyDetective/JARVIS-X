"""Minimal, harmless built-in capabilities that prove the registration
architecture. No network, filesystem, process or system access: pure
functions of their arguments (and the clock for get_current_time).

`builtin_packages()` builds FRESH tool instances every call — no module
level mutable state — in dependency order."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Literal

from pydantic import BaseModel, Field

from app.capabilities.models import Capability, CapabilityCategory, CapabilitySource
from app.security.permissions import PermissionLevel
from app.tools.base import Tool


class _EchoArgs(BaseModel):
    text: str = Field(max_length=2000, description="Text to return unchanged.")


class EchoTool(Tool):
    name = "echo"
    description = "Returns the given text unchanged."
    args_model = _EchoArgs
    permission_level = PermissionLevel.SAFE

    async def execute(self, args: _EchoArgs) -> str:
        return args.text


class _NoArgs(BaseModel):
    pass


class CurrentTimeTool(Tool):
    name = "get_current_time"
    description = "Returns the current UTC date and time in ISO 8601 format."
    args_model = _NoArgs
    permission_level = PermissionLevel.SAFE

    async def execute(self, args: _NoArgs) -> str:
        return datetime.now(timezone.utc).isoformat(timespec="seconds")


class _TransformArgs(BaseModel):
    text: str = Field(max_length=2000, description="Text to transform.")
    mode: Literal["upper", "lower", "title", "reverse"] = Field(description="Transformation to apply.")


class TextTransformTool(Tool):
    name = "text_transform"
    description = "Transforms text: upper, lower, title case, or reverse."
    args_model = _TransformArgs
    permission_level = PermissionLevel.SAFE

    async def execute(self, args: _TransformArgs) -> str:
        return {
            "upper": args.text.upper,
            "lower": args.text.lower,
            "title": args.text.title,
            "reverse": lambda: args.text[::-1],
        }[args.mode]()


def builtin_packages() -> list[tuple[Capability, list[Tool]]]:
    core = Capability(
        id="core",
        name="Core",
        description="Basic always-safe utilities.",
        category=CapabilityCategory.CORE,
        source=CapabilitySource.BUILTIN,
        max_permission=PermissionLevel.SAFE,
        tool_names=("echo", "get_current_time"),
    )
    text = Capability(
        id="text_utilities",
        name="Text utilities",
        description="Simple text transformations.",
        category=CapabilityCategory.PRODUCTIVITY,
        source=CapabilitySource.BUILTIN,
        max_permission=PermissionLevel.SAFE,
        tool_names=("text_transform",),
        depends_on=("core",),
    )
    return [
        (core, [EchoTool(), CurrentTimeTool()]),
        (text, [TextTransformTool()]),
    ]
