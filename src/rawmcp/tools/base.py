"""The tool abstraction: a strict Pydantic input model, an output model and required scopes.

A tool's ``inputSchema`` and ``outputSchema`` are generated from its Pydantic models, so the
schema a client sees and the validation the server runs can never drift apart.
"""

from __future__ import annotations

import functools
import json
from abc import ABC, abstractmethod
from typing import Any, ClassVar

from pydantic import BaseModel, ConfigDict, ValidationError

from rawmcp.audit import Decision
from rawmcp.context import ToolContext
from rawmcp.versions import Revision


class ToolInput(BaseModel):
    """Base for tool inputs: unknown keys are rejected and no type coercion happens ("5" is not 5)."""

    model_config = ConfigDict(extra="forbid", strict=True)


class ToolOutput(BaseModel):
    """Base for tool outputs (``structuredContent``)."""

    model_config = ConfigDict(extra="forbid")


class ToolError(Exception):
    """An expected failure, returned to the client as a result with ``isError: true``.

    ``decision`` is what the audit log records: ``deny`` for policy blocks (jail escape,
    domain not allowed, write to a read-only database), ``error`` for ordinary failures
    (file not found, division by zero).
    """

    def __init__(self, message: str, *, decision: Decision = "error") -> None:
        super().__init__(message)
        self.decision: Decision = decision


class PolicyDenied(ToolError):
    """A tool refused an operation because the policy forbids it."""

    def __init__(self, message: str) -> None:
        super().__init__(message, decision="deny")


def _clean(schema: Any) -> Any:
    """Drop Pydantic's auto-generated ``title`` annotations; keep everything else.

    ``properties`` maps names to subschemas, so a property literally called ``title`` survives.
    """
    if isinstance(schema, list):
        return [_clean(item) for item in schema]
    if not isinstance(schema, dict):
        return schema
    out: dict[str, Any] = {}
    for key, value in schema.items():
        if key == "title" and isinstance(value, str):
            continue
        if key in ("properties", "$defs", "patternProperties") and isinstance(value, dict):
            out[key] = {name: _clean(sub) for name, sub in value.items()}
        else:
            out[key] = _clean(value)
    return out


@functools.cache
def _schema_json(model: type[BaseModel], mode: str) -> str:
    schema: dict[str, Any] = _clean(model.model_json_schema(mode=mode))  # type: ignore[arg-type]
    schema["type"] = "object"
    return json.dumps(schema)


def model_schema(model: type[BaseModel], mode: str = "validation") -> dict[str, Any]:
    """JSON Schema (draft 2020-12, the MCP default dialect) for a Pydantic model.

    Generation is cached (it costs milliseconds per model); each call returns a fresh copy.
    """
    schema: dict[str, Any] = json.loads(_schema_json(model, mode))
    return schema


class Tool(ABC):
    """One callable tool. Subclasses set the class attributes and implement :meth:`run`."""

    name: ClassVar[str]
    title: ClassVar[str]
    description: ClassVar[str]
    input_model: ClassVar[type[ToolInput]]
    output_model: ClassVar[type[ToolOutput]]
    scopes: ClassVar[frozenset[str]] = frozenset()
    read_only: ClassVar[bool] = True
    destructive: ClassVar[bool] = False
    idempotent: ClassVar[bool] = True
    open_world: ClassVar[bool] = False

    @abstractmethod
    async def run(self, args: Any, ctx: ToolContext) -> ToolOutput:
        """Execute the tool. Raise :class:`ToolError` for failures the caller should see."""

    def input_schema(self) -> dict[str, Any]:
        return model_schema(self.input_model, "validation")

    def output_schema(self) -> dict[str, Any]:
        return model_schema(self.output_model, "serialization")

    def definition(self, revision: Revision) -> dict[str, Any]:
        """The ``Tool`` object for ``tools/list``, shaped for one protocol revision.

        ``title``/``outputSchema`` exist from 2025-06-18 and ``annotations`` from 2025-03-26;
        2024-11-05 clients get just ``name``, ``description`` and ``inputSchema``.
        """
        tool: dict[str, Any] = {"name": self.name}
        if revision.structured_output:
            tool["title"] = self.title
        tool["description"] = self.description
        tool["inputSchema"] = self.input_schema()
        if revision.structured_output:
            tool["outputSchema"] = self.output_schema()
        if revision.tool_annotations:
            annotations: dict[str, Any] = {
                "readOnlyHint": self.read_only,
                "destructiveHint": self.destructive,
                "idempotentHint": self.idempotent,
                "openWorldHint": self.open_world,
            }
            if not revision.structured_output:
                annotations = {"title": self.title, **annotations}
            tool["annotations"] = annotations
        tool["_meta"] = {"dev.rawmcp/requiredScopes": sorted(self.scopes)} if revision.structured_output else None
        return {key: value for key, value in tool.items() if value is not None}

    def dump_output(self, output: ToolOutput) -> dict[str, Any]:
        """Serialise the output and check it round-trips through the output model.

        Raises ``ValueError`` if the tool produced something its own ``outputSchema`` would reject
        (for example a NaN float, which is not valid JSON).
        """
        if not isinstance(output, self.output_model):
            raise ValueError(f"{self.name} returned {type(output).__name__}, expected {self.output_model.__name__}")
        data = output.model_dump(mode="json")
        try:
            self.output_model.model_validate_json(json.dumps(data, allow_nan=False))
        except (ValidationError, ValueError) as exc:
            raise ValueError(f"{self.name} produced output that violates its outputSchema: {exc}") from None
        return data
