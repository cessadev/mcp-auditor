from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


@dataclass(frozen=True)
class ToolInfo:
    """A basic view of an MCP tool: all the rules need."""

    name: str
    description: str
    input_schema: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_mcp_tool(cls, tool: Any) -> ToolInfo:
        return cls(
            name=tool.name,
            description=tool.description or "",
            input_schema=tool.inputSchema or {},
        )

    @property
    def parameters(self) -> dict[str, dict[str, Any]]:
        return self.input_schema.get("properties", {})


@dataclass(frozen=True)
class Finding:
    """A finding: which rule was violated, in which tool, and based on what evidence."""

    rule_id: str
    severity: Severity
    tool: str
    message: str
    evidence: str = ""