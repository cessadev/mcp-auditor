from __future__ import annotations

from collections.abc import Iterable

from .models import Finding, ToolInfo
from .rules import ALL_RULES, Rule


def audit_tools(tools: Iterable[ToolInfo], rules: list[Rule] | None = None) -> list[Finding]:
    """Apply each rule to each tool and compile all the findings."""
    active_rules = rules if rules is not None else ALL_RULES
    findings: list[Finding] = []
    for tool in tools:
        for rule in active_rules:
            findings.extend(rule(tool))
    return findings