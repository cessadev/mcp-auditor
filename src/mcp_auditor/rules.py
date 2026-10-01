from __future__ import annotations

import re
import unicodedata
from collections.abc import Callable

from .models import Finding, Severity, ToolInfo

Rule = Callable[[ToolInfo], list[Finding]]


def _all_text(tool: ToolInfo) -> str:
    """All the text that the AI model would read from this tool."""
    parts = [tool.name, tool.description]
    for schema in tool.parameters.values():
        parts.append(str(schema.get("description", "")))
    return "\n".join(parts)


# MCP001: Hidden instructions directed at the model (tool poisoning)

INJECTION_PATTERNS = [
    r"ignore (all |any )?(previous|prior|above) instructions",
    r"do(n'?t| not) (tell|inform|mention|reveal).{0,40}(user|human)",
    r"<\s*important\s*>",
    r"before (using|calling|running) this tool.{0,80}(read|send|include|fetch)",
    r"(read|cat|open|send).{0,40}(~/\.ssh|id_rsa|\.env|/etc/passwd)",
    r"system prompt",
]
_INJECTION_RE = [re.compile(p, re.IGNORECASE | re.DOTALL) for p in INJECTION_PATTERNS]


def check_prompt_injection(tool: ToolInfo) -> list[Finding]:
    text = _all_text(tool)
    findings = []
    for regex in _INJECTION_RE:
        match = regex.search(text)
        if match:
            findings.append(
                Finding(
                    rule_id="MCP001",
                    severity=Severity.HIGH,
                    tool=tool.name,
                    message="The text contains instructions directed at the model (possible injection)",
                    evidence=match.group(0)[:120],
                )
            )
    return findings


# MCP002: Invisible Unicode characters

def check_hidden_characters(tool: ToolInfo) -> list[Finding]:
    hidden = {c for c in _all_text(tool) if unicodedata.category(c) == "Cf"}
    if not hidden:
        return []
    codes = ", ".join(sorted(f"U+{ord(c):04X}" for c in hidden))
    return [
        Finding(
            rule_id="MCP002",
            severity=Severity.HIGH,
            tool=tool.name,
            message="It contains invisible Unicode characters that can hide text",
            evidence=codes,
        )
    ]


# MCP003: Execution of commands or arbitrary code

COMMAND_NAME_TOKENS = {"exec", "execute", "shell", "eval", "bash", "command", "cmd"}
COMMAND_PARAM_NAMES = {"command", "cmd", "shell", "script", "exec", "bash", "code", "eval"}


def check_command_execution(tool: ToolInfo) -> list[Finding]:
    reasons = []
    name_tokens = set(re.split(r"[_\-\s]+", tool.name.lower()))
    if name_tokens & COMMAND_NAME_TOKENS:
        reasons.append(f"nombre '{tool.name}'")
    for pname in tool.parameters:
        if pname.lower() in COMMAND_PARAM_NAMES:
            reasons.append(f"parámetro '{pname}'")
    if not reasons:
        return []
    return [
        Finding(
            rule_id="MCP003",
            severity=Severity.HIGH,
            tool=tool.name,
            message="Possible execution of arbitrary commands or code",
            evidence=", ".join(reasons),
        )
    ]


# MCP004: Unrestricted file paths

PATH_PARAM_NAMES = {"path", "file", "filepath", "file_path", "filename", "directory", "dir", "folder"}


def check_unrestricted_path(tool: ToolInfo) -> list[Finding]:
    findings = []
    for pname, schema in tool.parameters.items():
        if pname.lower() not in PATH_PARAM_NAMES or schema.get("type") != "string":
            continue
        if any(key in schema for key in ("enum", "pattern", "const")):
            continue
        findings.append(
            Finding(
                rule_id="MCP004",
                severity=Severity.MEDIUM,
                tool=tool.name,
                message="Unrestricted path parameter: risk of arbitrary file access",
                evidence=pname,
            )
        )
    return findings


# MCP005: Past credentials as parameters

SECRET_PARAM_RE = re.compile(
    r"(password|passwd|secret|token|api[_-]?key|credential|private[_-]?key)", re.IGNORECASE
)


def check_secrets_in_parameters(tool: ToolInfo) -> list[Finding]:
    return [
        Finding(
            rule_id="MCP005",
            severity=Severity.MEDIUM,
            tool=tool.name,
            message="It asks for credentials as an argument: this would be based on the model's context and the logs",
            evidence=pname,
        )
        for pname in tool.parameters
        if SECRET_PARAM_RE.search(pname)
    ]


ALL_RULES: list[Rule] = [
    check_prompt_injection,
    check_hidden_characters,
    check_command_execution,
    check_unrestricted_path,
    check_secrets_in_parameters,
]