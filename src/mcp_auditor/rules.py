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
                    message="Text contains instructions aimed at the model (possible prompt injection)",
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
            message="Contains invisible Unicode characters that can hide text",
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
            message="Possible arbitrary command or code execution",
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
            message="Asks for a credential as an argument: it would travel through the model context and logs",
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


# MCP006: unrestricted URL parameters (SSRF / exfiltration)

URL_PARAM_NAMES = {"url", "uri", "webhook", "endpoint", "callback", "callback_url", "webhook_url", "base_url"}

def check_unrestricted_url(tool: ToolInfo) -> list[Finding]:
    findings = []
    for pname, schema in tool.parameters.items():
        if pname.lower() not in URL_PARAM_NAMES or schema.get("type") != "string":
            continue
        if any(key in schema for key in ("enum", "pattern", "const")):
            continue
        findings.append(
            Finding(
                rule_id="MCP006",
                severity=Severity.MEDIUM,
                tool=tool.name,
                message="Unrestricted URL parameter: risk of SSRF or sending data to arbitrary hosts",
                evidence=pname,
            )
        )
    return findings


# MCP007: missing or meaningless description

MIN_DESCRIPTION_CHARS = 15

def check_missing_description(tool: ToolInfo) -> list[Finding]:
    if len(tool.description.strip()) >= MIN_DESCRIPTION_CHARS:
        return []
    return [
        Finding(
            rule_id="MCP007",
            severity=Severity.LOW,
            tool=tool.name,
            message="Tool has no meaningful description: models may misuse it and reviewers cannot assess it",
            evidence=repr(tool.description),
        )
    ]


# MCP008: destructive operations

DESTRUCTIVE_NAME_TOKENS = {
    "delete", "remove", "drop", "truncate", "destroy", "wipe", "erase", "kill", "format", "purge",
}

def check_destructive_tool(tool: ToolInfo) -> list[Finding]:
    tokens = set(re.split(r"[_\-\s]+", tool.name.lower()))
    hits = tokens & DESTRUCTIVE_NAME_TOKENS
    if not hits:
        return []
    return [
        Finding(
            rule_id="MCP008",
            severity=Severity.MEDIUM,
            tool=tool.name,
            message="Destructive operation exposed to the model: require human confirmation before it runs",
            evidence=", ".join(sorted(hits)),
        )
    ]


# MCP009: raw SQL as input

SQL_PARAM_NAMES = {"sql", "query", "statement", "raw_query"}
SQL_HINTS = ("sql", "database", "postgres", "mysql", "sqlite")

def check_raw_sql(tool: ToolInfo) -> list[Finding]:
    description = tool.description.lower()
    if not any(hint in description for hint in SQL_HINTS):
        return []
    return [
        Finding(
            rule_id="MCP009",
            severity=Severity.HIGH,
            tool=tool.name,
            message="Accepts raw SQL from the model: risk of data leaks, injection or destructive queries",
            evidence=pname,
        )
        for pname in tool.parameters
        if pname.lower() in SQL_PARAM_NAMES
    ]


# MCP010: oversized description

MAX_DESCRIPTION_CHARS = 1500

def check_oversized_description(tool: ToolInfo) -> list[Finding]:
    size = len(tool.description)
    if size <= MAX_DESCRIPTION_CHARS:
        return []
    return [
        Finding(
            rule_id="MCP010",
            severity=Severity.LOW,
            tool=tool.name,
            message="Very long description: long texts can hide instructions from reviewers",
            evidence=f"{size} characters",
        )
    ]

ALL_RULES: list[Rule] = [
    check_prompt_injection,
    check_hidden_characters,
    check_command_execution,
    check_unrestricted_path,
    check_secrets_in_parameters,
    check_unrestricted_url,
    check_missing_description,
    check_destructive_tool,
    check_raw_sql,
    check_oversized_description,
]