from __future__ import annotations

import json
from collections import Counter
from dataclasses import asdict, dataclass

from .models import Finding, Severity

_ORDER = {Severity.HIGH: 0, Severity.MEDIUM: 1, Severity.LOW: 2}
_MAX_TOOLS_SHOWN = 5
_MAX_EVIDENCE_SHOWN = 3


@dataclass(frozen=True)
class Group:
    """The same problem (rule + message) found in one or more tools."""

    rule_id: str
    severity: Severity
    message: str
    tools: tuple[str, ...]
    evidence: tuple[str, ...]


def sort_findings(findings: list[Finding]) -> list[Finding]:
    return sorted(findings, key=lambda f: (_ORDER[f.severity], f.tool, f.rule_id))


def group_findings(findings: list[Finding]) -> list[Group]:
    buckets: dict[tuple[str, Severity, str], dict[str, list[str]]] = {}
    for f in sort_findings(findings):
        bucket = buckets.setdefault((f.rule_id, f.severity, f.message), {"tools": [], "evidence": []})
        if f.tool not in bucket["tools"]:
            bucket["tools"].append(f.tool)
        if f.evidence and f.evidence not in bucket["evidence"]:
            bucket["evidence"].append(f.evidence)
    groups = [
        Group(
            rule_id=rule_id,
            severity=severity,
            message=message,
            tools=tuple(data["tools"]),
            evidence=tuple(data["evidence"]),
        )
        for (rule_id, severity, message), data in buckets.items()
    ]
    return sorted(groups, key=lambda g: (_ORDER[g.severity], g.rule_id))


def _short_list(items: tuple[str, ...], limit: int) -> str:
    shown = ", ".join(items[:limit])
    extra = len(items) - limit
    return f"{shown} (+{extra} more)" if extra > 0 else shown


def _summary(findings: list[Finding]) -> str:
    counts = Counter(f.severity for f in findings)
    return ", ".join(f"{counts.get(s, 0)} {s.value}" for s in (Severity.HIGH, Severity.MEDIUM, Severity.LOW))


def render_text(findings: list[Finding], tools_scanned: int) -> str:
    groups = group_findings(findings)
    lines = [f"mcp-toolcheck: {tools_scanned} tool(s) scanned, {len(findings)} finding(s)", ""]
    for g in groups:
        lines.append(f"[{g.severity.value.upper():6}] {g.rule_id}  {g.message}")
        lines.append(f"         tools ({len(g.tools)}): {_short_list(g.tools, _MAX_TOOLS_SHOWN)}")
        if g.evidence:
            lines.append(f"         evidence: {_short_list(g.evidence, _MAX_EVIDENCE_SHOWN)}")
        lines.append("")
    lines.append(f"Summary: {_summary(findings)}")
    return "\n".join(lines)


def render_markdown(findings: list[Finding], tools_scanned: int, title: str = "MCP audit report") -> str:
    lines = [
        f"## {title}",
        "",
        f"{tools_scanned} tool(s) scanned, {len(findings)} finding(s): {_summary(findings)}.",
        "",
    ]
    if findings:
        lines += ["| Severity | Rule | Issue | Tools | Evidence |", "|---|---|---|---|---|"]
        for g in group_findings(findings):
            tools = _short_list(g.tools, _MAX_TOOLS_SHOWN)
            evidence = _short_list(g.evidence, _MAX_EVIDENCE_SHOWN).replace("|", "\\|")
            lines.append(f"| {g.severity.value} | {g.rule_id} | {g.message} | {tools} | `{evidence}` |")
    else:
        lines.append("No findings.")
    return "\n".join(lines)


def render_json(findings: list[Finding], tools_scanned: int) -> str:
    counts = Counter(f.severity.value for f in findings)
    payload = {
        "tools_scanned": tools_scanned,
        "summary": {s.value: counts.get(s.value, 0) for s in Severity},
        "findings": [{**asdict(f), "severity": f.severity.value} for f in sort_findings(findings)],
    }
    return json.dumps(payload, indent=2, ensure_ascii=False)