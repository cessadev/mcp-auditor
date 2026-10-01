from __future__ import annotations

import json
from collections import Counter
from dataclasses import asdict

from .models import Finding, Severity

_ORDER = {Severity.HIGH: 0, Severity.MEDIUM: 1, Severity.LOW: 2}


def sort_findings(findings: list[Finding]) -> list[Finding]:
    return sorted(findings, key=lambda f: (_ORDER[f.severity], f.tool, f.rule_id))


def render_text(findings: list[Finding], tools_scanned: int) -> str:
    lines = [f"mcp-auditor: {tools_scanned} tool(s) scanned, {len(findings)} finding(s)", ""]
    for f in sort_findings(findings):
        lines.append(f"[{f.severity.value.upper():6}] {f.rule_id}  {f.tool}")
        lines.append(f"         {f.message}")
        if f.evidence:
            lines.append(f"         evidence: {f.evidence}")
        lines.append("")
    counts = Counter(f.severity for f in findings)
    summary = ", ".join(
        f"{counts.get(s, 0)} {s.value}" for s in (Severity.HIGH, Severity.MEDIUM, Severity.LOW)
    )
    lines.append(f"Summary: {summary}")
    return "\n".join(lines)


def render_json(findings: list[Finding], tools_scanned: int) -> str:
    payload = {
        "tools_scanned": tools_scanned,
        "findings": [{**asdict(f), "severity": f.severity.value} for f in sort_findings(findings)],
    }
    return json.dumps(payload, indent=2, ensure_ascii=False)