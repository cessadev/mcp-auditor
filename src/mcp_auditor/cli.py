from __future__ import annotations

import argparse
import asyncio
import sys

from .engine import audit_tools
from .models import Severity
from .report import render_json, render_text
from .scanner import fetch_tools_from_stdio, load_tools_from_file

_LEVELS = {"low": 1, "medium": 2, "high": 3}
_SEVERITY_LEVEL = {Severity.LOW: 1, Severity.MEDIUM: 2, Severity.HIGH: 3}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="mcp-auditor",
        description="Static security auditor for MCP servers.",
    )
    sub = parser.add_subparsers(dest="action", required=True)

    scan = sub.add_parser("scan", help="Audit the tools exposed by an MCP server")
    source = scan.add_mutually_exclusive_group(required=True)
    source.add_argument("--command", help='Command that starts a stdio MCP server, e.g. "python server.py"')
    source.add_argument("--tools-file", help="JSON file with a saved tool list (nothing is executed)")
    scan.add_argument("--format", choices=["text", "json"], default="text")
    scan.add_argument(
        "--fail-on",
        choices=["low", "medium", "high", "never"],
        default="high",
        help="Exit with code 1 if a finding at this severity or above exists (default: high)",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    try:
        if args.tools_file:
            tools = load_tools_from_file(args.tools_file)
        else:
            tools = asyncio.run(fetch_tools_from_stdio(args.command))
    except Exception as exc:
        print(f"error: could not read tools: {exc}", file=sys.stderr)
        return 2

    findings = audit_tools(tools)
    if args.format == "json":
        print(render_json(findings, len(tools)))
    else:
        print(render_text(findings, len(tools)))

    if args.fail_on != "never":
        threshold = _LEVELS[args.fail_on]
        if any(_SEVERITY_LEVEL[f.severity] >= threshold for f in findings):
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())