from __future__ import annotations

import asyncio
import json
import shlex
from pathlib import Path

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from .models import ToolInfo


async def _list_tools(command: str) -> list[ToolInfo]:
    parts = shlex.split(command)
    if not parts:
        raise ValueError("Empty server command")
    params = StdioServerParameters(command=parts[0], args=parts[1:])
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            result = await session.list_tools()
    return [ToolInfo.from_mcp_tool(t) for t in result.tools]


async def fetch_tools_from_stdio(command: str, timeout: float = 30.0) -> list[ToolInfo]:
    """Starts an MCP server as a subprocess, lists its tools and shuts it down."""
    return await asyncio.wait_for(_list_tools(command), timeout=timeout)


def load_tools_from_file(path: str | Path) -> list[ToolInfo]:
    """Loads a saved tool list (JSON). Nothing is executed: the safest mode."""
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    items = data["tools"] if isinstance(data, dict) else data
    return [
        ToolInfo(
            name=item["name"],
            description=item.get("description") or "",
            input_schema=item.get("inputSchema") or {},
        )
        for item in items
    ]