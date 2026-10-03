from __future__ import annotations

import asyncio
import json
import re
import shlex
import tempfile
from collections.abc import Iterator
from pathlib import Path
from typing import TextIO

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from .models import ToolInfo


class ScanError(Exception):
    """The server could not be reached. The message is written for humans."""


_MISSING_MODULE_RE = re.compile(r"No module named '([^']+)'")
_MAX_SERVER_OUTPUT_LINES = 6


def _leaf_exceptions(exc: BaseException) -> Iterator[BaseException]:
    """anyio wraps errors in an ExceptionGroup; this digs out the real ones."""
    nested = getattr(exc, "exceptions", None)
    if nested:
        for inner in nested:
            yield from _leaf_exceptions(inner)
    else:
        yield exc


def _server_output_block(server_output: str) -> str:
    lines = [line for line in server_output.strip().splitlines() if line.strip()]
    if not lines:
        return ""
    tail = "\n".join(f"    {line}" for line in lines[-_MAX_SERVER_OUTPUT_LINES:])
    return f"\n  server output (last lines):\n{tail}"


def _explain_failure(command: str, exc: BaseException, server_output: str) -> str:
    leaves = list(_leaf_exceptions(exc))

    if any(isinstance(e, FileNotFoundError) for e in leaves):
        return f"command not found: '{shlex.split(command)[0]}'. Check the path and that it is installed."

    missing = _MISSING_MODULE_RE.search(server_output)
    if missing:
        module = missing.group(1).split(".")[0]
        package = "mcp<2" if module == "mcp" else module
        return (
            f"the server crashed on startup: Python module '{module}' is not installed "
            "in the environment used by --command.\n"
            f"  Install it there (for example: pip install '{package}') or point --command "
            "at an interpreter that has it."
            + _server_output_block(server_output)
        )

    message = "the server process ended before finishing the MCP handshake (is it a stdio MCP server?)"
    block = _server_output_block(server_output)
    if block:
        return message + block
    detail = f"{type(leaves[0]).__name__}: {leaves[0]}" if leaves else str(exc)
    return f"{message}\n  ({detail})"


async def _list_tools(command: str, errlog: TextIO) -> list[ToolInfo]:
    parts = shlex.split(command)
    if not parts:
        raise ScanError("empty --command")
    params = StdioServerParameters(command=parts[0], args=parts[1:])
    async with stdio_client(params, errlog=errlog) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            result = await session.list_tools()
    return [ToolInfo.from_mcp_tool(t) for t in result.tools]


def _read_back(errlog: TextIO) -> str:
    errlog.flush()
    errlog.seek(0)
    return errlog.read()


async def fetch_tools_from_stdio(command: str, timeout: float = 30.0) -> list[ToolInfo]:
    """Starts an MCP server as a subprocess, lists its tools and shuts it down.

    The server's stderr is captured (not streamed) so that, if startup fails,
    we can show the relevant lines together with a human-readable explanation.
    """
    with tempfile.TemporaryFile(mode="w+", encoding="utf-8", errors="replace") as errlog:
        try:
            return await asyncio.wait_for(_list_tools(command, errlog), timeout=timeout)
        except ScanError:
            raise
        except asyncio.TimeoutError:
            raise ScanError(
                f"the server did not finish the MCP handshake within {timeout:g} seconds "
                "(is --command a stdio MCP server? Use --timeout to wait longer)."
                + _server_output_block(_read_back(errlog))
            ) from None
        except Exception as exc:
            raise ScanError(_explain_failure(command, exc, _read_back(errlog))) from exc


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