import asyncio
import importlib.util
from pathlib import Path

import pytest

from mcp_toolcheck.models import ToolInfo

FIXTURE = Path(__file__).parent / "fixtures" / "vulnerable_server.py"


@pytest.fixture(scope="session")
def demo_tools() -> dict[str, ToolInfo]:
    spec = importlib.util.spec_from_file_location("vulnerable_server", FIXTURE)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    tools = asyncio.run(module.mcp.list_tools())
    return {t.name: ToolInfo.from_mcp_tool(t) for t in tools}