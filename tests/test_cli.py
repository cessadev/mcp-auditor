import asyncio
import json
import shlex
import sys
from pathlib import Path

from mcp_toolcheck.cli import main
from mcp_toolcheck.scanner import fetch_tools_from_stdio

SERVER = Path(__file__).parent / "fixtures" / "vulnerable_server.py"
COMMAND = f"{shlex.quote(sys.executable)} {shlex.quote(str(SERVER))}"


def test_scan_real_server_over_stdio():
    tools = asyncio.run(fetch_tools_from_stdio(COMMAND))
    names = {t.name for t in tools}
    assert {"run_command", "read_file", "get_time"} <= names


def test_cli_exits_1_when_high_findings(capsys):
    code = main(["scan", "--command", COMMAND])
    out = capsys.readouterr().out
    assert code == 1
    assert "MCP003" in out


def test_cli_json_output_is_valid(capsys):
    code = main(["scan", "--command", COMMAND, "--format", "json", "--fail-on", "never"])
    payload = json.loads(capsys.readouterr().out)
    assert code == 0
    assert payload["tools_scanned"] >= 5
    assert any(f["rule_id"] == "MCP001" for f in payload["findings"])


def test_clean_tools_file_exits_0(tmp_path, capsys):
    tools_file = tmp_path / "tools.json"
    tools_file.write_text(
        json.dumps(
            [
                {
                    "name": "get_time",
                    "description": "Returns the current time in UTC.",
                    "inputSchema": {"type": "object", "properties": {}},
                }
            ]
        )
    )
    assert main(["scan", "--tools-file", str(tools_file)]) == 0


def test_unreadable_server_exits_2(capsys):
    assert main(["scan", "--command", "this-command-does-not-exist"]) == 2


def test_cli_groups_repeated_findings(tmp_path, capsys):
    tools = [
        {"name": f"git_{n}", "description": "Runs a git operation on a repository.",
         "inputSchema": {"type": "object", "properties": {"repo_path": {"type": "string"}}}}
        for n in ("add", "diff", "commit")
    ]
    tools_file = tmp_path / "tools.json"
    tools_file.write_text(json.dumps(tools))
    main(["scan", "--tools-file", str(tools_file), "--fail-on", "never"])
    out = capsys.readouterr().out
    assert out.count("MCP004") == 1
    assert "tools (3)" in out


def test_cli_markdown_output(capsys):
    main(["scan", "--command", COMMAND, "--format", "markdown", "--fail-on", "never"])
    out = capsys.readouterr().out
    assert out.startswith("## MCP audit report")
    assert "| high | MCP003 |" in out