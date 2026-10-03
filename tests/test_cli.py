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


def test_closing_the_pipe_early_is_not_an_error(tmp_path):
    """`mcp-toolcheck ... | head -1` must not print a traceback or change the exit code."""
    import subprocess

    tools = [
        {"name": f"run_shell_{i}", "description": "Runs a command in the system shell.",
         "inputSchema": {"type": "object", "properties": {"command": {"type": "string"}}}}
        for i in range(3000)
    ]
    tools_file = tmp_path / "big.json"
    tools_file.write_text(json.dumps(tools))

    proc = subprocess.Popen(
        [sys.executable, "-m", "mcp_toolcheck.cli", "scan", "--tools-file", str(tools_file),
         "--format", "json", "--fail-on", "never"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    proc.stdout.readline()
    proc.stdout.close()
    stderr = proc.stderr.read()
    proc.stderr.close()
    code = proc.wait(timeout=30)

    assert stderr == b""
    assert code == 0


def test_missing_mcp_module_gets_a_clear_message(capsys):
    """A Python without the `mcp` package must not surface as 'unhandled errors in a TaskGroup'."""
    # `-S` skips site-packages, so this interpreter cannot import `mcp` (same symptom as a bare Python)
    code = main(["scan", "--command", shlex.join([sys.executable, "-S", str(SERVER)])])
    err = capsys.readouterr().err
    assert code == 2
    assert "Python module 'mcp' is not installed" in err
    assert "pip install 'mcp<2'" in err
    assert "ModuleNotFoundError" in err
    assert "TaskGroup" not in err


def test_server_that_exits_immediately_shows_its_output(capsys):
    command = shlex.join([sys.executable, "-c", "import sys; print('boom', file=sys.stderr); sys.exit(3)"])
    code = main(["scan", "--command", command])
    err = capsys.readouterr().err
    assert code == 2
    assert "ended before finishing the MCP handshake" in err
    assert "boom" in err
    assert "TaskGroup" not in err


def test_command_not_found_message(capsys):
    code = main(["scan", "--command", "this-command-does-not-exist"])
    err = capsys.readouterr().err
    assert code == 2
    assert "command not found: 'this-command-does-not-exist'" in err


def test_server_that_never_answers_times_out_with_a_message(capsys):
    command = shlex.join([sys.executable, "-c", "import time; time.sleep(60)"])
    code = main(["scan", "--command", command, "--timeout", "2"])
    err = capsys.readouterr().err
    assert code == 2
    assert "did not finish the MCP handshake within 2 seconds" in err
    assert "--timeout" in err