from mcp_toolcheck.engine import audit_tools
from mcp_toolcheck.models import ToolInfo
from mcp_toolcheck.rules import (
    check_command_execution,
    check_destructive_tool,
    check_hidden_characters,
    check_missing_description,
    check_oversized_description,
    check_prompt_injection,
    check_raw_sql,
    check_secrets_in_parameters,
    check_unrestricted_path,
    check_unrestricted_url,
)


def ids(findings):
    return {f.rule_id for f in findings}


def test_detects_prompt_injection(demo_tools):
    assert ids(check_prompt_injection(demo_tools["add_numbers"])) == {"MCP001"}


def test_detects_hidden_characters(demo_tools):
    assert ids(check_hidden_characters(demo_tools["weather"])) == {"MCP002"}


def test_detects_command_execution(demo_tools):
    assert ids(check_command_execution(demo_tools["run_command"])) == {"MCP003"}


def test_detects_unrestricted_path(demo_tools):
    assert ids(check_unrestricted_path(demo_tools["read_file"])) == {"MCP004"}


def test_detects_secret_parameter(demo_tools):
    assert ids(check_secrets_in_parameters(demo_tools["add_numbers"])) == {"MCP005"}


def test_clean_tool_has_no_findings(demo_tools):
    assert audit_tools([demo_tools["get_time"]]) == []


def test_path_with_enum_is_not_flagged():
    tool = ToolInfo(
        name="read_report",
        description="Reads one of the allowed reports.",
        input_schema={"properties": {"path": {"type": "string", "enum": ["a.txt", "b.txt"]}}},
    )
    assert check_unrestricted_path(tool) == []


def test_detects_unrestricted_url(demo_tools):
    assert ids(check_unrestricted_url(demo_tools["fetch_url"])) == {"MCP006"}


def test_detects_missing_description(demo_tools):
    assert ids(check_missing_description(demo_tools["ping"])) == {"MCP007"}


def test_detects_destructive_tool(demo_tools):
    assert ids(check_destructive_tool(demo_tools["delete_all_records"])) == {"MCP008"}


def test_detects_raw_sql(demo_tools):
    assert ids(check_raw_sql(demo_tools["run_query"])) == {"MCP009"}


def test_detects_oversized_description():
    tool = ToolInfo(name="verbose", description="word " * 400)
    assert ids(check_oversized_description(tool)) == {"MCP010"}