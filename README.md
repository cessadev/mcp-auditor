# mcp-toolcheck

Static security auditor for [MCP](https://modelcontextprotocol.io) (Model Context Protocol) servers.

MCP lets AI agents call external tools, but a tool's name, description and
input schema are plain text that the model reads and trusts. A malicious or
careless server can hide instructions in that text, ask for credentials, or
expose dangerous capabilities. `mcp-toolcheck` inspects what a server declares
and reports risky patterns before you connect it to an agent.

## What it checks

| Rule   | Severity | Detects                                                          |
|--------|----------|------------------------------------------------------------------|
| MCP001 | High     | Hidden instructions aimed at the model (tool poisoning)          |
| MCP002 | High     | Invisible Unicode characters that can hide text                  |
| MCP003 | High     | Arbitrary command or code execution                              |
| MCP004 | Medium   | Unrestricted file path parameters                                |
| MCP005 | Medium   | Credentials requested as tool arguments                          |
| MCP006 | Medium   | Unrestricted URL parameters (SSRF / data exfiltration)           |
| MCP007 | Low      | Missing or meaningless tool description                          |
| MCP008 | Medium   | Destructive operations exposed to the model                      |
| MCP009 | High     | Raw SQL accepted as input                                        |
| MCP010 | Low      | Oversized descriptions that can hide instructions                |

## Usage

    uv run mcp-toolcheck scan --command "python my_server.py"
    uv run mcp-toolcheck scan --tools-file tools.json --format markdown
    uv run mcp-toolcheck scan --command "..." --fail-on medium   # exit 1 in CI

## How good are the rules?

`evals/` contains a small hand-labeled corpus (benign and risky tool definitions).
Current result: precision 1.00, recall 0.96 on 36 cases. This corpus was written by
the author and rules were tuned against it, so treat the numbers as a regression
guard, not as an independent benchmark. Known miss: paraphrased injections without
trigger phrases. Run it with `uv run python evals/run_eval.py`.

## Related work

Other MCP security scanners exist, including MCP-Scan (Invariant Labs / Snyk),
MCP Armor, mcp-tool-auditor and mcpguard. This project differs by running fully
offline with no API keys, by auditing third-party servers inside an isolated
sandbox, and by shipping its own evaluation corpus.

## Status

Early development. Rules are heuristics: every finding includes evidence so
you can decide if it is a real problem or a false positive.

## License

MIT