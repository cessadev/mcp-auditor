# mcp-auditor

Static security auditor for [MCP](https://modelcontextprotocol.io) (Model Context Protocol) servers.

MCP lets AI agents call external tools, but a tool's name, description and
input schema are plain text that the model reads and trusts. A malicious or
careless server can hide instructions in that text, ask for credentials, or
expose dangerous capabilities. `mcp-auditor` inspects what a server declares
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

## Status

Early development. Rules are heuristics: every finding includes evidence so
you can decide if it is a real problem or a false positive.

## License

MIT