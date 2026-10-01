#!/usr/bin/env bash
# Audits a third-party MCP server published on PyPI, in two isolated phases.
# Usage: scripts/audit-pypi.sh <pypi-package> [entrypoint] [extra scan flags...]
# Example: scripts/audit-pypi.sh mcp-server-fetch mcp-server-fetch --format markdown
set -euo pipefail

PKG="${1:?usage: audit-pypi.sh <pypi-package> [entrypoint] [extra scan flags...]}"
ENTRY="${2:-$PKG}"

if [[ ! "$PKG" =~ ^[A-Za-z0-9._-]+$ || ! "$ENTRY" =~ ^[A-Za-z0-9._-]+$ ]]; then
  echo "error: invalid package or entrypoint name" >&2
  exit 2
fi

echo ">> Phase 1/2 (network ON): install wheels only into an isolated venv" >&2
docker compose run --rm -T prepare uv venv --allow-existing "/targets/$PKG" >&2
docker compose run --rm -T prepare uv pip install --python "/targets/$PKG/bin/python" --no-build "$PKG" >&2

echo ">> Phase 2/2 (network OFF, read-only fs): audit the server" >&2
docker compose run --rm -T sandbox /opt/venv/bin/mcp-toolcheck scan \
  --fail-on never "${@:3}" --command "/targets/$PKG/bin/$ENTRY"