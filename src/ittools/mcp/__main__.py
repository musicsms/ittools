"""Entry point for running the MCP server via `python3 -m ittools.mcp`."""

from __future__ import annotations

import sys
from ittools.cli.main import main

if __name__ == "__main__":
    sys.exit(main(["mcp"] + sys.argv[1:]))
