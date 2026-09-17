"""Model Context Protocol (MCP) server subsystem for ittools."""

from __future__ import annotations

from typing import Any

__all__ = ["tools", "create_mcp_server", "run_mcp_server"]


def __getattr__(name: str) -> Any:
    if name in ("create_mcp_server", "run_mcp_server"):
        from ittools.mcp.server import create_mcp_server, run_mcp_server

        return {"create_mcp_server": create_mcp_server, "run_mcp_server": run_mcp_server}[name]
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
