"""CLI commands for running the ittools Model Context Protocol (MCP) server."""

from __future__ import annotations

import argparse
import sys


def handle_mcp(args: argparse.Namespace) -> int:
    """Handle 'mcp' CLI subcommand execution."""
    try:
        from ittools.mcp.server import create_mcp_server, run_mcp_server
    except (ImportError, ModuleNotFoundError):
        sys.stderr.write(
            "error: The 'mcp' package is required to run the MCP server.\n"
            'Install it with: pip install "ittools[mcp]"\n'
        )
        return 1

    try:
        run_mcp_server(transport=args.transport, port=args.port)
        return 0
    except (ImportError, ModuleNotFoundError):
        sys.stderr.write(
            "error: The 'mcp' package is required to run the MCP server.\n"
            'Install it with: pip install "ittools[mcp]"\n'
        )
        return 1


def register_mcp_commands(subparsers: argparse._SubParsersAction) -> None:
    """Register 'mcp' command and arguments."""
    parser = subparsers.add_parser(
        "mcp",
        help="Run the native Model Context Protocol (MCP) server",
        description="Run the native Model Context Protocol (MCP) server for AI assistants",
    )
    parser.add_argument(
        "--transport",
        choices=["stdio", "sse"],
        default="stdio",
        help="Transport protocol (default: stdio)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=8000,
        help="Port for SSE transport (default: 8000)",
    )
    parser.set_defaults(handler=handle_mcp)
