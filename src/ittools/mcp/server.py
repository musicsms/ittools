"""Model Context Protocol (MCP) server instance setup, tool registration, and execution."""

from __future__ import annotations

try:
    from mcp.server.mcpserver import MCPServer
except ImportError:  # pragma: no cover
    try:
        from mcp.server.fastmcp import FastMCP as MCPServer
    except ImportError as exc:
        raise ImportError(
            "The 'mcp' package is required to run the MCP server. "
            'Install it with: pip install "ittools[mcp]"'
        ) from exc

from ittools.mcp.tools import (
    adcs_ca_cert,
    adcs_retrieve,
    adcs_sign,
    config_generate,
    csr_decode,
    csr_generate,
    keypair_passphrase,
    keypair_pgp,
    keypair_rsa,
    keypair_ssh,
    pfx_create,
    pfx_extract,
    ssl_check,
    ssl_headers,
    ssl_match,
)


def create_mcp_server() -> MCPServer:
    """Create and configure the ittools MCP server instance with all tools registered."""
    server = MCPServer(
        "ittools",
        instructions="IT, PKI, ADCS, Keypair, and SSL/TLS automation toolkit",
    )

    tools = [
        # PKI tools
        csr_generate,
        csr_decode,
        pfx_create,
        pfx_extract,
        ssl_match,
        # Keypair tools
        keypair_passphrase,
        keypair_rsa,
        keypair_ssh,
        keypair_pgp,
        # SSL tools
        ssl_check,
        ssl_headers,
        # Config tool
        config_generate,
        # ADCS tools
        adcs_sign,
        adcs_retrieve,
        adcs_ca_cert,
    ]

    for tool_fn in tools:
        server.tool()(tool_fn)

    return server


def run_mcp_server(transport: str = "stdio", port: int = 8000) -> None:
    """Run the MCP server on the specified transport (stdio or sse)."""
    server = create_mcp_server()
    if transport == "sse":
        server.run(transport="sse", port=port)
    elif transport == "stdio":
        server.run(transport="stdio")
    else:
        raise ValueError(f"Unsupported transport: {transport} (expected 'stdio' or 'sse')")
