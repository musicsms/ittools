"""Server TLS configuration generator tool for the Model Context Protocol (MCP) server."""

from __future__ import annotations

import os

from ittools.core.config_gen.generator import generate_server_config
from ittools.mcp.tools.pki import _write_public_file


def config_generate(
    server: str,
    profile: str = "intermediate",
    domain: str = "example.com",
    cert_path: str = "/etc/ssl/certs/cert.pem",
    key_path: str = "/etc/ssl/private/key.pem",
    hsts: bool = True,
    output_path: str | None = None,
    force: bool = False,
) -> dict:
    """Generate hardened server TLS virtual host configurations adhering to Mozilla guidelines.

    Args:
        server: Target web server type ('nginx', 'apache', or 'caddy').
        profile: TLS security profile ('intermediate' or 'modern', default: 'intermediate').
        domain: Domain name for the virtual host configuration (default: 'example.com').
        cert_path: Destination path for the certificate file (default: '/etc/ssl/certs/cert.pem').
        key_path: Destination path for the private key file (default: '/etc/ssl/private/key.pem').
        hsts: Whether to enable HTTP Strict Transport Security (default: True).
        output_path: Optional destination file path to persist configuration (mode 0644).
        force: Overwrite existing target file if True.

    Returns:
        Dictionary containing:
            - server: Normalized server name.
            - profile: Normalized profile name.
            - config: Rendered server configuration string.
            - saved_to: Destination path if output_path was provided, otherwise None.

    Raises:
        ValueError: If server or profile is unsupported.
        FileExistsError: If output_path exists and force is False.
    """
    if output_path:
        if not force and os.path.exists(output_path):
            raise FileExistsError(
                f"Target file already exists: {output_path} (use force=True to overwrite)"
            )

    config_content = generate_server_config(
        server=server,
        profile=profile,
        domain=domain,
        cert_path=cert_path,
        key_path=key_path,
        hsts=hsts,
    )

    saved_to: str | None = None
    if output_path:
        _write_public_file(output_path, config_content, force=force)
        saved_to = output_path

    server_norm = server.strip().lower() if isinstance(server, str) else server
    profile_norm = profile.strip().lower() if isinstance(profile, str) else profile

    return {
        "server": server_norm,
        "profile": profile_norm,
        "config": config_content,
        "saved_to": saved_to,
    }
