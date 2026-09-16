"""Server TLS configuration generator following Mozilla SSL guidelines."""

from __future__ import annotations

SUPPORTED_SERVERS = {"nginx", "apache", "caddy"}
SUPPORTED_PROFILES = {"intermediate", "modern"}

# Standard Mozilla Intermediate Ciphers (OpenSSL format)
OPENSSL_INTERMEDIATE_CIPHERS = (
    "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:"
    "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:"
    "ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:"
    "DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384"
)

# Standard Mozilla Intermediate Ciphers (IANA / Go / Caddy format)
CADDY_INTERMEDIATE_CIPHERS = (
    "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 "
    "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 "
    "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 "
    "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 "
    "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 "
    "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256"
)


def _generate_nginx(
    profile: str, domain: str, cert_path: str, key_path: str, hsts: bool
) -> str:
    """Generate Nginx TLS virtual host block."""
    if profile == "modern":
        profile_block = (
            "    # Modern configuration\n"
            "    ssl_protocols TLSv1.3;\n"
            "    ssl_prefer_server_ciphers off;"
        )
    else:
        profile_block = (
            "    # Intermediate configuration\n"
            "    ssl_protocols TLSv1.2 TLSv1.3;\n"
            f"    ssl_ciphers {OPENSSL_INTERMEDIATE_CIPHERS};\n"
            "    ssl_prefer_server_ciphers off;"
        )

    lines = [
        "server {",
        "    listen 443 ssl http2;",
        "    listen [::]:443 ssl http2;",
        f"    server_name {domain};",
        "",
        f"    ssl_certificate {cert_path};",
        f"    ssl_certificate_key {key_path};",
        "    ssl_session_timeout 1d;",
        "    ssl_session_cache shared:SSL:10m;",
        "    ssl_session_tickets off;",
        "",
        profile_block,
    ]
    if hsts:
        lines.extend([
            "",
            "    # HSTS (63072000 seconds)",
            '    add_header Strict-Transport-Security "max-age=63072000" always;',
        ])
    lines.append("}")
    return "\n".join(lines) + "\n"


def _generate_apache(
    profile: str, domain: str, cert_path: str, key_path: str, hsts: bool
) -> str:
    """Generate Apache TLS virtual host block."""
    if profile == "modern":
        profile_block = (
            "    # Modern configuration\n"
            "    SSLProtocol all -SSLv3 -TLSv1 -TLSv1.1 -TLSv1.2\n"
            f"    SSLCipherSuite {OPENSSL_INTERMEDIATE_CIPHERS}\n"
            "    SSLHonorCipherOrder off\n"
            "    SSLSessionTickets off"
        )
    else:
        profile_block = (
            "    # Intermediate configuration\n"
            "    SSLProtocol all -SSLv3 -TLSv1 -TLSv1.1\n"
            f"    SSLCipherSuite {OPENSSL_INTERMEDIATE_CIPHERS}\n"
            "    SSLHonorCipherOrder off\n"
            "    SSLSessionTickets off"
        )

    lines = [
        "<VirtualHost *:443>",
        f"    ServerName {domain}",
        "    SSLEngine on",
        "",
        f"    SSLCertificateFile {cert_path}",
        f"    SSLCertificateKeyFile {key_path}",
        "",
        profile_block,
    ]
    if hsts:
        lines.extend([
            "",
            "    # HSTS (63072000 seconds)",
            '    Header always set Strict-Transport-Security "max-age=63072000"',
        ])
    lines.append("</VirtualHost>")
    return "\n".join(lines) + "\n"


def _generate_caddy(
    profile: str, domain: str, cert_path: str, key_path: str, hsts: bool
) -> str:
    """Generate Caddyfile TLS block."""
    if profile == "modern":
        tls_block = (
            f"    tls {cert_path} {key_path} {{\n"
            "        protocols tls1.3\n"
            "    }"
        )
    else:
        tls_block = (
            f"    tls {cert_path} {key_path} {{\n"
            "        protocols tls1.2 tls1.3\n"
            f"        ciphers {CADDY_INTERMEDIATE_CIPHERS}\n"
            "    }"
        )

    lines = [
        f"{domain} {{",
        tls_block,
    ]
    if hsts:
        lines.extend([
            "",
            "    # HSTS (63072000 seconds)",
            '    header Strict-Transport-Security "max-age=63072000;"',
        ])
    lines.append("}")
    return "\n".join(lines) + "\n"


def generate_server_config(
    server: str,
    profile: str = "intermediate",
    domain: str = "example.com",
    cert_path: str = "/etc/ssl/certs/cert.pem",
    key_path: str = "/etc/ssl/private/key.pem",
    hsts: bool = True,
) -> str:
    """Generate hardened server TLS configuration adhering to Mozilla guidelines.

    Args:
        server: Target server type ('nginx', 'apache', or 'caddy'), case-insensitive.
        profile: TLS security profile ('intermediate' or 'modern'), case-insensitive.
        domain: Domain name for the virtual host block.
        cert_path: Filesystem path to the SSL/TLS certificate file.
        key_path: Filesystem path to the SSL/TLS private key file.
        hsts: Whether to include HTTP Strict Transport Security (HSTS) header.

    Returns:
        Rendered configuration block as a string.

    Raises:
        ValueError: If server or profile is unsupported.
    """
    if not isinstance(server, str) or not server.strip():
        raise ValueError(
            f"Unsupported server: {server}. Supported servers: nginx, apache, caddy"
        )
    if not isinstance(profile, str) or not profile.strip():
        raise ValueError(
            f"Unsupported profile: {profile}. Supported profiles: intermediate, modern"
        )

    server_clean = server.strip().lower()
    profile_clean = profile.strip().lower()

    if server_clean not in SUPPORTED_SERVERS:
        raise ValueError(
            f"Unsupported server: '{server}'. Supported servers: {', '.join(sorted(SUPPORTED_SERVERS))}"
        )

    if profile_clean not in SUPPORTED_PROFILES:
        raise ValueError(
            f"Unsupported profile: '{profile}'. Supported profiles: {', '.join(sorted(SUPPORTED_PROFILES))}"
        )

    domain_val = domain.strip() if isinstance(domain, str) and domain.strip() else "example.com"
    cert_val = cert_path.strip() if isinstance(cert_path, str) and cert_path.strip() else "/etc/ssl/certs/cert.pem"
    key_val = key_path.strip() if isinstance(key_path, str) and key_path.strip() else "/etc/ssl/private/key.pem"

    if server_clean == "nginx":
        return _generate_nginx(
            profile=profile_clean,
            domain=domain_val,
            cert_path=cert_val,
            key_path=key_val,
            hsts=bool(hsts),
        )
    elif server_clean == "apache":
        return _generate_apache(
            profile=profile_clean,
            domain=domain_val,
            cert_path=cert_val,
            key_path=key_val,
            hsts=bool(hsts),
        )
    elif server_clean == "caddy":
        return _generate_caddy(
            profile=profile_clean,
            domain=domain_val,
            cert_path=cert_val,
            key_path=key_val,
            hsts=bool(hsts),
        )

    raise ValueError(f"Unsupported server: {server}")
