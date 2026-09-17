"""SSL/TLS inspection and HTTP security headers tools for the Model Context Protocol (MCP) server."""

from __future__ import annotations

import dataclasses

from ittools.core.ssl_check.checker import inspect_ssl_cert
from ittools.core.ssl_check.headers import analyze_security_headers


def ssl_check(
    host: str,
    port: int = 443,
    timeout: float = 10.0,
) -> dict:
    """Connect to a remote host over TLS to inspect the leaf certificate, cipher suite, and validity chain.

    Args:
        host: Remote hostname or IP address.
        port: Destination port number (default: 443).
        timeout: Network socket timeout in seconds (default: 10.0).

    Returns:
        Dictionary representation of the SSLReport containing host, port, subject, issuer,
        validity dates, days remaining, expiration status, SANs, TLS version, cipher suite,
        warnings, and chain validity.

    Raises:
        ValueError: If no peer certificate was received.
        OSError: If connection or TLS handshake fails.
    """
    report = inspect_ssl_cert(host=host, port=port, timeout=timeout)
    return dataclasses.asdict(report)


def ssl_headers(
    url: str,
    timeout: float = 10.0,
) -> dict:
    """Inspect and grade HTTP security headers for a given website URL.

    Args:
        url: The website URL to inspect (defaults to https:// if scheme is omitted).
        timeout: HTTP request timeout in seconds (default: 10.0).

    Returns:
        Dictionary representation of the HeadersReport containing URL, HTTP status code,
        present security headers, missing security headers, letter grade security score,
        and actionable recommendations.

    Raises:
        requests.RequestException: If the HTTP request fails or times out.
    """
    report = analyze_security_headers(url=url, timeout=timeout)
    return dataclasses.asdict(report)
