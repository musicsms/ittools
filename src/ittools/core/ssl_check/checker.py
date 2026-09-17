"""Remote SSL/TLS certificate inspector."""

from __future__ import annotations

from dataclasses import dataclass, field
import datetime
import socket
import ssl
from typing import Any

from cryptography import x509


@dataclass
class SSLReport:
    """Report containing remote SSL/TLS certificate inspection details."""

    host: str
    port: int
    subject: str
    issuer: str
    valid_from: str
    valid_to: str
    days_remaining: int
    is_expired: bool
    sans: list[str] = field(default_factory=list)
    tls_version: str = ""
    cipher_suite: str = ""
    warning: str | None = None
    is_valid_chain: bool = True


def _fetch_peer_cert_and_info(
    host: str,
    port: int = 443,
    timeout: float = 10.0,
) -> dict[str, Any]:
    """Connect to a remote host and retrieve its TLS peer certificate info.

    Args:
        host: Hostname or IP address to connect to.
        port: Destination port (default 443).
        timeout: Socket timeout in seconds.

    Returns:
        Dict containing raw parsed certificate properties.

    Raises:
        ValueError: If no peer certificate was received.
        OSError: If connection or TLS handshake fails.
    """
    is_valid_chain = True
    verification_error_msg: str | None = None

    try:
        context = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                der = ssock.getpeercert(binary_form=True)
                tls_version = ssock.version() or ""
                cipher = ssock.cipher()
                cipher_suite = cipher[0] if cipher else ""
    except ssl.SSLCertVerificationError as e:
        is_valid_chain = False
        verification_error_msg = str(e)
        if hasattr(ssl, "_create_unverified_context"):
            insecure_ctx = ssl._create_unverified_context()
        else:
            insecure_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            insecure_ctx.check_hostname = False
            insecure_ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with insecure_ctx.wrap_socket(sock, server_hostname=host) as ssock:
                der = ssock.getpeercert(binary_form=True)
                tls_version = ssock.version() or ""
                cipher = ssock.cipher()
                cipher_suite = cipher[0] if cipher else ""

    if not der:
        raise ValueError(f"No peer certificate received from {host}:{port}")

    cert = x509.load_der_x509_certificate(der)

    valid_from = cert.not_valid_before_utc.strftime("%Y-%m-%dT%H:%M:%SZ")
    valid_to = cert.not_valid_after_utc.strftime("%Y-%m-%dT%H:%M:%SZ")

    now = datetime.datetime.now(datetime.timezone.utc)
    days_remaining = (cert.not_valid_after_utc - now).days
    is_expired = now > cert.not_valid_after_utc

    sans: list[str] = []
    try:
        san_ext = cert.extensions.get_extension_for_oid(
            x509.ExtensionOID.SUBJECT_ALTERNATIVE_NAME
        )
        for item in san_ext.value:
            sans.append(str(item.value))
    except x509.ExtensionNotFound:
        pass

    warning: str | None = None
    if is_expired:
        warning = "Certificate has expired"
    elif days_remaining < 30:
        warning = f"Certificate expires soon ({days_remaining} days remaining)"

    if verification_error_msg:
        if warning:
            warning = f"{verification_error_msg}; {warning}"
        else:
            warning = verification_error_msg

    return {
        "subject": cert.subject.rfc4514_string(),
        "issuer": cert.issuer.rfc4514_string(),
        "valid_from": valid_from,
        "valid_to": valid_to,
        "days_remaining": days_remaining,
        "is_expired": is_expired,
        "sans": sans,
        "tls_version": tls_version,
        "cipher_suite": cipher_suite,
        "warning": warning,
        "is_valid_chain": is_valid_chain,
    }


def check_remote_ssl(
    host: str,
    port: int = 443,
    timeout: float = 10.0,
) -> SSLReport:
    """Inspect the SSL/TLS certificate of a remote host.

    Args:
        host: Hostname or IP address.
        port: Port number (default 443).
        timeout: Network timeout in seconds (default 10.0).

    Returns:
        SSLReport with validity details, SANs, TLS version, and any warnings.
    """
    info = _fetch_peer_cert_and_info(host, port, timeout)

    is_expired = info.get("is_expired", False)
    days_remaining = info.get("days_remaining", 0)

    warning = info.get("warning")
    if warning is None:
        if is_expired:
            warning = "Certificate has expired"
        elif days_remaining < 30:
            warning = f"Certificate expires soon ({days_remaining} days remaining)"

    return SSLReport(
        host=host,
        port=port,
        subject=info.get("subject", ""),
        issuer=info.get("issuer", ""),
        valid_from=info.get("valid_from", ""),
        valid_to=info.get("valid_to", ""),
        days_remaining=days_remaining,
        is_expired=is_expired,
        sans=info.get("sans", []),
        tls_version=info.get("tls_version", ""),
        cipher_suite=info.get("cipher_suite", ""),
        warning=warning,
        is_valid_chain=info.get("is_valid_chain", True),
    )


inspect_ssl_cert = check_remote_ssl

