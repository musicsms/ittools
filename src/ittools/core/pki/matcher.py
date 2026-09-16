"""PKI private key and certificate/CSR matching service."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib

from cryptography import x509
from cryptography.hazmat.primitives import serialization


@dataclass
class MatchResult:
    """Result of checking whether a private key matches a certificate or CSR."""

    matched: bool
    key_hash: str
    cert_hash: str
    message: str


def match_key_and_cert(
    private_key_pem: str,
    cert_or_csr_pem: str,
) -> MatchResult:
    """Check whether a private key matches an X.509 certificate or CSR.

    Extracts the SubjectPublicKeyInfo DER bytes from both keys, calculates
    their SHA-256 hashes, and compares them.

    Args:
        private_key_pem: PEM string of the private key.
        cert_or_csr_pem: PEM string of the certificate or CSR.

    Returns:
        MatchResult with matched status, public key SHA256 hashes, and message.

    Raises:
        ValueError: If private key or certificate/CSR PEM cannot be parsed.
    """
    # Parse private key
    try:
        priv_key = serialization.load_pem_private_key(
            private_key_pem.strip().encode("utf-8"),
            password=None,
        )
    except Exception as e:
        raise ValueError(f"Could not parse private key PEM: {e}") from e

    # Parse certificate or CSR
    data_bytes = cert_or_csr_pem.strip().encode("utf-8")
    pub_key = None

    # Try X.509 Certificate first
    try:
        cert = x509.load_pem_x509_certificate(data_bytes)
        pub_key = cert.public_key()
    except Exception:
        pass

    # Try X.509 CSR next
    if pub_key is None:
        try:
            csr = x509.load_pem_x509_csr(data_bytes)
            pub_key = csr.public_key()
        except Exception:
            pass

    # Try public key PEM directly as a fallback
    if pub_key is None:
        try:
            pub_key = serialization.load_pem_public_key(data_bytes)
        except Exception:
            pass

    if pub_key is None:
        raise ValueError("Could not parse certificate or CSR PEM")

    # Extract DER encoded SubjectPublicKeyInfo
    key_spki = priv_key.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    cert_spki = pub_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    key_hash = hashlib.sha256(key_spki).hexdigest()
    cert_hash = hashlib.sha256(cert_spki).hexdigest()
    matched = (key_hash == cert_hash)

    if matched:
        message = "The private key matches the certificate/CSR (SHA-256 public key hash matches)."
    else:
        message = "The private key does NOT match the certificate/CSR (SHA-256 public key hashes differ)."

    return MatchResult(
        matched=matched,
        key_hash=key_hash,
        cert_hash=cert_hash,
        message=message,
    )
