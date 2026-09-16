"""PKCS#12 (PFX) container serialization and extraction service."""

from __future__ import annotations

from dataclasses import dataclass

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import pkcs12


@dataclass(frozen=True)
class PFXExtractResult:
    """Result of extracting a PKCS#12 bundle."""

    private_key_pem: str | None
    cert_pem: str | None
    ca_certs_pem: list[str]
    friendly_name: str | None


def create_pfx_bundle(
    private_key_pem: str,
    cert_pem: str,
    ca_certs_pem: list[str] | str | None = None,
    password: str | None = None,
    friendly_name: str | None = None,
    key_password: str | None = None,
) -> bytes:
    """Serialize a private key, certificate, and optional CA certificates into PKCS#12 bytes.

    Args:
        private_key_pem: PEM-encoded private key.
        cert_pem: PEM-encoded end-entity certificate.
        ca_certs_pem: Optional list of PEM CA certificates or multi-cert PEM bundle string.
        password: Password for the PFX container.
        friendly_name: Optional alias name for the certificate.
        key_password: Password to decrypt private_key_pem if encrypted.

    Returns:
        Binary bytes of the PKCS#12 container.

    Raises:
        ValueError: If private key, certificate, or CA certificates cannot be loaded.
    """
    key_pass_bytes = key_password.encode("utf-8") if key_password else None
    try:
        private_key = serialization.load_pem_private_key(
            private_key_pem.encode("utf-8"),
            password=key_pass_bytes,
        )
    except Exception as exc:
        raise ValueError(f"Failed to load private key: {exc}") from exc

    try:
        leaf_cert = x509.load_pem_x509_certificate(cert_pem.encode("utf-8"))
    except Exception as exc:
        raise ValueError(f"Failed to load certificate: {exc}") from exc

    cas: list[x509.Certificate] = []
    if ca_certs_pem:
        if isinstance(ca_certs_pem, str):
            try:
                cas = list(x509.load_pem_x509_certificates(ca_certs_pem.encode("utf-8")))
            except Exception as exc:
                raise ValueError(f"Failed to load CA certificate bundle: {exc}") from exc
        else:
            for item in ca_certs_pem:
                try:
                    cas.extend(x509.load_pem_x509_certificates(item.encode("utf-8")))
                except Exception as exc:
                    raise ValueError(f"Failed to load CA certificate: {exc}") from exc

    encryption_algo: serialization.KeySerializationEncryption
    if password:
        encryption_algo = serialization.BestAvailableEncryption(password.encode("utf-8"))
    else:
        encryption_algo = serialization.NoEncryption()

    name_bytes = friendly_name.encode("utf-8") if friendly_name else None

    return pkcs12.serialize_key_and_certificates(
        name=name_bytes,
        key=private_key,
        cert=leaf_cert,
        cas=cas if cas else None,
        encryption_algorithm=encryption_algo,
    )


def extract_pfx_bundle(
    pfx_bytes: bytes,
    password: str | None = None,
) -> PFXExtractResult:
    """Extract private key, leaf certificate, and CA certificates from PKCS#12 bytes.

    Args:
        pfx_bytes: Binary bytes of .pfx/.p12 file.
        password: Password for the PFX archive (None if unencrypted).

    Returns:
        PFXExtractResult containing extracted PEM components.

    Raises:
        ValueError: If decryption or parsing fails.
    """
    pwd_bytes = password.encode("utf-8") if password else None
    try:
        p12 = pkcs12.load_pkcs12(
            pfx_bytes,
            password=pwd_bytes,
        )
    except Exception as exc:
        raise ValueError(f"Failed to decrypt or parse PKCS#12: {exc}") from exc

    key_pem: str | None = None
    if p12.key is not None:
        key_pem = p12.key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode("utf-8")

    cert_pem: str | None = None
    friendly_name: str | None = None
    if p12.cert is not None:
        cert_pem = p12.cert.certificate.public_bytes(serialization.Encoding.PEM).decode("utf-8")
        if p12.cert.friendly_name is not None:
            friendly_name = p12.cert.friendly_name.decode("utf-8")

    ca_pems: list[str] = []
    if p12.additional_certs:
        for ca in p12.additional_certs:
            ca_pems.append(ca.certificate.public_bytes(serialization.Encoding.PEM).decode("utf-8"))

    return PFXExtractResult(
        private_key_pem=key_pem,
        cert_pem=cert_pem,
        ca_certs_pem=ca_pems,
        friendly_name=friendly_name,
    )
