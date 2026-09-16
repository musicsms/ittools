"""Tests for PKCS#12 / PFX creation and extraction service."""

from datetime import datetime, timedelta, timezone
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from ittools.core.pki.pfx import PFXExtractResult, create_pfx_bundle, extract_pfx_bundle


def _generate_test_key_and_cert(cn: str = "example.com", is_ca: bool = False, key_password: str | None = None):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, cn)])
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc) - timedelta(days=1))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=365))
    )
    if is_ca:
        builder = builder.add_extension(
            x509.BasicConstraints(ca=True, path_length=None),
            critical=True,
        )
    cert = builder.sign(key, hashes.SHA256())

    if key_password:
        encryption = serialization.BestAvailableEncryption(key_password.encode("utf-8"))
    else:
        encryption = serialization.NoEncryption()

    key_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=encryption,
    ).decode("utf-8")
    cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode("utf-8")
    return key_pem, cert_pem


def test_create_and_extract_pfx_with_password():
    key_pem, cert_pem = _generate_test_key_and_cert("server.local")
    pfx_bytes = create_pfx_bundle(
        private_key_pem=key_pem,
        cert_pem=cert_pem,
        password="secretpassword",
        friendly_name="TestServer",
    )
    assert isinstance(pfx_bytes, bytes)
    assert len(pfx_bytes) > 0

    result = extract_pfx_bundle(pfx_bytes, password="secretpassword")
    assert isinstance(result, PFXExtractResult)
    assert result.private_key_pem is not None
    assert "BEGIN PRIVATE KEY" in result.private_key_pem
    assert result.cert_pem is not None
    assert "BEGIN CERTIFICATE" in result.cert_pem
    assert result.friendly_name == "TestServer"
    assert result.ca_certs_pem == []


def test_create_and_extract_pfx_without_password():
    key_pem, cert_pem = _generate_test_key_and_cert("nopass.local")
    pfx_bytes = create_pfx_bundle(
        private_key_pem=key_pem,
        cert_pem=cert_pem,
        password=None,
    )
    assert isinstance(pfx_bytes, bytes)
    result = extract_pfx_bundle(pfx_bytes, password=None)
    assert result.private_key_pem is not None
    assert result.cert_pem is not None


def test_create_pfx_with_ca_chain_list():
    key_pem, cert_pem = _generate_test_key_and_cert("leaf.local")
    _, ca1_pem = _generate_test_key_and_cert("Intermediate CA", is_ca=True)
    _, ca2_pem = _generate_test_key_and_cert("Root CA", is_ca=True)

    pfx_bytes = create_pfx_bundle(
        private_key_pem=key_pem,
        cert_pem=cert_pem,
        ca_certs_pem=[ca1_pem, ca2_pem],
        password="chainpwd",
    )
    result = extract_pfx_bundle(pfx_bytes, password="chainpwd")
    assert len(result.ca_certs_pem) == 2
    assert ca1_pem in result.ca_certs_pem
    assert ca2_pem in result.ca_certs_pem


def test_create_pfx_with_ca_chain_string():
    key_pem, cert_pem = _generate_test_key_and_cert("leaf.local")
    _, ca1_pem = _generate_test_key_and_cert("Intermediate CA", is_ca=True)
    _, ca2_pem = _generate_test_key_and_cert("Root CA", is_ca=True)
    combined_ca_pem = f"{ca1_pem}\n{ca2_pem}"

    pfx_bytes = create_pfx_bundle(
        private_key_pem=key_pem,
        cert_pem=cert_pem,
        ca_certs_pem=combined_ca_pem,
        password="chainpwd",
    )
    result = extract_pfx_bundle(pfx_bytes, password="chainpwd")
    assert len(result.ca_certs_pem) == 2


def test_create_pfx_with_encrypted_private_key():
    key_pem, cert_pem = _generate_test_key_and_cert("enckey.local", key_password="mypassword")
    pfx_bytes = create_pfx_bundle(
        private_key_pem=key_pem,
        cert_pem=cert_pem,
        password="bundlepassword",
        key_password="mypassword",
    )
    result = extract_pfx_bundle(pfx_bytes, password="bundlepassword")
    assert result.private_key_pem is not None
    assert "BEGIN PRIVATE KEY" in result.private_key_pem


def test_extract_pfx_invalid_password():
    key_pem, cert_pem = _generate_test_key_and_cert("pwd.local")
    pfx_bytes = create_pfx_bundle(key_pem, cert_pem, password="correct")
    with pytest.raises(ValueError, match="Failed to decrypt or parse PKCS#12"):
        extract_pfx_bundle(pfx_bytes, password="wrong")


def test_create_pfx_invalid_private_key():
    _, cert_pem = _generate_test_key_and_cert("invalidkey.local")
    with pytest.raises(ValueError, match="Failed to load private key"):
        create_pfx_bundle("not-a-private-key", cert_pem)


def test_create_pfx_invalid_certificate():
    key_pem, _ = _generate_test_key_and_cert("invalidcert.local")
    with pytest.raises(ValueError, match="Failed to load certificate"):
        create_pfx_bundle(key_pem, "not-a-cert")


def test_create_pfx_invalid_ca_certificate():
    key_pem, cert_pem = _generate_test_key_and_cert("leaf.local")
    with pytest.raises(ValueError, match="Failed to load CA certificate"):
        create_pfx_bundle(key_pem, cert_pem, ca_certs_pem=["not-a-ca-cert"])
