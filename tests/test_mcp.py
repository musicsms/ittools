"""Tests for ittools Model Context Protocol (MCP) server subsystem and tools."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import os
from pathlib import Path
import pytest

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from ittools.mcp.tools.pki import (
    csr_decode,
    csr_generate,
    pfx_create,
    pfx_extract,
    ssl_match,
)


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


def test_mcp_csr_generate_in_memory():
    """Verify csr_generate operates entirely in-memory when output_dir is omitted."""
    res = csr_generate(
        common_name="api.example.com",
        organization="Acme Corp",
        organizational_unit="Engineering",
        city="San Francisco",
        state="CA",
        country="US",
        email="dev@example.com",
        sans=["api.example.com", "api-backup.example.com"],
        key_size=2048,
    )

    assert isinstance(res, dict)
    assert res["common_name"] == "api.example.com"
    assert "-----BEGIN RSA PRIVATE KEY-----" in res["private_key_pem"] or "-----BEGIN PRIVATE KEY-----" in res["private_key_pem"]
    assert "-----BEGIN CERTIFICATE REQUEST-----" in res["csr_pem"]
    assert res["saved_files"] == []

    # Verify generated CSR content can be decoded cleanly
    decoded = csr_decode(res["csr_pem"])
    assert decoded["common_name"] == "api.example.com"
    assert decoded["organization"] == "Acme Corp"
    assert decoded["country"] == "US"
    assert "api-backup.example.com" in decoded["sans"]


def test_mcp_csr_generate_with_output_dir(tmp_path: Path):
    """Verify csr_generate writes files with 0600 on private key and respects force guard."""
    out_dir = tmp_path / "csr_output"
    res = csr_generate(
        common_name="secure.test.org",
        output_dir=str(out_dir),
    )

    assert len(res["saved_files"]) == 2
    key_path = Path(res["saved_files"][0] if res["saved_files"][0].endswith(".key") else res["saved_files"][1])
    csr_path = Path(res["saved_files"][1] if res["saved_files"][1].endswith(".csr") else res["saved_files"][0])

    assert key_path.exists()
    assert csr_path.exists()
    assert key_path.read_text(encoding="utf-8") == res["private_key_pem"]
    assert csr_path.read_text(encoding="utf-8") == res["csr_pem"]

    # Verify mode 0600 (-rw-------) on private key
    key_mode = os.stat(key_path).st_mode & 0o777
    assert key_mode == 0o600

    # Overwrite protection: force=False must raise FileExistsError upfront
    with pytest.raises(FileExistsError, match="Target file already exists"):
        csr_generate(common_name="secure.test.org", output_dir=str(out_dir), force=False)

    # With force=True, generation should succeed
    res2 = csr_generate(common_name="secure.test.org", output_dir=str(out_dir), force=True)
    assert len(res2["saved_files"]) == 2


def test_mcp_csr_decode():
    """Verify csr_decode extracts CSR subject, SANs, and key metadata."""
    res = csr_generate(
        common_name="decode.example.com",
        organization="Test Org",
        country="US",
        sans=["decode.example.com", "alt.example.com"],
        key_size=2048,
    )

    decoded = csr_decode(res["csr_pem"])
    assert decoded["common_name"] == "decode.example.com"
    assert decoded["organization"] == "Test Org"
    assert decoded["country"] == "US"
    assert decoded["sans"] == ["decode.example.com", "alt.example.com"]
    assert decoded["key_type"] == "RSA"
    assert decoded["key_size"] == 2048
    assert decoded["signature_algorithm"] != ""

    # Invalid CSR should raise ValueError
    with pytest.raises(ValueError, match="Could not parse CSR PEM"):
        csr_decode("INVALID_PEM_DATA")


def test_mcp_pfx_create_and_extract_flow(tmp_path: Path):
    """Verify pfx_create and pfx_extract supporting both base64 and file path workflows."""
    key_pem, cert_pem = _generate_test_key_and_cert("bundle.local")
    _, ca_pem = _generate_test_key_and_cert("CA Root", is_ca=True)

    # 1. In-memory round-trip via base64
    create_mem = pfx_create(
        private_key_pem=key_pem,
        cert_pem=cert_pem,
        ca_certs_pem=ca_pem,
        password="testpassword",
        friendly_name="MyBundle",
    )
    assert create_mem["pfx_base64"]
    assert create_mem["size_bytes"] > 0
    assert create_mem["friendly_name"] == "MyBundle"
    assert create_mem["saved_to"] is None

    extract_mem = pfx_extract(
        pfx_data_or_path=create_mem["pfx_base64"],
        password="testpassword",
    )
    assert extract_mem["private_key_pem"] is not None
    assert "BEGIN PRIVATE KEY" in extract_mem["private_key_pem"]
    assert extract_mem["cert_pem"] is not None
    assert "BEGIN CERTIFICATE" in extract_mem["cert_pem"]
    assert len(extract_mem["ca_certs_pem"]) == 1
    assert extract_mem["friendly_name"] == "MyBundle"
    assert extract_mem["saved_files"] == []

    # 2. File persistence round-trip with 0600 mode and force guard
    pfx_file = tmp_path / "test_bundle.pfx"
    create_file = pfx_create(
        private_key_pem=key_pem,
        cert_pem=cert_pem,
        ca_certs_pem=ca_pem,
        password="testpassword",
        friendly_name="FileBundle",
        output_path=str(pfx_file),
    )
    assert create_file["saved_to"] == str(pfx_file)
    assert pfx_file.exists()
    pfx_mode = os.stat(pfx_file).st_mode & 0o777
    assert pfx_mode == 0o600

    # Overwrite protection on pfx_create
    with pytest.raises(FileExistsError, match="Target file already exists"):
        pfx_create(
            private_key_pem=key_pem,
            cert_pem=cert_pem,
            output_path=str(pfx_file),
            force=False,
        )

    # Overwrite allowed when force=True
    create_file_forced = pfx_create(
        private_key_pem=key_pem,
        cert_pem=cert_pem,
        ca_certs_pem=ca_pem,
        password="testpassword",
        output_path=str(pfx_file),
        force=True,
    )
    assert create_file_forced["saved_to"] == str(pfx_file)

    # 3. Extraction from file path to disk
    extract_dir = tmp_path / "extracted_pfx"
    extract_file = pfx_extract(
        pfx_data_or_path=str(pfx_file),
        password="testpassword",
        output_dir=str(extract_dir),
    )
    assert len(extract_file["saved_files"]) == 3
    key_files = [f for f in extract_file["saved_files"] if f.endswith(".key")]
    assert len(key_files) == 1
    extracted_key_path = Path(key_files[0])
    assert extracted_key_path.exists()
    extracted_key_mode = os.stat(extracted_key_path).st_mode & 0o777
    assert extracted_key_mode == 0o600

    # Overwrite protection on pfx_extract
    with pytest.raises(FileExistsError, match="Target file already exists"):
        pfx_extract(
            pfx_data_or_path=str(pfx_file),
            password="testpassword",
            output_dir=str(extract_dir),
            force=False,
        )


def test_mcp_ssl_match():
    """Verify ssl_match confirms matching key/cert pairs and detects mismatches."""
    key1_pem, cert1_pem = _generate_test_key_and_cert("cert1.local")
    key2_pem, cert2_pem = _generate_test_key_and_cert("cert2.local")

    # Match test with certificate
    match_result = ssl_match(key1_pem, cert1_pem)
    assert match_result["matched"] is True
    assert match_result["key_hash"] == match_result["cert_hash"]
    assert "matches" in match_result["message"]

    # Mismatch test with mismatched certificate
    mismatch_result = ssl_match(key1_pem, cert2_pem)
    assert mismatch_result["matched"] is False
    assert mismatch_result["key_hash"] != mismatch_result["cert_hash"]
    assert "not match" in mismatch_result["message"].lower()

    # Match test with CSR
    csr_result = csr_generate("match-csr.local")
    csr_match = ssl_match(csr_result["private_key_pem"], csr_result["csr_pem"])
    assert csr_match["matched"] is True
    assert csr_match["key_hash"] == csr_match["cert_hash"]
