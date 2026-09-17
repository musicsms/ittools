"""Tests for ittools Model Context Protocol (MCP) server subsystem and tools."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import os
from pathlib import Path
import pytest

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from ittools.mcp.tools.config import config_generate
from ittools.mcp.tools.keypair import (
    keypair_passphrase,
    keypair_pgp,
    keypair_rsa,
    keypair_ssh,
)
from ittools.mcp.tools.pki import (
    csr_decode,
    csr_generate,
    pfx_create,
    pfx_extract,
    ssl_match,
)
from ittools.mcp.tools.ssl import ssl_check, ssl_headers


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


def test_mcp_keypair_passphrase():
    """Verify keypair_passphrase generates passphrases with default and custom options."""
    # Default: 4 words, "-" separator
    res = keypair_passphrase()
    assert isinstance(res, dict)
    assert "passphrase" in res
    words = res["passphrase"].split("-")
    assert len(words) == 4
    for w in words:
        assert w.islower()
        assert w.isalpha()

    # Custom configuration
    res_custom = keypair_passphrase(
        words=6,
        separator=".",
        capitalize=True,
        include_numbers=True,
        include_special=True,
    )
    passphrase = res_custom["passphrase"]
    parts = passphrase.split(".")
    assert len(parts) == 6
    for p in parts[:-1]:
        assert p.istitle()
    assert any(c.isdigit() for c in passphrase)
    assert any(c in "!@#$%^&*?" for c in passphrase)

    # Invalid word count
    with pytest.raises(ValueError, match="words_count must be at least 1"):
        keypair_passphrase(words=0)


def test_mcp_keypair_rsa(tmp_path: Path):
    """Verify keypair_rsa in-memory generation and file output with 0600 permissions."""
    # 1. In-memory generation
    res = keypair_rsa(key_size=2048)
    assert isinstance(res, dict)
    assert "BEGIN RSA PRIVATE KEY" in res["private_key_pem"] or "BEGIN PRIVATE KEY" in res["private_key_pem"]
    assert "BEGIN PUBLIC KEY" in res["public_key_pem"]
    assert res["saved_files"] == []

    # In-memory with password
    res_enc = keypair_rsa(key_size=2048, password="testpassword")
    assert "BEGIN ENCRYPTED PRIVATE KEY" in res_enc["private_key_pem"] or "ENCRYPTED" in res_enc["private_key_pem"] or "BEGIN PRIVATE KEY" in res_enc["private_key_pem"]

    # 2. Output path with mode 0600 on private key and 0644 on public key
    out_path = tmp_path / "id_rsa"
    pub_path = tmp_path / "id_rsa.pub"
    res_file = keypair_rsa(key_size=2048, output_path=str(out_path))

    assert res_file["saved_files"] == [str(out_path), str(pub_path)]
    assert out_path.exists()
    assert pub_path.exists()
    assert out_path.read_text(encoding="utf-8") == res_file["private_key_pem"]
    assert pub_path.read_text(encoding="utf-8") == res_file["public_key_pem"]

    priv_mode = os.stat(out_path).st_mode & 0o777
    pub_mode = os.stat(pub_path).st_mode & 0o777
    assert priv_mode == 0o600
    assert pub_mode == 0o644

    # 3. Overwrite protection: force=False raises FileExistsError upfront
    with pytest.raises(FileExistsError, match="Target file already exists"):
        keypair_rsa(key_size=2048, output_path=str(out_path), force=False)

    # Overwrite protection when only .pub exists
    out_path.unlink()
    assert pub_path.exists()
    with pytest.raises(FileExistsError, match="Target file already exists"):
        keypair_rsa(key_size=2048, output_path=str(out_path), force=False)

    # 4. Overwrite allowed with force=True
    res_forced = keypair_rsa(key_size=2048, output_path=str(out_path), force=True)
    assert len(res_forced["saved_files"]) == 2
    assert out_path.exists()


def test_mcp_keypair_ssh(tmp_path: Path):
    """Verify keypair_ssh in-memory generation (ed25519/rsa) and file output with 0600 permissions."""
    # 1. In-memory Ed25519
    res_ed = keypair_ssh(key_type="ed25519", comment="user@example.com")
    assert isinstance(res_ed, dict)
    assert "BEGIN OPENSSH PRIVATE KEY" in res_ed["private_key"]
    assert res_ed["public_key"].startswith("ssh-ed25519 ")
    assert res_ed["public_key"].endswith("user@example.com")
    assert res_ed["saved_files"] == []

    # 2. In-memory RSA
    res_rsa = keypair_ssh(key_type="rsa", key_size=2048, comment="rsa-key")
    assert "BEGIN OPENSSH PRIVATE KEY" in res_rsa["private_key"]
    assert res_rsa["public_key"].startswith("ssh-rsa ")
    assert res_rsa["public_key"].endswith("rsa-key")

    # 3. Output path with mode 0600 and 0644
    ssh_key_path = tmp_path / "id_ed25519"
    ssh_pub_path = tmp_path / "id_ed25519.pub"
    res_file = keypair_ssh(key_type="ed25519", output_path=str(ssh_key_path))

    assert res_file["saved_files"] == [str(ssh_key_path), str(ssh_pub_path)]
    assert ssh_key_path.exists()
    assert ssh_pub_path.exists()
    assert ssh_key_path.read_text(encoding="utf-8") == res_file["private_key"]
    assert ssh_pub_path.read_text(encoding="utf-8") == res_file["public_key"]

    priv_mode = os.stat(ssh_key_path).st_mode & 0o777
    pub_mode = os.stat(ssh_pub_path).st_mode & 0o777
    assert priv_mode == 0o600
    assert pub_mode == 0o644

    # 4. Overwrite protection
    with pytest.raises(FileExistsError, match="Target file already exists"):
        keypair_ssh(key_type="ed25519", output_path=str(ssh_key_path), force=False)

    ssh_key_path.unlink()
    assert ssh_pub_path.exists()
    with pytest.raises(FileExistsError, match="Target file already exists"):
        keypair_ssh(key_type="ed25519", output_path=str(ssh_key_path), force=False)

    # 5. Overwrite allowed with force=True
    res_forced = keypair_ssh(key_type="ed25519", output_path=str(ssh_key_path), force=True)
    assert len(res_forced["saved_files"]) == 2


def test_mcp_keypair_pgp(tmp_path: Path):
    """Verify keypair_pgp in-memory generation and file output with 0600 permissions."""
    # 1. In-memory generation
    res = keypair_pgp(
        name="MCP User",
        email="mcp@example.com",
        comment="Test MCP Key",
        expire_years=1,
    )
    assert isinstance(res, dict)
    assert "-----BEGIN PGP PRIVATE KEY BLOCK-----" in res["private_key"]
    assert "-----BEGIN PGP PUBLIC KEY BLOCK-----" in res["public_key"]
    assert len(res["fingerprint"]) > 0
    assert res["saved_files"] == []

    # 2. Output directory
    pgp_dir = tmp_path / "pgp_output"
    res_file = keypair_pgp(
        name="MCP User",
        email="mcp@example.com",
        output_dir=str(pgp_dir),
    )
    priv_file = pgp_dir / "private.asc"
    pub_file = pgp_dir / "public.asc"

    assert res_file["saved_files"] == [str(priv_file), str(pub_file)]
    assert priv_file.exists()
    assert pub_file.exists()
    assert priv_file.read_text(encoding="utf-8") == res_file["private_key"]
    assert pub_file.read_text(encoding="utf-8") == res_file["public_key"]

    priv_mode = os.stat(priv_file).st_mode & 0o777
    pub_mode = os.stat(pub_file).st_mode & 0o777
    assert priv_mode == 0o600
    assert pub_mode == 0o644

    # 3. Overwrite protection
    with pytest.raises(FileExistsError, match="Target file already exists"):
        keypair_pgp(name="MCP User", email="mcp@example.com", output_dir=str(pgp_dir), force=False)

    priv_file.unlink()
    assert pub_file.exists()
    with pytest.raises(FileExistsError, match="Target file already exists"):
        keypair_pgp(name="MCP User", email="mcp@example.com", output_dir=str(pgp_dir), force=False)

    # 4. Overwrite allowed with force=True
    res_forced = keypair_pgp(
        name="MCP User",
        email="mcp@example.com",
        output_dir=str(pgp_dir),
        force=True,
    )
    assert len(res_forced["saved_files"]) == 2

    # 5. Invalid parameters
    with pytest.raises(ValueError, match="Name cannot be empty"):
        keypair_pgp(name="", email="test@example.com")
    with pytest.raises(ValueError, match="Email cannot be empty"):
        keypair_pgp(name="Test", email="")


def test_mcp_ssl_check():
    """Verify ssl_check inspects remote certificates and returns a structured dictionary."""
    from unittest.mock import MagicMock, patch

    # Generate an in-memory test certificate
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([
        x509.NameAttribute(x509.NameOID.COMMON_NAME, "test.local"),
        x509.NameAttribute(x509.NameOID.ORGANIZATION_NAME, "Test Org"),
    ])
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=90))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName("test.local")]),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    der_bytes = cert.public_bytes(serialization.Encoding.DER)

    mock_sock = MagicMock()
    mock_ssock = MagicMock()
    mock_ssock.getpeercert.return_value = der_bytes
    mock_ssock.version.return_value = "TLSv1.3"
    mock_ssock.cipher.return_value = ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256)
    mock_ssock.__enter__.return_value = mock_ssock
    mock_ssock.__exit__.return_value = False

    mock_context = MagicMock()
    mock_context.wrap_socket.return_value = mock_ssock

    with (
        patch("socket.create_connection") as mock_create_conn,
        patch("ssl.create_default_context", return_value=mock_context),
    ):
        mock_create_conn.return_value.__enter__.return_value = mock_sock
        mock_create_conn.return_value.__exit__.return_value = False

        res = ssl_check(host="test.local", port=443, timeout=5.0)

        assert isinstance(res, dict)
        assert res["host"] == "test.local"
        assert res["port"] == 443
        assert "CN=test.local" in res["subject"]
        assert res["days_remaining"] >= 88
        assert res["is_expired"] is False
        assert "test.local" in res["sans"]
        assert res["tls_version"] == "TLSv1.3"
        assert res["cipher_suite"] == "TLS_AES_256_GCM_SHA384"
        assert res["is_valid_chain"] is True


def test_mcp_ssl_headers():
    """Verify ssl_headers analyzes HTTP security headers and returns a structured dictionary."""
    from unittest.mock import MagicMock, patch

    mock_resp = MagicMock()
    mock_resp.url = "https://secure.example.com"
    mock_resp.status_code = 200
    mock_resp.headers = {
        "Strict-Transport-Security": "max-age=63072000; includeSubDomains; preload",
        "Content-Security-Policy": "default-src 'self'",
        "X-Frame-Options": "DENY",
        "X-Content-Type-Options": "nosniff",
        "Referrer-Policy": "no-referrer",
        "Permissions-Policy": "geolocation=()",
    }

    with patch("requests.get", return_value=mock_resp):
        res = ssl_headers(url="https://secure.example.com", timeout=8.0)

        assert isinstance(res, dict)
        assert res["url"] == "https://secure.example.com"
        assert res["status_code"] == 200
        assert res["security_score"] == "A"
        assert len(res["missing_headers"]) == 0
        assert len(res["present_headers"]) == 6
        assert "Strict-Transport-Security" in res["present_headers"]


def test_mcp_config_generate(tmp_path: Path):
    """Verify config_generate renders TLS configs in-memory and to disk with force guard."""
    # 1. In-memory generation
    res = config_generate(
        server="nginx",
        profile="intermediate",
        domain="mysite.local",
        cert_path="/etc/ssl/certs/mysite.crt",
        key_path="/etc/ssl/private/mysite.key",
        hsts=True,
    )
    assert isinstance(res, dict)
    assert res["server"] == "nginx"
    assert res["profile"] == "intermediate"
    assert "server_name mysite.local;" in res["config"]
    assert "ssl_certificate /etc/ssl/certs/mysite.crt;" in res["config"]
    assert "Strict-Transport-Security" in res["config"]
    assert res["saved_to"] is None

    # 2. Disk persistence
    cfg_file = tmp_path / "nginx.conf"
    res_file = config_generate(
        server="nginx",
        domain="mysite.local",
        output_path=str(cfg_file),
    )
    assert res_file["saved_to"] == str(cfg_file)
    assert cfg_file.exists()
    assert cfg_file.read_text(encoding="utf-8") == res_file["config"]
    cfg_mode = os.stat(cfg_file).st_mode & 0o777
    assert cfg_mode == 0o644

    # 3. Overwrite protection: force=False raises FileExistsError upfront
    with pytest.raises(FileExistsError, match="Target file already exists"):
        config_generate(server="nginx", output_path=str(cfg_file), force=False)

    # 4. Overwrite allowed when force=True
    res_forced = config_generate(
        server="caddy",
        domain="caddy.local",
        output_path=str(cfg_file),
        force=True,
    )
    assert res_forced["saved_to"] == str(cfg_file)
    assert "caddy.local {" in cfg_file.read_text(encoding="utf-8")

    # 5. Unsupported server raises ValueError
    with pytest.raises(ValueError, match="Unsupported server"):
        config_generate(server="unknown_server")

