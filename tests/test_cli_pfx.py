"""CLI integration tests for ittools pfx commands."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import os
import stat
import sys
from unittest.mock import patch
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from ittools.cli.main import main


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


def test_cli_help_includes_pfx(capsys):
    ret = main(["--help"])
    assert ret == 0
    captured = capsys.readouterr()
    assert "pfx" in captured.out


def test_cli_pfx_help(capsys):
    ret = main(["pfx", "--help"])
    assert ret == 0
    captured = capsys.readouterr()
    assert "create" in captured.out
    assert "extract" in captured.out


def test_cli_pfx_no_subcommand(capsys):
    ret = main(["pfx"])
    assert ret == 1
    captured = capsys.readouterr()
    assert "usage:" in captured.err or "usage:" in captured.out


def test_cli_pfx_create_and_extract_flow(tmp_path):
    key_pem, cert_pem = _generate_test_key_and_cert("cli.test.local")
    key_file = tmp_path / "server.key"
    cert_file = tmp_path / "server.crt"
    pfx_file = tmp_path / "server.pfx"
    extract_dir = tmp_path / "extracted"

    key_file.write_text(key_pem, encoding="utf-8")
    cert_file.write_text(cert_pem, encoding="utf-8")

    # 1. Create PFX with password
    code = main([
        "pfx", "create",
        "--key", str(key_file),
        "--cert", str(cert_file),
        "--out", str(pfx_file),
        "--password", "clipassword",
        "--name", "MyCert",
    ])
    assert code == 0
    assert pfx_file.exists()

    # 2. Extract PFX
    code = main([
        "pfx", "extract",
        "--in", str(pfx_file),
        "--password", "clipassword",
        "--out-dir", str(extract_dir),
    ])
    assert code == 0
    assert (extract_dir / "server.key").exists()
    assert (extract_dir / "server.crt").exists()

    # Verify 0600 permissions on extracted private key
    file_stat = os.stat(extract_dir / "server.key")
    assert stat.S_IMODE(file_stat.st_mode) == 0o600


def test_cli_pfx_create_target_exists_without_force(tmp_path):
    key_pem, cert_pem = _generate_test_key_and_cert("guard.local")
    key_file = tmp_path / "guard.key"
    cert_file = tmp_path / "guard.crt"
    pfx_file = tmp_path / "guard.pfx"

    key_file.write_text(key_pem, encoding="utf-8")
    cert_file.write_text(cert_pem, encoding="utf-8")
    pfx_file.write_text("existing", encoding="utf-8")

    # Without --force -> exit code 1
    code = main([
        "pfx", "create",
        "--key", str(key_file),
        "--cert", str(cert_file),
        "--out", str(pfx_file),
        "--password", "pwd",
    ])
    assert code == 1

    # With --force -> exit code 0
    code = main([
        "pfx", "create",
        "--key", str(key_file),
        "--cert", str(cert_file),
        "--out", str(pfx_file),
        "--password", "pwd",
        "--force",
    ])
    assert code == 0
    assert pfx_file.read_bytes() != b"existing"


def test_cli_pfx_extract_target_exists_without_force(tmp_path):
    key_pem, cert_pem = _generate_test_key_and_cert("extract-guard.local")
    key_file = tmp_path / "input.key"
    cert_file = tmp_path / "input.crt"
    pfx_file = tmp_path / "extract-guard.pfx"
    extract_dir = tmp_path / "extracted"
    extract_dir.mkdir(parents=True, exist_ok=True)

    key_file.write_text(key_pem, encoding="utf-8")
    cert_file.write_text(cert_pem, encoding="utf-8")

    # Create the PFX first
    assert main([
        "pfx", "create",
        "--key", str(key_file),
        "--cert", str(cert_file),
        "--out", str(pfx_file),
        "--password", "secret",
    ]) == 0

    # Target key exists prior to extraction
    existing_key = extract_dir / "extract-guard.key"
    existing_key.write_text("pre-existing key", encoding="utf-8")

    # Without --force -> exit code 1, pre-existing file not modified
    code = main([
        "pfx", "extract",
        "--in", str(pfx_file),
        "--password", "secret",
        "--out-dir", str(extract_dir),
    ])
    assert code == 1
    assert existing_key.read_text(encoding="utf-8") == "pre-existing key"

    # With --force -> exit code 0, file overwritten with 0600
    code = main([
        "pfx", "extract",
        "--in", str(pfx_file),
        "--password", "secret",
        "--out-dir", str(extract_dir),
        "--force",
    ])
    assert code == 0
    assert existing_key.read_text(encoding="utf-8") != "pre-existing key"
    assert "BEGIN PRIVATE KEY" in existing_key.read_text(encoding="utf-8")
    assert stat.S_IMODE(os.stat(existing_key).st_mode) == 0o600


def test_cli_pfx_extract_invalid_password(tmp_path, capsys):
    key_pem, cert_pem = _generate_test_key_and_cert("badpass.local")
    key_file = tmp_path / "server.key"
    cert_file = tmp_path / "server.crt"
    pfx_file = tmp_path / "server.pfx"

    key_file.write_text(key_pem, encoding="utf-8")
    cert_file.write_text(cert_pem, encoding="utf-8")

    assert main([
        "pfx", "create",
        "--key", str(key_file),
        "--cert", str(cert_file),
        "--out", str(pfx_file),
        "--password", "rightpassword",
    ]) == 0

    capsys.readouterr()  # clear buffer

    code = main([
        "pfx", "extract",
        "--in", str(pfx_file),
        "--password", "wrongpassword",
        "--out-dir", str(tmp_path / "out"),
    ])
    assert code == 1
    captured = capsys.readouterr()
    assert "Failed to extract PFX" in captured.err or "Failed to decrypt" in captured.err


def test_cli_pfx_create_missing_inputs(tmp_path, capsys):
    key_file = tmp_path / "missing.key"
    cert_file = tmp_path / "missing.crt"
    pfx_file = tmp_path / "out.pfx"

    code = main([
        "pfx", "create",
        "--key", str(key_file),
        "--cert", str(cert_file),
        "--out", str(pfx_file),
        "--password", "pass",
    ])
    assert code == 1
    captured = capsys.readouterr()
    assert "Private key file not found" in captured.err

    # Key exists, cert missing
    key_pem, _ = _generate_test_key_and_cert("test.local")
    key_file.write_text(key_pem, encoding="utf-8")

    code = main([
        "pfx", "create",
        "--key", str(key_file),
        "--cert", str(cert_file),
        "--out", str(pfx_file),
        "--password", "pass",
    ])
    assert code == 1
    captured = capsys.readouterr()
    assert "Certificate file not found" in captured.err


def test_cli_pfx_create_and_extract_ca_chain(tmp_path):
    key_pem, cert_pem = _generate_test_key_and_cert("service.local")
    _, ca_pem = _generate_test_key_and_cert("Test Root CA", is_ca=True)

    key_file = tmp_path / "service.key"
    cert_file = tmp_path / "service.crt"
    ca_file = tmp_path / "ca.crt"
    pfx_file = tmp_path / "service.pfx"
    extract_dir = tmp_path / "extracted"

    key_file.write_text(key_pem, encoding="utf-8")
    cert_file.write_text(cert_pem, encoding="utf-8")
    ca_file.write_text(ca_pem, encoding="utf-8")

    code = main([
        "pfx", "create",
        "--key", str(key_file),
        "--cert", str(cert_file),
        "--ca", str(ca_file),
        "--out", str(pfx_file),
        "--password", "chainpwd",
    ])
    assert code == 0

    code = main([
        "pfx", "extract",
        "--in", str(pfx_file),
        "--password", "chainpwd",
        "--out-dir", str(extract_dir),
    ])
    assert code == 0
    assert (extract_dir / "service.key").exists()
    assert (extract_dir / "service.crt").exists()
    assert (extract_dir / "service-ca.crt").exists()
    assert ca_pem in (extract_dir / "service-ca.crt").read_text(encoding="utf-8")


def test_cli_pfx_create_and_extract_no_password(tmp_path):
    key_pem, cert_pem = _generate_test_key_and_cert("nopass.local")
    key_file = tmp_path / "nopass.key"
    cert_file = tmp_path / "nopass.crt"
    pfx_file = tmp_path / "nopass.pfx"
    extract_dir = tmp_path / "extracted"

    key_file.write_text(key_pem, encoding="utf-8")
    cert_file.write_text(cert_pem, encoding="utf-8")

    code = main([
        "pfx", "create",
        "--key", str(key_file),
        "--cert", str(cert_file),
        "--out", str(pfx_file),
        "--no-password",
    ])
    assert code == 0

    code = main([
        "pfx", "extract",
        "--in", str(pfx_file),
        "--out-dir", str(extract_dir),
    ])
    assert code == 0
    assert (extract_dir / "nopass.key").exists()
    assert stat.S_IMODE(os.stat(extract_dir / "nopass.key").st_mode) == 0o600


def test_cli_pfx_interactive_password_prompt(tmp_path):
    key_pem, cert_pem = _generate_test_key_and_cert("interactive.local")
    key_file = tmp_path / "interactive.key"
    cert_file = tmp_path / "interactive.crt"
    pfx_file = tmp_path / "interactive.pfx"
    extract_dir = tmp_path / "extracted"

    key_file.write_text(key_pem, encoding="utf-8")
    cert_file.write_text(cert_pem, encoding="utf-8")

    with patch("sys.stdin.isatty", return_value=True), patch("getpass.getpass", return_value="interactive_pwd"):
        code = main([
            "pfx", "create",
            "--key", str(key_file),
            "--cert", str(cert_file),
            "--out", str(pfx_file),
        ])
        assert code == 0

    with patch("sys.stdin.isatty", return_value=True), patch("getpass.getpass", return_value="interactive_pwd"):
        code = main([
            "pfx", "extract",
            "--in", str(pfx_file),
            "--out-dir", str(extract_dir),
        ])
        assert code == 0
        assert (extract_dir / "interactive.key").exists()


def test_cli_pfx_extract_custom_paths(tmp_path):
    key_pem, cert_pem = _generate_test_key_and_cert("custom.local")
    _, ca_pem = _generate_test_key_and_cert("Custom CA", is_ca=True)

    key_file = tmp_path / "custom.key"
    cert_file = tmp_path / "custom.crt"
    ca_file = tmp_path / "custom_ca.crt"
    pfx_file = tmp_path / "custom.pfx"

    custom_key = tmp_path / "custom_out" / "priv.key"
    custom_cert = tmp_path / "custom_out" / "public.crt"
    custom_ca = tmp_path / "custom_out" / "chain.crt"

    key_file.write_text(key_pem, encoding="utf-8")
    cert_file.write_text(cert_pem, encoding="utf-8")
    ca_file.write_text(ca_pem, encoding="utf-8")

    assert main([
        "pfx", "create",
        "--key", str(key_file),
        "--cert", str(cert_file),
        "--ca", str(ca_file),
        "--out", str(pfx_file),
        "--password", "pass",
    ]) == 0

    code = main([
        "pfx", "extract",
        "--in", str(pfx_file),
        "--password", "pass",
        "--key-out", str(custom_key),
        "--cert-out", str(custom_cert),
        "--ca-out", str(custom_ca),
    ])
    assert code == 0
    assert custom_key.exists()
    assert custom_cert.exists()
    assert custom_ca.exists()
    assert stat.S_IMODE(os.stat(custom_key).st_mode) == 0o600


def test_cli_pfx_extract_write_failure(tmp_path, capsys):
    key_pem, cert_pem = _generate_test_key_and_cert("failwrite.local")
    key_file = tmp_path / "server.key"
    cert_file = tmp_path / "server.crt"
    pfx_file = tmp_path / "server.pfx"

    key_file.write_text(key_pem, encoding="utf-8")
    cert_file.write_text(cert_pem, encoding="utf-8")

    assert main([
        "pfx", "create",
        "--key", str(key_file),
        "--cert", str(cert_file),
        "--out", str(pfx_file),
        "--no-password",
    ]) == 0

    capsys.readouterr()

    with patch("os.open", side_effect=OSError("Disk write error")):
        code = main([
            "pfx", "extract",
            "--in", str(pfx_file),
            "--out-dir", str(tmp_path / "out"),
        ])
        assert code == 1
        captured = capsys.readouterr()
        assert "Failed to write extracted file" in captured.err

