"""CLI integration tests for ittools adcs commands."""

from __future__ import annotations

import io
import os
import stat
import sys
from unittest.mock import MagicMock, patch
import pytest

from ittools.cli.main import main
from ittools.core.adcs.client import ADCSResult
from ittools.core.adcs.exceptions import (
    ADCSAuthError,
    ADCSConnectionError,
    ADCSError,
    ADCSPendingError,
    ADCSRequestDeniedError,
)
from ittools.core.pki.pfx import extract_pfx_bundle
from datetime import datetime, timedelta, timezone
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

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

FAKE_CSR = (
    "-----BEGIN CERTIFICATE REQUEST-----\n"
    "MIICvDCCAaQCAQAwdzELMAkGA1UEBhMCVVMxEzARBgNVBAgMCkNhbGlmb3JuaWEx\n"
    "-----END CERTIFICATE REQUEST-----\n"
)
FAKE_CERT = (
    "-----BEGIN CERTIFICATE-----\n"
    "MIIDazCCAlOgAwIBAgIUQfakecert...\n"
    "-----END CERTIFICATE-----\n"
)
FAKE_CA_P7B = (
    "-----BEGIN PKCS7-----\n"
    "MIIF...fakecap7b...\n"
    "-----END PKCS7-----\n"
)


def test_cli_help_includes_adcs(capsys):
    ret = main(["--help"])
    assert ret == 0
    captured = capsys.readouterr()
    assert "adcs" in captured.out


def test_cli_adcs_help(capsys):
    ret = main(["adcs", "--help"])
    assert ret == 0
    captured = capsys.readouterr()
    assert "sign" in captured.out
    assert "retrieve" in captured.out
    assert "ca-cert" in captured.out


def test_cli_adcs_no_subcommand(capsys):
    ret = main(["adcs"])
    assert ret == 1
    captured = capsys.readouterr()
    assert "usage:" in captured.err or "usage:" in captured.out


@patch("ittools.core.adcs.client.ADCSClient.submit_csr")
def test_cli_adcs_sign_success(mock_submit, tmp_path, capsys):
    mock_submit.return_value = ADCSResult(
        req_id="501",
        cert_pem=FAKE_CERT,
    )
    csr_file = tmp_path / "req.csr"
    csr_file.write_text(FAKE_CSR, encoding="utf-8")
    out_file = tmp_path / "issued.cer"

    code = main([
        "adcs", "sign",
        "--server", "ca.corp.local",
        "--csr", str(csr_file),
        "--username", "corp\\admin",
        "--password", "secretpass",
        "--out", str(out_file),
    ])
    assert code == 0
    assert out_file.exists()
    assert out_file.read_text(encoding="utf-8") == FAKE_CERT
    captured = capsys.readouterr()
    assert "501" in captured.out


@patch("ittools.core.adcs.client.ADCSClient.submit_csr")
def test_cli_adcs_sign_pending_exits_code_3(mock_submit, tmp_path, capsys):
    mock_submit.side_effect = ADCSPendingError("777")
    csr_file = tmp_path / "req.csr"
    csr_file.write_text(FAKE_CSR, encoding="utf-8")

    code = main([
        "adcs", "sign",
        "--server", "ca.corp.local",
        "--csr", str(csr_file),
        "--username", "corp\\admin",
        "--password", "secretpass",
    ])
    assert code == 3
    captured = capsys.readouterr()
    assert "777" in captured.err or "777" in captured.out
    assert "retrieve" in captured.err or "retrieve" in captured.out


@patch("ittools.core.adcs.client.ADCSClient.submit_csr")
def test_cli_adcs_sign_network_error_exits_code_2(mock_submit, tmp_path, capsys):
    mock_submit.side_effect = ADCSConnectionError("Connection to ADCS server ca.unreachable failed: Network unreachable")
    csr_file = tmp_path / "req.csr"
    csr_file.write_text(FAKE_CSR, encoding="utf-8")

    code = main([
        "adcs", "sign",
        "--server", "ca.unreachable",
        "--csr", str(csr_file),
        "--username", "user",
        "--password", "pass",
    ])
    assert code == 2
    captured = capsys.readouterr()
    assert "error:" in captured.err.lower() or "connection" in captured.err.lower()


@patch("ittools.core.adcs.client.ADCSClient.submit_csr")
def test_cli_adcs_sign_with_pfx_export(mock_submit, tmp_path):
    key_pem, cert_pem = _generate_test_key_and_cert("adcs.pfx.local")
    mock_submit.return_value = ADCSResult(req_id="601", cert_pem=cert_pem)

    csr_file = tmp_path / "test.csr"
    key_file = tmp_path / "test.key"
    out_cer = tmp_path / "test.cer"
    pfx_file = tmp_path / "final.pfx"

    csr_file.write_text(FAKE_CSR, encoding="utf-8")
    key_file.write_text(key_pem, encoding="utf-8")

    code = main([
        "adcs", "sign",
        "--server", "ca.corp.local",
        "--csr", str(csr_file),
        "--key", str(key_file),
        "--out", str(out_cer),
        "--out-pfx", str(pfx_file),
        "--pfx-password", "secretpfx",
        "--name", "MyAlias",
        "--username", "user",
        "--password", "pass",
    ])
    assert code == 0
    assert out_cer.exists()
    assert pfx_file.exists()

    # Verify PFX contents and decryptability
    pfx_bytes = pfx_file.read_bytes()
    res = extract_pfx_bundle(pfx_bytes, password="secretpfx")
    assert res.private_key_pem is not None
    assert res.cert_pem is not None
    loaded_cert = x509.load_pem_x509_certificate(res.cert_pem.encode("utf-8"))
    assert "adcs.pfx.local" in loaded_cert.subject.rfc4514_string()
    assert res.friendly_name == "MyAlias"

    # Verify restrictive 0600 file permissions on PFX file
    st = os.stat(pfx_file)
    assert st.st_mode & 0o777 == 0o600


@patch("ittools.core.adcs.client.ADCSClient.retrieve_cert")
def test_cli_adcs_retrieve_success(mock_retrieve, tmp_path, capsys):
    mock_retrieve.return_value = FAKE_CERT
    out_file = tmp_path / "retrieved.cer"

    code = main([
        "adcs", "retrieve",
        "--server", "ca.corp.local",
        "--req-id", "105",
        "--username", "corp\\admin",
        "--password", "secretpass",
        "--out", str(out_file),
    ])
    assert code == 0
    assert out_file.exists()
    assert out_file.read_text(encoding="utf-8") == FAKE_CERT
    mock_retrieve.assert_called_once_with("105")
    captured = capsys.readouterr()
    assert "saved" in captured.out.lower()


@patch("ittools.core.adcs.client.ADCSClient.retrieve_cert")
def test_cli_adcs_retrieve_with_pfx(mock_retrieve, tmp_path):
    key_pem, cert_pem = _generate_test_key_and_cert("retrieved.local")
    mock_retrieve.return_value = cert_pem

    key_file = tmp_path / "server.key"
    out_cer = tmp_path / "server.cer"
    out_pfx = tmp_path / "server.pfx"

    key_file.write_text(key_pem, encoding="utf-8")

    code = main([
        "adcs", "retrieve",
        "--server", "ca.corp.local",
        "--req-id", "202",
        "--key", str(key_file),
        "--out", str(out_cer),
        "--out-pfx", str(out_pfx),
        "--pfx-password", "pfxpass",
        "--username", "user",
        "--password", "pass",
    ])
    assert code == 0
    assert out_cer.exists()
    assert out_pfx.exists()

    res = extract_pfx_bundle(out_pfx.read_bytes(), password="pfxpass")
    assert res.private_key_pem is not None
    assert res.cert_pem is not None


@patch("ittools.core.adcs.client.ADCSClient.retrieve_cert")
def test_cli_adcs_retrieve_network_error_exits_code_2(mock_retrieve, tmp_path):
    mock_retrieve.side_effect = ADCSConnectionError("Timeout connecting to server")
    code = main([
        "adcs", "retrieve",
        "--server", "ca.corp.local",
        "--req-id", "202",
        "--username", "user",
        "--password", "pass",
    ])
    assert code == 2


@patch("ittools.core.adcs.client.ADCSClient.get_ca_cert")
def test_cli_adcs_ca_cert_success(mock_ca_cert, tmp_path, capsys):
    mock_ca_cert.return_value = FAKE_CA_P7B
    out_file = tmp_path / "ca.p7b"

    code = main([
        "adcs", "ca-cert",
        "--server", "ca.corp.local",
        "--username", "corp\\admin",
        "--password", "secretpass",
        "--out", str(out_file),
    ])
    assert code == 0
    assert out_file.exists()
    assert out_file.read_text(encoding="utf-8") == FAKE_CA_P7B
    captured = capsys.readouterr()
    assert "ca bundle" in captured.out.lower()


@patch("ittools.core.adcs.client.ADCSClient.get_ca_cert")
def test_cli_adcs_ca_cert_network_error_exits_code_2(mock_ca_cert):
    mock_ca_cert.side_effect = ADCSConnectionError("SSL handshake failure")
    code = main([
        "adcs", "ca-cert",
        "--server", "ca.corp.local",
        "--username", "user",
        "--password", "pass",
    ])
    assert code == 2


@patch("ittools.core.adcs.client.ADCSClient.submit_csr")
def test_cli_adcs_overwrite_guard(mock_submit, tmp_path, capsys):
    # Pre-create target output file
    target_cer = tmp_path / "existing.cer"
    target_cer.write_text("already here", encoding="utf-8")

    csr_file = tmp_path / "req.csr"
    csr_file.write_text(FAKE_CSR, encoding="utf-8")

    # 1. Sign without --force fails with exit code 1
    code = main([
        "adcs", "sign",
        "--server", "ca.corp.local",
        "--csr", str(csr_file),
        "--username", "user",
        "--password", "pass",
        "--out", str(target_cer),
    ])
    assert code == 1
    # submit_csr should NOT be called due to upfront check
    mock_submit.assert_not_called()
    captured = capsys.readouterr()
    assert "already exists" in captured.err.lower()

    # 2. Sign with --force succeeds
    mock_submit.return_value = ADCSResult(req_id="999", cert_pem=FAKE_CERT)
    code = main([
        "adcs", "sign",
        "--server", "ca.corp.local",
        "--csr", str(csr_file),
        "--username", "user",
        "--password", "pass",
        "--out", str(target_cer),
        "--force",
    ])
    assert code == 0
    assert target_cer.read_text(encoding="utf-8") == FAKE_CERT


@patch("ittools.core.adcs.client.ADCSClient.retrieve_cert")
def test_cli_adcs_retrieve_overwrite_guard(mock_retrieve, tmp_path, capsys):
    target_cer = tmp_path / "existing_retrieve.cer"
    target_cer.write_text("existing", encoding="utf-8")

    code = main([
        "adcs", "retrieve",
        "--server", "ca.corp.local",
        "--req-id", "123",
        "--out", str(target_cer),
    ])
    assert code == 1
    mock_retrieve.assert_not_called()
    captured = capsys.readouterr()
    assert "already exists" in captured.err.lower()

    # With --force
    mock_retrieve.return_value = FAKE_CERT
    code = main([
        "adcs", "retrieve",
        "--server", "ca.corp.local",
        "--req-id", "123",
        "--out", str(target_cer),
        "--force",
    ])
    assert code == 0
    assert target_cer.read_text(encoding="utf-8") == FAKE_CERT


@patch("ittools.core.adcs.client.ADCSClient.get_ca_cert")
def test_cli_adcs_ca_cert_overwrite_guard(mock_ca_cert, tmp_path, capsys):
    target_p7b = tmp_path / "existing_ca.p7b"
    target_p7b.write_text("existing", encoding="utf-8")

    code = main([
        "adcs", "ca-cert",
        "--server", "ca.corp.local",
        "--out", str(target_p7b),
    ])
    assert code == 1
    mock_ca_cert.assert_not_called()
    captured = capsys.readouterr()
    assert "already exists" in captured.err.lower()

    # With --force
    mock_ca_cert.return_value = FAKE_CA_P7B
    code = main([
        "adcs", "ca-cert",
        "--server", "ca.corp.local",
        "--out", str(target_p7b),
        "--force",
    ])
    assert code == 0
    assert target_p7b.read_text(encoding="utf-8") == FAKE_CA_P7B


def test_cli_adcs_missing_csr_file(tmp_path, capsys):
    code = main([
        "adcs", "sign",
        "--server", "ca.corp.local",
        "--csr", str(tmp_path / "nonexistent.csr"),
    ])
    assert code == 1
    captured = capsys.readouterr()
    assert "not found" in captured.err.lower()


def test_cli_adcs_missing_key_file(tmp_path, capsys):
    csr_file = tmp_path / "req.csr"
    csr_file.write_text(FAKE_CSR, encoding="utf-8")

    code = main([
        "adcs", "sign",
        "--server", "ca.corp.local",
        "--csr", str(csr_file),
        "--key", str(tmp_path / "nonexistent.key"),
        "--out-pfx", str(tmp_path / "out.pfx"),
    ])
    assert code == 1
    captured = capsys.readouterr()
    assert "not found" in captured.err.lower()


@patch("ittools.core.adcs.client.ADCSClient.submit_csr")
def test_cli_adcs_denied_exits_code_1(mock_submit, tmp_path, capsys):
    mock_submit.side_effect = ADCSRequestDeniedError("The permissions of certificate template are not sufficient.")
    csr_file = tmp_path / "req.csr"
    csr_file.write_text(FAKE_CSR, encoding="utf-8")

    code = main([
        "adcs", "sign",
        "--server", "ca.corp.local",
        "--csr", str(csr_file),
        "--username", "user",
        "--password", "pass",
    ])
    assert code == 1
    captured = capsys.readouterr()
    assert "denied" in captured.err.lower() or "sufficient" in captured.err.lower()


@patch("ittools.core.adcs.client.ADCSClient.submit_csr")
def test_cli_adcs_auth_error_exits_code_1(mock_submit, tmp_path, capsys):
    mock_submit.side_effect = ADCSAuthError("Authentication failed: invalid username or password (HTTP 401)")
    csr_file = tmp_path / "req.csr"
    csr_file.write_text(FAKE_CSR, encoding="utf-8")

    code = main([
        "adcs", "sign",
        "--server", "ca.corp.local",
        "--csr", str(csr_file),
        "--username", "user",
        "--password", "wrongpass",
    ])
    assert code == 1
    captured = capsys.readouterr()
    assert "authentication failed" in captured.err.lower()


@patch("getpass.getpass")
@patch("sys.stdin.isatty", return_value=True)
@patch("ittools.core.adcs.client.ADCSClient.submit_csr")
def test_cli_adcs_interactive_password_prompt(mock_submit, mock_isatty, mock_getpass, tmp_path):
    mock_getpass.return_value = "prompted_pass"
    mock_submit.return_value = ADCSResult(req_id="701", cert_pem=FAKE_CERT)
    csr_file = tmp_path / "req.csr"
    csr_file.write_text(FAKE_CSR, encoding="utf-8")
    out_cer = tmp_path / "issued.cer"

    code = main([
        "adcs", "sign",
        "--server", "ca.corp.local",
        "--csr", str(csr_file),
        "--username", "domain\\alice",
        "--out", str(out_cer),
    ])
    assert code == 0
    mock_getpass.assert_called_once()
    assert "alice" in mock_getpass.call_args[0][0]


@patch("ittools.core.adcs.client.ADCSClient.submit_csr")
def test_cli_adcs_stdin_csr(mock_submit, tmp_path, monkeypatch):
    mock_submit.return_value = ADCSResult(req_id="801", cert_pem=FAKE_CERT)
    out_cer = tmp_path / "stdin.cer"
    monkeypatch.setattr("sys.stdin", io.StringIO(FAKE_CSR))

    code = main([
        "adcs", "sign",
        "--server", "ca.corp.local",
        "--csr", "-",
        "--username", "user",
        "--password", "pass",
        "--out", str(out_cer),
    ])
    assert code == 0
    assert out_cer.exists()
    mock_submit.assert_called_once_with(FAKE_CSR, template="WebServer")
