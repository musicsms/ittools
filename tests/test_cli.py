"""Unit and integration tests for the ittools CLI layer."""

import io
import os
import stat
from unittest.mock import patch
import pytest

from ittools.cli.main import main
from ittools.core.keypair.pgp import PGPKeyPair
from ittools.core.keypair.rsa import generate_rsa_keypair
from ittools.core.pki.csr import CSRSubject, generate_csr
from ittools.core.ssl_check.checker import SSLReport
from ittools.core.ssl_check.headers import HeadersReport


def test_cli_help(capsys):
    ret = main(["--help"])
    assert ret == 0
    captured = capsys.readouterr()
    assert "ittools" in captured.out
    assert "csr" in captured.out
    assert "keypair" in captured.out
    assert "ssl" in captured.out
    assert "config" in captured.out


def test_cli_no_args(capsys):
    ret = main([])
    assert ret != 0
    captured = capsys.readouterr()
    # Should print help or usage when called without subcommand
    assert "usage:" in captured.err or "usage:" in captured.out


def test_cli_passphrase(capsys):
    ret = main(["keypair", "passphrase", "--words", "3", "--sep", "_"])
    assert ret == 0
    captured = capsys.readouterr()
    parts = captured.out.strip().split("_")
    assert len(parts) == 3


def test_cli_passphrase_options(capsys):
    ret = main([
        "keypair", "passphrase",
        "--words", "2",
        "--sep", "-",
        "--capitalize",
        "--numbers",
        "--special",
    ])
    assert ret == 0
    captured = capsys.readouterr()
    text = captured.out.strip()
    assert "-" in text
    # Should have a capitalized letter
    assert any(c.isupper() for c in text)
    # Should have a digit
    assert any(c.isdigit() for c in text)


def test_cli_csr_generate_non_interactive(tmp_path, capsys):
    out_dir = str(tmp_path / "output")
    ret = main(["csr", "generate", "--cn", "test.example.com", "--country", "VN", "--output-dir", out_dir])
    assert ret == 0
    captured = capsys.readouterr()
    assert "CERTIFICATE REQUEST" in captured.out
    key_file = tmp_path / "output" / "test.example.com" / "test.example.com.key"
    csr_file = tmp_path / "output" / "test.example.com" / "test.example.com.csr"
    assert key_file.exists()
    assert csr_file.exists()

    # Verify 0600 file permissions on the generated private key
    mode = stat.S_IMODE(os.stat(key_file).st_mode)
    assert mode == 0o600


def test_cli_csr_generate_force_protection(tmp_path, capsys):
    out_dir = str(tmp_path / "output")
    cmd = ["csr", "generate", "--cn", "force.test.com", "--output-dir", out_dir]
    ret1 = main(cmd)
    assert ret1 == 0

    # Running again without --force should fail (exit 1)
    ret2 = main(cmd)
    assert ret2 == 1
    captured2 = capsys.readouterr()
    assert "already exists" in captured2.err.lower() or "force" in captured2.err.lower()

    # Running with --force should succeed
    ret3 = main(cmd + ["--force"])
    assert ret3 == 0


def test_cli_csr_generate_interactive(tmp_path, capsys, monkeypatch):
    out_dir = str(tmp_path / "output")
    # Simulate user inputs:
    # 1. empty CN -> should reprompt
    # 2. interactive.example.com -> valid CN
    # 3. Acme Corp -> org
    # 4. IT Dept -> ou
    # 5. Hanoi -> city
    # 6. Hanoi -> state
    # 7. VN -> country
    # 8. test@example.com -> email
    # 9. alt.example.com, 10.0.0.1 -> san
    # 10. 2048 -> key size
    simulated_input = io.StringIO(
        "\ninteractive.example.com\nAcme Corp\nIT Dept\nHanoi\nHanoi\nVN\ntest@example.com\nalt.example.com, 10.0.0.1\n2048\n"
    )
    monkeypatch.setattr("sys.stdin", simulated_input)

    # Calling csr generate with no flags triggers interactive mode
    # We pass --output-dir by changing working directory or via mocked default
    orig_cwd = os.getcwd()
    os.chdir(tmp_path)
    try:
        ret = main(["csr", "generate"])
        assert ret == 0
        captured = capsys.readouterr()
        assert "CERTIFICATE REQUEST" in captured.out
        key_file = tmp_path / "output" / "interactive.example.com" / "interactive.example.com.key"
        assert key_file.exists()
        assert stat.S_IMODE(os.stat(key_file).st_mode) == 0o600
    finally:
        os.chdir(orig_cwd)


def test_cli_csr_decode_file(tmp_path, capsys):
    res = generate_csr(CSRSubject(common_name="decode.example.com", country="US", organization="Decoders Inc"))
    csr_path = tmp_path / "test.csr"
    csr_path.write_text(res.csr_pem, encoding="utf-8")

    ret = main(["csr", "decode", "--in", str(csr_path)])
    assert ret == 0
    captured = capsys.readouterr()
    assert "decode.example.com" in captured.out
    assert "Decoders Inc" in captured.out
    assert "US" in captured.out


def test_cli_csr_decode_stdin(capsys, monkeypatch):
    res = generate_csr(CSRSubject(common_name="stdin.example.com", country="GB"))
    monkeypatch.setattr("sys.stdin", io.StringIO(res.csr_pem))

    ret = main(["csr", "decode"])
    assert ret == 0
    captured = capsys.readouterr()
    assert "stdin.example.com" in captured.out
    assert "GB" in captured.out


def test_cli_csr_decode_invalid(capsys):
    ret = main(["csr", "decode", "--in", "/non/existent/file.csr"])
    assert ret == 1
    captured = capsys.readouterr()
    assert captured.err != ""


def test_cli_keypair_rsa_stdout(capsys):
    ret = main(["keypair", "rsa", "--size", "2048"])
    assert ret == 0
    captured = capsys.readouterr()
    assert "BEGIN PRIVATE KEY" in captured.out
    assert "BEGIN PUBLIC KEY" in captured.out


def test_cli_keypair_rsa_out(tmp_path, capsys):
    out_key = tmp_path / "id_rsa"
    ret = main(["keypair", "rsa", "--size", "2048", "--out", str(out_key)])
    assert ret == 0
    assert out_key.exists()
    assert (tmp_path / "id_rsa.pub").exists()
    assert stat.S_IMODE(os.stat(out_key).st_mode) == 0o600


def test_cli_keypair_ssh_stdout(capsys):
    ret = main(["keypair", "ssh", "--type", "ed25519", "--comment", "admin@lab"])
    assert ret == 0
    captured = capsys.readouterr()
    assert "OPENSSH PRIVATE KEY" in captured.out
    assert "ssh-ed25519" in captured.out
    assert "admin@lab" in captured.out


def test_cli_keypair_ssh_out(tmp_path, capsys):
    out_key = tmp_path / "id_ed25519"
    ret = main(["keypair", "ssh", "--type", "ed25519", "--out", str(out_key)])
    assert ret == 0
    assert out_key.exists()
    assert (tmp_path / "id_ed25519.pub").exists()
    assert stat.S_IMODE(os.stat(out_key).st_mode) == 0o600


def test_cli_keypair_pgp(tmp_path, capsys):
    fake_pgp = PGPKeyPair(
        private_key="-----BEGIN PGP PRIVATE KEY BLOCK-----\nfake\n-----END PGP PRIVATE KEY BLOCK-----",
        public_key="-----BEGIN PGP PUBLIC KEY BLOCK-----\nfake\n-----END PGP PUBLIC KEY BLOCK-----",
        fingerprint="ABCD1234EF567890",
    )
    with patch("ittools.cli.commands.keypair.generate_pgp_key", return_value=fake_pgp):
        out_dir = tmp_path / "pgp"
        ret = main([
            "keypair", "pgp",
            "--name", "Alice",
            "--email", "alice@example.com",
            "--out-dir", str(out_dir),
        ])
        assert ret == 0
        priv_file = out_dir / "private.asc"
        pub_file = out_dir / "public.asc"
        assert priv_file.exists()
        assert pub_file.exists()
        assert stat.S_IMODE(os.stat(priv_file).st_mode) == 0o600
        captured = capsys.readouterr()
        assert "ABCD1234EF567890" in captured.out or "ABCD1234EF567890" in captured.err


def test_cli_ssl_check_valid(capsys):
    fake_report = SSLReport(
        host="example.com",
        port=443,
        subject="CN=example.com",
        issuer="CN=DigiCert",
        valid_from="2026-01-01T00:00:00Z",
        valid_to="2027-01-01T00:00:00Z",
        days_remaining=120,
        is_expired=False,
        sans=["example.com"],
        tls_version="TLSv1.3",
        cipher_suite="TLS_AES_256_GCM_SHA384",
        warning=None,
    )
    with patch("ittools.cli.commands.ssl.check_remote_ssl", return_value=fake_report):
        # Table output
        ret = main(["ssl", "check", "example.com"])
        assert ret == 0
        captured = capsys.readouterr()
        assert "CN=example.com" in captured.out
        assert "120" in captured.out

        # JSON output
        ret_json = main(["ssl", "check", "example.com", "--json"])
        assert ret_json == 0
        captured_json = capsys.readouterr()
        assert '"host": "example.com"' in captured_json.out


def test_cli_ssl_check_network_error(capsys):
    with patch("ittools.cli.commands.ssl.check_remote_ssl", side_effect=OSError("Connection refused")):
        ret = main(["ssl", "check", "unreachable.local"])
        assert ret == 2
        captured = capsys.readouterr()
        assert "Connection refused" in captured.err


def test_cli_ssl_check_expired_or_expiring(capsys):
    fake_report = SSLReport(
        host="expired.example.com",
        port=443,
        subject="CN=expired.example.com",
        issuer="CN=DigiCert",
        valid_from="2025-01-01T00:00:00Z",
        valid_to="2026-01-01T00:00:00Z",
        days_remaining=-50,
        is_expired=True,
        sans=["expired.example.com"],
        tls_version="TLSv1.3",
        cipher_suite="TLS_AES_256_GCM_SHA384",
        warning="Certificate has expired",
    )
    with patch("ittools.cli.commands.ssl.check_remote_ssl", return_value=fake_report):
        ret = main(["ssl", "check", "expired.example.com"])
        # Should exit with code 3 on expired / security warning
        assert ret == 3
        captured = capsys.readouterr()
        assert "expired" in captured.out.lower() or "expired" in captured.err.lower()


def test_cli_ssl_headers(capsys):
    fake_report = HeadersReport(
        url="https://example.com",
        status_code=200,
        present_headers={"Strict-Transport-Security": "max-age=31536000"},
        missing_headers=["Permissions-Policy"],
        security_score="B",
        recommendations=["Add Permissions-Policy"],
    )
    with patch("ittools.cli.commands.ssl.check_security_headers", return_value=fake_report):
        ret = main(["ssl", "headers", "https://example.com"])
        assert ret == 0
        captured = capsys.readouterr()
        assert "Strict-Transport-Security" in captured.out
        assert "Score" in captured.out or "score" in captured.out

        # JSON mode
        ret_json = main(["ssl", "headers", "https://example.com", "--json"])
        assert ret_json == 0
        captured_json = capsys.readouterr()
        assert '"security_score": "B"' in captured_json.out


def test_cli_ssl_headers_network_error(capsys):
    with patch("ittools.cli.commands.ssl.check_security_headers", side_effect=OSError("Network unreachable")):
        ret = main(["ssl", "headers", "https://unreachable.local"])
        assert ret == 2
        captured = capsys.readouterr()
        assert "Network unreachable" in captured.err


def test_cli_ssl_match(tmp_path, capsys):
    res = generate_csr(CSRSubject(common_name="match.example.com"))
    key_file = tmp_path / "test.key"
    csr_file = tmp_path / "test.csr"
    key_file.write_text(res.private_key_pem, encoding="utf-8")
    csr_file.write_text(res.csr_pem, encoding="utf-8")

    # Match test: exit 0
    ret = main(["ssl", "match", "--key", str(key_file), "--cert", str(csr_file)])
    assert ret == 0
    captured = capsys.readouterr()
    assert "matches" in captured.out.lower()

    # Mismatch test: exit 3
    other_key = generate_rsa_keypair(key_size=2048)
    other_key_file = tmp_path / "other.key"
    other_key_file.write_text(other_key.private_key_pem, encoding="utf-8")

    ret_mismatch = main(["ssl", "match", "--key", str(other_key_file), "--cert", str(csr_file)])
    assert ret_mismatch == 3
    captured_mismatch = capsys.readouterr()
    assert "not match" in captured_mismatch.out.lower() or "mismatch" in captured_mismatch.out.lower()


def test_cli_config_generate(capsys):
    ret = main(["config", "generate", "--server", "nginx", "--domain", "mytest.com"])
    assert ret == 0
    captured = capsys.readouterr()
    assert "server_name mytest.com;" in captured.out


def test_cli_config_generate_apache_and_caddy(capsys):
    ret_apache = main(["config", "generate", "--server", "apache", "--domain", "apache.test.com"])
    assert ret_apache == 0
    captured_apache = capsys.readouterr()
    assert "ServerName apache.test.com" in captured_apache.out

    ret_caddy = main(["config", "generate", "--server", "caddy", "--domain", "caddy.test.com", "--no-hsts"])
    assert ret_caddy == 0
    captured_caddy = capsys.readouterr()
    assert "caddy.test.com {" in captured_caddy.out
    assert "Strict-Transport-Security" not in captured_caddy.out


def test_cli_debug_flag(capsys):
    # Trigger a validation error with and without --debug
    ret_no_debug = main(["config", "generate", "--server", "unknown_server"])
    assert ret_no_debug == 1
    captured_no_debug = capsys.readouterr()
    assert "Traceback" not in captured_no_debug.err
    assert "Unsupported server" in captured_no_debug.err

    ret_debug = main(["--debug", "config", "generate", "--server", "unknown_server"])
    assert ret_debug == 1
    captured_debug = capsys.readouterr()
    assert "Traceback" in captured_debug.err


def test_cli_csr_generate_no_orphaned_key_on_existing_csr(tmp_path, capsys):
    out_dir = tmp_path / "output"
    target_dir = out_dir / "orphan.test.com"
    target_dir.mkdir(parents=True)
    existing_csr = target_dir / "orphan.test.com.csr"
    existing_csr.write_text("dummy csr content", encoding="utf-8")

    key_file = target_dir / "orphan.test.com.key"

    # Should fail upfront before creating or touching .key file
    ret = main(["csr", "generate", "--cn", "orphan.test.com", "--output-dir", str(out_dir)])
    assert ret == 1
    assert not key_file.exists(), "Private key should NOT be created when destination CSR already exists"


def test_cli_keypair_rsa_no_orphaned_key_on_existing_pub(tmp_path, capsys):
    priv_file = tmp_path / "id_rsa"
    pub_file = tmp_path / "id_rsa.pub"
    pub_file.write_text("existing pub key", encoding="utf-8")

    ret = main(["keypair", "rsa", "--size", "2048", "--out", str(priv_file)])
    assert ret == 1
    assert not priv_file.exists(), "Private key should NOT be created when destination .pub already exists"


def test_cli_keypair_ssh_no_orphaned_key_on_existing_pub(tmp_path, capsys):
    priv_file = tmp_path / "id_ssh"
    pub_file = tmp_path / "id_ssh.pub"
    pub_file.write_text("existing ssh pub key", encoding="utf-8")

    ret = main(["keypair", "ssh", "--type", "ed25519", "--out", str(priv_file)])
    assert ret == 1
    assert not priv_file.exists(), "Private key should NOT be created when destination .pub already exists"


def test_cli_non_network_oserror_exits_code_1(capsys):
    import errno
    with patch("ittools.cli.commands.ssl.check_remote_ssl", side_effect=OSError(errno.ENOSPC, "No space left on device")):
        ret = main(["ssl", "check", "example.com"])
        # Non-network OSError must exit with 1 (validation/system error), NOT 2 (network error)
        assert ret == 1
        captured = capsys.readouterr()
        assert "No space left on device" in captured.err

