import shutil
from unittest.mock import patch
import pytest
from ittools.core.keypair.pgp import generate_pgp_key, GPGNotInstalledError, PGPKeyPair


def test_generate_pgp_key():
    if not shutil.which("gpg"):
        with pytest.raises(GPGNotInstalledError):
            generate_pgp_key(name="Alice", email="alice@example.com")
    else:
        key = generate_pgp_key(name="Alice", email="alice@example.com", key_size=2048)
        assert isinstance(key, PGPKeyPair)
        assert "-----BEGIN PGP PRIVATE KEY BLOCK-----" in key.private_key
        assert "-----BEGIN PGP PUBLIC KEY BLOCK-----" in key.public_key
        assert len(key.fingerprint) > 0


def test_generate_pgp_key_missing_gpg():
    with patch("shutil.which", return_value=None):
        with pytest.raises(GPGNotInstalledError, match="System gpg binary is not installed"):
            generate_pgp_key(name="Alice", email="alice@example.com")


def test_generate_pgp_key_with_passphrase():
    if not shutil.which("gpg"):
        pytest.skip("gpg not installed")
    key = generate_pgp_key(
        name="Bob",
        email="bob@example.com",
        comment="test key",
        key_size=2048,
        passphrase="pgpsecretpassword",
    )
    assert isinstance(key, PGPKeyPair)
    assert "-----BEGIN PGP PRIVATE KEY BLOCK-----" in key.private_key
    assert "-----BEGIN PGP PUBLIC KEY BLOCK-----" in key.public_key
    assert len(key.fingerprint) > 0


def test_generate_pgp_key_invalid_inputs():
    with pytest.raises(ValueError, match="Name cannot be empty"):
        generate_pgp_key(name="", email="alice@example.com")
    with pytest.raises(ValueError, match="Email cannot be empty"):
        generate_pgp_key(name="Alice", email="")
    with pytest.raises(ValueError, match="expire_years must be non-negative"):
        generate_pgp_key(name="Alice", email="alice@example.com", expire_years=-1)


def test_generate_pgp_key_gpg_agent_cleanup():
    if not shutil.which("gpg"):
        pytest.skip("gpg not installed")
    with patch("subprocess.run") as mock_run:
        generate_pgp_key(name="Alice", email="alice@example.com", key_size=2048)
        # Check that gpgconf was called to kill gpg-agent
        kill_calls = [
            call for call in mock_run.call_args_list
            if call[0][0][0] == "gpgconf" and "--kill" in call[0][0] and "gpg-agent" in call[0][0]
        ]
        assert len(kill_calls) >= 1

