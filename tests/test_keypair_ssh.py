from ittools.core.keypair.ssh import generate_ssh_keypair, SSHKeyPair
from cryptography.hazmat.primitives import serialization
import pytest


def test_generate_ssh_ed25519():
    pair = generate_ssh_keypair(key_type="ed25519", comment="user@example.com")
    assert isinstance(pair, SSHKeyPair)
    assert pair.key_type == "ed25519"
    assert "BEGIN OPENSSH PRIVATE KEY" in pair.private_key
    assert pair.public_key.startswith("ssh-ed25519 ")
    assert pair.public_key.endswith("user@example.com")

    # Verify unencrypted private key can be loaded
    key = serialization.load_ssh_private_key(pair.private_key.encode("utf-8"), password=None)
    assert key is not None


def test_generate_ssh_rsa():
    pair = generate_ssh_keypair(key_type="rsa", key_size=2048, comment="rsa-key")
    assert isinstance(pair, SSHKeyPair)
    assert pair.key_type == "rsa"
    assert "BEGIN OPENSSH PRIVATE KEY" in pair.private_key
    assert pair.public_key.startswith("ssh-rsa ")
    assert pair.public_key.endswith("rsa-key")

    key = serialization.load_ssh_private_key(pair.private_key.encode("utf-8"), password=None)
    assert key is not None


def test_generate_ssh_encrypted():
    pair = generate_ssh_keypair(key_type="ed25519", password="sshsecretpassword")
    assert "BEGIN OPENSSH PRIVATE KEY" in pair.private_key

    # Loading with wrong password fails
    try:
        serialization.load_ssh_private_key(pair.private_key.encode("utf-8"), password=b"wrong")
        assert False, "Should have failed with wrong password"
    except (ValueError, TypeError):
        pass

    # Loading with right password succeeds
    key = serialization.load_ssh_private_key(pair.private_key.encode("utf-8"), password=b"sshsecretpassword")
    assert key is not None


def test_generate_ssh_unsupported_type():
    with pytest.raises(ValueError, match="Unsupported key type"):
        generate_ssh_keypair(key_type="ecdsa")


def test_generate_ssh_comment_sanitization():
    pair = generate_ssh_keypair(key_type="ed25519", comment="  user@example.com\r\nwith newline  ")
    assert "\n" not in pair.public_key
    assert "\r" not in pair.public_key
    assert pair.public_key.endswith("user@example.com  with newline")
    assert len(pair.public_key.splitlines()) == 1

