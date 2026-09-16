from ittools.core.keypair.rsa import generate_rsa_keypair, RSAKeyPair
from cryptography.hazmat.primitives import serialization
import pytest


def test_generate_rsa_keypair_unencrypted():
    pair = generate_rsa_keypair(key_size=2048)
    assert isinstance(pair, RSAKeyPair)
    assert "BEGIN RSA PRIVATE KEY" in pair.private_key_pem or "BEGIN PRIVATE KEY" in pair.private_key_pem
    assert "BEGIN PUBLIC KEY" in pair.public_key_pem

    # Verify public key can be loaded
    pub_key = serialization.load_pem_public_key(pair.public_key_pem.encode("utf-8"))
    assert pub_key.key_size == 2048

    # Verify private key can be loaded without password
    priv_key = serialization.load_pem_private_key(pair.private_key_pem.encode("utf-8"), password=None)
    assert priv_key.key_size == 2048


def test_generate_rsa_keypair_encrypted():
    pair = generate_rsa_keypair(key_size=2048, password="secretpassword")
    assert isinstance(pair, RSAKeyPair)
    assert "ENCRYPTED" in pair.private_key_pem or "BEGIN ENCRYPTED PRIVATE KEY" in pair.private_key_pem

    # Loading with wrong password fails
    try:
        serialization.load_pem_private_key(pair.private_key_pem.encode("utf-8"), password=b"wrong")
        assert False, "Should have failed with wrong password"
    except (ValueError, TypeError):
        pass

    # Loading with correct password succeeds
    priv_key = serialization.load_pem_private_key(
        pair.private_key_pem.encode("utf-8"),
        password=b"secretpassword",
    )
    assert priv_key.key_size == 2048


def test_generate_rsa_keypair_invalid_key_size():
    with pytest.raises(ValueError, match="key_size must be at least 512"):
        generate_rsa_keypair(key_size=256)
