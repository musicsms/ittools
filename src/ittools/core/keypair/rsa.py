"""RSA keypair generation service."""

from __future__ import annotations

from dataclasses import dataclass

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa


@dataclass
class RSAKeyPair:
    """Represents an RSA private and public key pair in PEM format."""

    private_key_pem: str
    public_key_pem: str


def generate_rsa_keypair(
    key_size: int = 2048,
    password: str | None = None,
) -> RSAKeyPair:
    """Generate an RSA key pair.

    Args:
        key_size: Bit length of the RSA key (minimum 512, default 2048).
        password: Optional passphrase to encrypt the private key.

    Returns:
        RSAKeyPair containing PEM-encoded private and public keys.

    Raises:
        ValueError: If key_size is less than 512.
    """
    if key_size < 512:
        raise ValueError("key_size must be at least 512")

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
    )

    if password:
        encryption_algorithm: serialization.KeySerializationEncryption = (
            serialization.BestAvailableEncryption(password.encode("utf-8"))
        )
    else:
        encryption_algorithm = serialization.NoEncryption()

    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=encryption_algorithm,
    ).decode("utf-8")

    public_key_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")

    return RSAKeyPair(
        private_key_pem=private_key_pem,
        public_key_pem=public_key_pem,
    )
