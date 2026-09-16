"""SSH keypair generation service (Ed25519 and RSA)."""

from __future__ import annotations

from dataclasses import dataclass

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa


@dataclass
class SSHKeyPair:
    """Represents an SSH key pair with OpenSSH formatting."""

    private_key: str
    public_key: str
    key_type: str


def generate_ssh_keypair(
    key_type: str = "ed25519",
    key_size: int = 2048,
    password: str | None = None,
    comment: str = "",
) -> SSHKeyPair:
    """Generate an SSH key pair in OpenSSH format.

    Args:
        key_type: Key algorithm ('ed25519' or 'rsa').
        key_size: Key size in bits (only used for RSA keys, minimum 512).
        password: Optional passphrase to encrypt the private key.
        comment: Optional comment appended to the public key.

    Returns:
        SSHKeyPair containing private key, public key, and key type.

    Raises:
        ValueError: If key_type is unsupported or key_size is invalid.
    """
    normalized_type = key_type.lower().strip()

    if normalized_type == "ed25519":
        private_key = ed25519.Ed25519PrivateKey.generate()
    elif normalized_type == "rsa":
        if key_size < 512:
            raise ValueError("key_size must be at least 512")
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
        )
    else:
        raise ValueError(
            f"Unsupported key type: {key_type}. Must be 'ed25519' or 'rsa'."
        )

    if password:
        encryption_algorithm: serialization.KeySerializationEncryption = (
            serialization.BestAvailableEncryption(password.encode("utf-8"))
        )
    else:
        encryption_algorithm = serialization.NoEncryption()

    private_key_str = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.OpenSSH,
        encryption_algorithm=encryption_algorithm,
    ).decode("utf-8")

    raw_public_str = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.OpenSSH,
        format=serialization.PublicFormat.OpenSSH,
    ).decode("utf-8")

    clean_comment = comment.strip()
    public_key_str = (
        f"{raw_public_str} {clean_comment}" if clean_comment else raw_public_str
    )

    return SSHKeyPair(
        private_key=private_key_str,
        public_key=public_key_str,
        key_type=normalized_type,
    )
