"""Cryptographic keypair generation tools for the Model Context Protocol (MCP) server."""

from __future__ import annotations

import os

from ittools.core.keypair.passphrase import generate_passphrase
from ittools.core.keypair.pgp import generate_pgp_key
from ittools.core.keypair.rsa import generate_rsa_keypair
from ittools.core.keypair.ssh import generate_ssh_keypair
from ittools.mcp.tools.pki import _write_public_file, _write_secure_file


def keypair_passphrase(
    words: int = 4,
    separator: str = "-",
    capitalize: bool = False,
    include_numbers: bool = False,
    include_special: bool = False,
) -> dict:
    """Generate an EFF-style multi-word cryptographically secure passphrase.

    Args:
        words: Number of words in the passphrase (minimum 1, default: 4).
        separator: String delimiter placed between words (default: "-").
        capitalize: If True, capitalize each word.
        include_numbers: If True, append a random digit (0-9).
        include_special: If True, append a random special character.

    Returns:
        Dictionary containing:
            - passphrase: Generated passphrase string.

    Raises:
        ValueError: If words is less than 1.
    """
    passphrase = generate_passphrase(
        words_count=words,
        separator=separator,
        capitalize=capitalize,
        include_numbers=include_numbers,
        include_special=include_special,
    )
    return {"passphrase": passphrase}


def keypair_rsa(
    key_size: int = 2048,
    password: str | None = None,
    output_path: str | None = None,
    force: bool = False,
) -> dict:
    """Generate a standard PKCS#8 RSA keypair.

    Args:
        key_size: Bit length of the RSA key (minimum 512, default: 2048).
        password: Optional passphrase to encrypt the private key.
        output_path: Optional destination path to write private key (0600) and public key (.pub, 0644).
        force: Overwrite existing target files if True.

    Returns:
        Dictionary containing:
            - private_key_pem: PEM-encoded RSA private key.
            - public_key_pem: PEM-encoded SubjectPublicKeyInfo public key.
            - saved_files: List of file paths written if output_path provided, otherwise empty.

    Raises:
        ValueError: If key_size is less than 512.
        FileExistsError: If target output files exist and force is False.
    """
    saved_files: list[str] = []
    pub_path: str | None = None

    if output_path:
        pub_path = f"{output_path}.pub"
        if not force:
            existing = [f for f in (output_path, pub_path) if os.path.exists(f)]
            if existing:
                raise FileExistsError(
                    f"Target file already exists: {', '.join(existing)} (use force=True to overwrite)"
                )

    pair = generate_rsa_keypair(key_size=key_size, password=password)

    if output_path and pub_path:
        _write_secure_file(output_path, pair.private_key_pem, force=force)
        _write_public_file(pub_path, pair.public_key_pem, force=force)
        saved_files = [output_path, pub_path]

    return {
        "private_key_pem": pair.private_key_pem,
        "public_key_pem": pair.public_key_pem,
        "saved_files": saved_files,
    }


def keypair_ssh(
    key_type: str = "ed25519",
    key_size: int = 2048,
    comment: str = "",
    password: str | None = None,
    output_path: str | None = None,
    force: bool = False,
) -> dict:
    """Generate an OpenSSH-compatible keypair (Ed25519 or RSA).

    Args:
        key_type: Key algorithm ('ed25519' or 'rsa', default: 'ed25519').
        key_size: Key size in bits (only used for RSA keys, minimum 512, default: 2048).
        comment: Optional comment appended to the public key.
        password: Optional passphrase to encrypt the private key.
        output_path: Optional destination path to write private key (0600) and public key (.pub, 0644).
        force: Overwrite existing target files if True.

    Returns:
        Dictionary containing:
            - private_key: OpenSSH-formatted private key string.
            - public_key: OpenSSH-formatted public key string.
            - saved_files: List of file paths written if output_path provided, otherwise empty.

    Raises:
        ValueError: If key_type is unsupported or key_size is invalid.
        FileExistsError: If target output files exist and force is False.
    """
    saved_files: list[str] = []
    pub_path: str | None = None

    if output_path:
        pub_path = f"{output_path}.pub"
        if not force:
            existing = [f for f in (output_path, pub_path) if os.path.exists(f)]
            if existing:
                raise FileExistsError(
                    f"Target file already exists: {', '.join(existing)} (use force=True to overwrite)"
                )

    pair = generate_ssh_keypair(
        key_type=key_type,
        key_size=key_size,
        password=password,
        comment=comment,
    )

    if output_path and pub_path:
        _write_secure_file(output_path, pair.private_key, force=force)
        _write_public_file(pub_path, pair.public_key, force=force)
        saved_files = [output_path, pub_path]

    return {
        "private_key": pair.private_key,
        "public_key": pair.public_key,
        "saved_files": saved_files,
    }


def keypair_pgp(
    name: str,
    email: str,
    comment: str = "",
    expire_years: int = 1,
    password: str | None = None,
    output_dir: str | None = None,
    force: bool = False,
) -> dict:
    """Generate an ASCII-armored PGP keypair via GnuPG in an isolated environment.

    Args:
        name: Real name of key owner.
        email: Email address of key owner.
        comment: Optional comment for user ID.
        expire_years: Expiration duration in years (default: 1, 0 means no expiration).
        password: Optional passphrase to protect private key.
        output_dir: Optional directory to write private.asc (0600) and public.asc (0644).
        force: Overwrite existing target files if True.

    Returns:
        Dictionary containing:
            - fingerprint: Hexadecimal fingerprint string.
            - private_key: ASCII-armored PGP private key.
            - public_key: ASCII-armored PGP public key.
            - saved_files: List of file paths written if output_dir provided, otherwise empty.

    Raises:
        ValueError: If name or email is empty, or expire_years is negative.
        GPGNotInstalledError: If system 'gpg' binary is not installed.
        FileExistsError: If target output files exist and force is False.
    """
    saved_files: list[str] = []
    priv_path: str | None = None
    pub_path: str | None = None

    if output_dir:
        priv_path = os.path.join(output_dir, "private.asc")
        pub_path = os.path.join(output_dir, "public.asc")
        if not force:
            existing = [f for f in (priv_path, pub_path) if os.path.exists(f)]
            if existing:
                raise FileExistsError(
                    f"Target file already exists: {', '.join(existing)} (use force=True to overwrite)"
                )

    pair = generate_pgp_key(
        name=name,
        email=email,
        comment=comment,
        expire_years=expire_years,
        passphrase=password,
    )

    if output_dir and priv_path and pub_path:
        _write_secure_file(priv_path, pair.private_key, force=force)
        _write_public_file(pub_path, pair.public_key, force=force)
        saved_files = [priv_path, pub_path]

    return {
        "fingerprint": pair.fingerprint,
        "private_key": pair.private_key,
        "public_key": pair.public_key,
        "saved_files": saved_files,
    }
