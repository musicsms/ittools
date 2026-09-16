"""PGP key generation service using GnuPG."""

from __future__ import annotations

from dataclasses import dataclass
import os
import shutil
import tempfile

import gnupg


class GPGNotInstalledError(Exception):
    """Raised when the system gpg binary cannot be found in PATH."""


@dataclass
class PGPKeyPair:
    """Represents a PGP key pair and its primary fingerprint."""

    private_key: str
    public_key: str
    fingerprint: str


def generate_pgp_key(
    name: str,
    email: str,
    comment: str = "",
    key_type: str = "RSA",
    key_size: int = 2048,
    expire_years: int = 1,
    passphrase: str | None = None,
) -> PGPKeyPair:
    """Generate a PGP key pair in an isolated temporary keyring.

    Args:
        name: Real name of the key owner.
        email: Email address of the key owner.
        comment: Optional comment for user ID.
        key_type: Key algorithm (e.g. 'RSA').
        key_size: Key length in bits (default 2048).
        expire_years: Expiration duration in years (0 means does not expire).
        passphrase: Optional passphrase to protect the private key.

    Returns:
        PGPKeyPair containing ASCII-armored private and public keys and fingerprint.

    Raises:
        GPGNotInstalledError: If system 'gpg' executable is not found.
        ValueError: If name or email is empty.
        RuntimeError: If key generation or export fails.
    """
    if not shutil.which("gpg"):
        raise GPGNotInstalledError("System gpg binary is not installed.")

    if not name or not name.strip():
        raise ValueError("Name cannot be empty")
    if not email or not email.strip():
        raise ValueError("Email cannot be empty")

    expire_str = "0" if expire_years == 0 else f"{expire_years}y"

    with tempfile.TemporaryDirectory() as temp_dir:
        # Configure gpg-agent and gpg for unattended loopback pinentry
        agent_conf = os.path.join(temp_dir, "gpg-agent.conf")
        with open(agent_conf, "w", encoding="utf-8") as f:
            f.write("allow-loopback-pinentry\n")

        gpg_conf = os.path.join(temp_dir, "gpg.conf")
        with open(gpg_conf, "w", encoding="utf-8") as f:
            f.write("pinentry-mode loopback\n")

        gpg = gnupg.GPG(gnupghome=temp_dir, options=["--pinentry-mode", "loopback"])

        gen_kwargs: dict[str, object] = {
            "name_real": name.strip(),
            "name_email": email.strip(),
            "name_comment": comment.strip() if comment else "",
            "key_type": key_type,
            "key_length": key_size,
            "expire_date": expire_str,
        }

        if passphrase:
            gen_kwargs["passphrase"] = passphrase
        else:
            gen_kwargs["no_protection"] = True

        input_data = gpg.gen_key_input(**gen_kwargs)
        result = gpg.gen_key(input_data)

        if not result.fingerprint:
            raise RuntimeError(
                f"Failed to generate PGP key: {result.status} {result.stderr}"
            )

        fingerprint = str(result.fingerprint)
        public_key = gpg.export_keys(fingerprint)
        private_key = gpg.export_keys(
            fingerprint, secret=True, passphrase=passphrase or ""
        )

        if not public_key:
            raise RuntimeError(
                f"Failed to export PGP public key for fingerprint {fingerprint}"
            )
        if not private_key:
            raise RuntimeError(
                f"Failed to export PGP private key for fingerprint {fingerprint}"
            )

        return PGPKeyPair(
            private_key=private_key,
            public_key=public_key,
            fingerprint=fingerprint,
        )
