"""Core keypair services (passphrase, RSA, SSH, PGP)."""

from ittools.core.keypair.passphrase import generate_passphrase
from ittools.core.keypair.pgp import GPGNotInstalledError, PGPKeyPair, generate_pgp_key
from ittools.core.keypair.rsa import RSAKeyPair, generate_rsa_keypair
from ittools.core.keypair.ssh import SSHKeyPair, generate_ssh_keypair

__all__ = [
    "generate_passphrase",
    "RSAKeyPair",
    "generate_rsa_keypair",
    "SSHKeyPair",
    "generate_ssh_keypair",
    "PGPKeyPair",
    "generate_pgp_key",
    "GPGNotInstalledError",
]
