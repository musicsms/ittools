"""Keypair generation commands (passphrase, RSA, SSH, PGP)."""

from __future__ import annotations

import argparse
import os
import sys

from ittools.cli.commands.csr import write_file, write_private_key_file
from ittools.core.keypair.passphrase import generate_passphrase
from ittools.core.keypair.pgp import generate_pgp_key
from ittools.core.keypair.rsa import generate_rsa_keypair
from ittools.core.keypair.ssh import generate_ssh_keypair


def handle_keypair_passphrase(args: argparse.Namespace) -> int:
    """Handle 'keypair passphrase' command."""
    passphrase = generate_passphrase(
        words_count=args.words,
        separator=args.sep,
        capitalize=args.capitalize,
        include_numbers=args.numbers,
        include_special=args.special,
    )
    sys.stdout.write(f"{passphrase}\n")
    return 0


def handle_keypair_rsa(args: argparse.Namespace) -> int:
    """Handle 'keypair rsa' command."""
    keypair = generate_rsa_keypair(key_size=args.size, password=args.password)
    if args.out:
        priv_path = args.out
        pub_path = f"{args.out}.pub"
        write_private_key_file(priv_path, keypair.private_key_pem, force=args.force)
        write_file(pub_path, keypair.public_key_pem, force=args.force)
        sys.stderr.write(f"Saved private key to {priv_path}\nSaved public key to {pub_path}\n")
    else:
        sys.stdout.write(keypair.private_key_pem)
        sys.stdout.write(keypair.public_key_pem)
    return 0


def handle_keypair_ssh(args: argparse.Namespace) -> int:
    """Handle 'keypair ssh' command."""
    keypair = generate_ssh_keypair(
        key_type=args.type,
        key_size=args.size,
        password=args.password,
        comment=args.comment or "",
    )
    if args.out:
        priv_path = args.out
        pub_path = f"{args.out}.pub"
        write_private_key_file(priv_path, keypair.private_key, force=args.force)
        write_file(pub_path, keypair.public_key, force=args.force)
        sys.stderr.write(f"Saved private key to {priv_path}\nSaved public key to {pub_path}\n")
    else:
        sys.stdout.write(f"{keypair.private_key}\n")
        sys.stdout.write(f"{keypair.public_key}\n")
    return 0


def handle_keypair_pgp(args: argparse.Namespace) -> int:
    """Handle 'keypair pgp' command."""
    keypair = generate_pgp_key(
        name=args.name,
        email=args.email,
        comment=args.comment or "",
        expire_years=args.expire,
        passphrase=args.password,
    )
    if args.out_dir:
        os.makedirs(args.out_dir, exist_ok=True)
        priv_path = os.path.join(args.out_dir, "private.asc")
        pub_path = os.path.join(args.out_dir, "public.asc")
        write_private_key_file(priv_path, keypair.private_key, force=args.force)
        write_file(pub_path, keypair.public_key, force=args.force)
        sys.stdout.write(f"Fingerprint: {keypair.fingerprint}\n")
        sys.stderr.write(f"Saved private key to {priv_path}\nSaved public key to {pub_path}\n")
    else:
        sys.stdout.write(f"Fingerprint: {keypair.fingerprint}\n")
        sys.stdout.write(f"{keypair.private_key}\n")
        sys.stdout.write(f"{keypair.public_key}\n")
    return 0


def register_keypair_commands(subparsers: argparse._SubParsersAction) -> None:
    """Register 'keypair' command group and subcommands."""
    keypair_parser = subparsers.add_parser(
        "keypair",
        help="Cryptographic keypair generation utilities",
        description="Generate passphrases, RSA, SSH, and PGP keypairs",
    )
    keypair_subparsers = keypair_parser.add_subparsers(dest="subcommand")

    # keypair passphrase
    passphrase_parser = keypair_subparsers.add_parser(
        "passphrase",
        help="Generate cryptographically secure passphrase",
        description="Generate a multi-word passphrase from a built-in wordlist",
    )
    passphrase_parser.add_argument("--words", type=int, default=4, help="Word count (default: 4)")
    passphrase_parser.add_argument("--sep", default="-", help="Word separator (default: '-')")
    passphrase_parser.add_argument("--capitalize", action="store_true", help="Capitalize each word")
    passphrase_parser.add_argument("--numbers", action="store_true", help="Append random digit")
    passphrase_parser.add_argument("--special", action="store_true", help="Append random special character")
    passphrase_parser.set_defaults(handler=handle_keypair_passphrase)

    # keypair rsa
    rsa_parser = keypair_subparsers.add_parser(
        "rsa",
        help="Generate RSA keypair",
        description="Generate an RSA private and public keypair",
    )
    rsa_parser.add_argument("--size", type=int, default=2048, help="RSA key bit length (default: 2048)")
    rsa_parser.add_argument("--password", default=None, help="Passphrase to encrypt private key")
    rsa_parser.add_argument("--out", default=None, help="Base path to output private and public (.pub) keys")
    rsa_parser.add_argument("--force", action="store_true", help="Overwrite existing output files")
    rsa_parser.set_defaults(handler=handle_keypair_rsa)

    # keypair ssh
    ssh_parser = keypair_subparsers.add_parser(
        "ssh",
        help="Generate SSH keypair",
        description="Generate an OpenSSH format private and public keypair",
    )
    ssh_parser.add_argument(
        "--type",
        default="ed25519",
        choices=["ed25519", "rsa"],
        help="Key algorithm ('ed25519' or 'rsa', default: 'ed25519')",
    )
    ssh_parser.add_argument("--size", type=int, default=2048, help="Key size for RSA (default: 2048)")
    ssh_parser.add_argument("--comment", default="", help="Comment appended to public key")
    ssh_parser.add_argument("--password", default=None, help="Passphrase to encrypt private key")
    ssh_parser.add_argument("--out", default=None, help="Base path to output private and public (.pub) keys")
    ssh_parser.add_argument("--force", action="store_true", help="Overwrite existing output files")
    ssh_parser.set_defaults(handler=handle_keypair_ssh)

    # keypair pgp
    pgp_parser = keypair_subparsers.add_parser(
        "pgp",
        help="Generate PGP keypair",
        description="Generate an ASCII-armored PGP keypair using system GnuPG",
    )
    pgp_parser.add_argument("--name", required=True, help="User's real name")
    pgp_parser.add_argument("--email", required=True, help="User's email address")
    pgp_parser.add_argument("--comment", default="", help="User comment")
    pgp_parser.add_argument("--expire", type=int, default=1, help="Expiration in years (0 for never, default: 1)")
    pgp_parser.add_argument("--password", default=None, help="Passphrase to protect private key")
    pgp_parser.add_argument("--out-dir", default=None, help="Directory to save private.asc and public.asc")
    pgp_parser.add_argument("--force", action="store_true", help="Overwrite existing output files")
    pgp_parser.set_defaults(handler=handle_keypair_pgp)
