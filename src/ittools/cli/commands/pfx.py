"""CLI commands for PKCS#12 (PFX) containers."""

from __future__ import annotations

import argparse
import getpass
import os
from pathlib import Path
import sys

from ittools.core.pki.pfx import create_pfx_bundle, extract_pfx_bundle


def register_pfx_commands(subparsers: argparse._SubParsersAction) -> None:
    """Register 'pfx' command group and subcommands."""
    parser = subparsers.add_parser(
        "pfx",
        help="Create and extract PKCS#12 (.pfx / .p12) archives",
        description="Utilities for creating and extracting PKCS#12 / PFX archives",
    )
    pfx_sub = parser.add_subparsers(dest="subcommand")

    # pfx create
    create_p = pfx_sub.add_parser(
        "create",
        help="Bundle Private Key + Cert into .pfx",
        description="Bundle a private key and certificate into a PKCS#12 archive",
    )
    create_p.add_argument("--key", required=True, help="Path to private key PEM file")
    create_p.add_argument("--cert", required=True, help="Path to certificate PEM file")
    create_p.add_argument("--ca", help="Path to CA certificate PEM file or bundle")
    create_p.add_argument("--out", help="Output .pfx file path")
    create_p.add_argument("--password", help="Password for PFX archive")
    create_p.add_argument("--no-password", action="store_true", help="Do not encrypt PFX with password")
    create_p.add_argument("--key-password", help="Password to decrypt private key if encrypted")
    create_p.add_argument("--name", help="Friendly name / alias for certificate")
    create_p.add_argument("--force", action="store_true", help="Overwrite existing output file")
    create_p.set_defaults(handler=handle_pfx_create)

    # pfx extract
    extract_p = pfx_sub.add_parser(
        "extract",
        help="Extract components from .pfx",
        description="Extract private key, certificate, and CA certificates from a PKCS#12 archive",
    )
    extract_p.add_argument("--in", dest="in_file", required=True, help="Path to .pfx/.p12 file")
    extract_p.add_argument("--password", help="Password for PFX archive")
    extract_p.add_argument("--out-dir", help="Output directory for extracted files")
    extract_p.add_argument("--key-out", help="Custom path for extracted private key")
    extract_p.add_argument("--cert-out", help="Custom path for extracted certificate")
    extract_p.add_argument("--ca-out", help="Custom path for extracted CA bundle")
    extract_p.add_argument("--force", action="store_true", help="Overwrite existing output files")
    extract_p.set_defaults(handler=handle_pfx_extract)


def handle_pfx_create(args: argparse.Namespace) -> int:
    """Handle 'ittools pfx create'."""
    key_path = Path(args.key)
    cert_path = Path(args.cert)

    if not key_path.exists():
        sys.stderr.write(f"error: Private key file not found: {args.key}\n")
        return 1
    if not cert_path.exists():
        sys.stderr.write(f"error: Certificate file not found: {args.cert}\n")
        return 1

    out_path = Path(args.out) if args.out else Path(f"./output/{cert_path.stem}.pfx")
    if out_path.exists() and not args.force:
        sys.stderr.write(f"error: Destination file '{out_path}' already exists. Use --force to overwrite.\n")
        return 1

    ca_content: str | None = None
    if args.ca:
        ca_p = Path(args.ca)
        if not ca_p.exists():
            sys.stderr.write(f"error: CA file not found: {args.ca}\n")
            return 1
        ca_content = ca_p.read_text(encoding="utf-8")

    password = args.password
    if password is None and not args.no_password:
        if sys.stdin.isatty():
            password = getpass.getpass("Enter password for PFX (leave empty for none): ")
            if not password:
                password = None

    try:
        key_pem = key_path.read_text(encoding="utf-8")
        cert_pem = cert_path.read_text(encoding="utf-8")
        pfx_bytes = create_pfx_bundle(
            private_key_pem=key_pem,
            cert_pem=cert_pem,
            ca_certs_pem=ca_content,
            password=password,
            friendly_name=args.name,
            key_password=args.key_password,
        )
    except Exception as exc:
        sys.stderr.write(f"error: Failed to create PFX: {exc}\n")
        return 1

    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_bytes(pfx_bytes)
    sys.stdout.write(f"PKCS#12 archive successfully created at: {out_path}\n")
    return 0


def handle_pfx_extract(args: argparse.Namespace) -> int:
    """Handle 'ittools pfx extract'."""
    in_path = Path(args.in_file)
    if not in_path.exists():
        sys.stderr.write(f"error: PFX file not found: {args.in_file}\n")
        return 1

    password = args.password
    if password is None and sys.stdin.isatty():
        password = getpass.getpass("Enter password for PFX (leave empty if none): ")
        if not password:
            password = None

    try:
        pfx_bytes = in_path.read_bytes()
        result = extract_pfx_bundle(pfx_bytes, password=password)
    except Exception as exc:
        sys.stderr.write(f"error: Failed to extract PFX: {exc}\n")
        return 1

    out_dir = Path(args.out_dir) if args.out_dir else Path(f"./output/{in_path.stem}")
    key_dest = Path(args.key_out) if args.key_out else out_dir / f"{in_path.stem}.key"
    cert_dest = Path(args.cert_out) if args.cert_out else out_dir / f"{in_path.stem}.crt"
    ca_dest = Path(args.ca_out) if args.ca_out else out_dir / f"{in_path.stem}-ca.crt"

    # Upfront overwrite checks before writing any files
    targets: list[Path] = []
    if result.private_key_pem:
        targets.append(key_dest)
    if result.cert_pem:
        targets.append(cert_dest)
    if result.ca_certs_pem:
        targets.append(ca_dest)

    for target in targets:
        if target.exists() and not args.force:
            sys.stderr.write(f"error: Destination file '{target}' already exists. Use --force to overwrite.\n")
            return 1

    out_dir.mkdir(parents=True, exist_ok=True)

    if result.private_key_pem:
        key_dest.parent.mkdir(parents=True, exist_ok=True)
        flags = os.O_WRONLY | os.O_CREAT | (os.O_TRUNC if args.force else os.O_EXCL)
        fd = os.open(str(key_dest), flags, 0o600)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                f.write(result.private_key_pem)
        finally:
            os.chmod(str(key_dest), 0o600)
        sys.stdout.write(f"Private key extracted to: {key_dest} (mode 0600)\n")

    if result.cert_pem:
        cert_dest.parent.mkdir(parents=True, exist_ok=True)
        cert_dest.write_text(result.cert_pem, encoding="utf-8")
        sys.stdout.write(f"Certificate extracted to: {cert_dest}\n")

    if result.ca_certs_pem:
        ca_dest.parent.mkdir(parents=True, exist_ok=True)
        ca_bundle = "".join(c if c.endswith("\n") else c + "\n" for c in result.ca_certs_pem)
        ca_dest.write_text(ca_bundle, encoding="utf-8")
        sys.stdout.write(f"CA chain extracted to: {ca_dest}\n")

    return 0
