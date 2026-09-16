"""CSR generation and decoding commands."""

from __future__ import annotations

import argparse
import os
import sys

from ittools.cli.prompt import prompt_subject
from ittools.core.pki.csr import CSRSubject, decode_csr, generate_csr


def write_private_key_file(path: str, content: str, force: bool = False) -> None:
    """Write private key to path with 0600 permissions, respecting force flag."""
    if not force and os.path.exists(path):
        raise FileExistsError(f"File already exists: {path} (use --force to overwrite)")
    flags = os.O_WRONLY | os.O_CREAT | (os.O_TRUNC if force else os.O_EXCL)
    fd = os.open(path, flags, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(content)
    finally:
        os.chmod(path, 0o600)


def write_file(path: str, content: str, force: bool = False) -> None:
    """Write regular file to path, respecting force flag."""
    if not force and os.path.exists(path):
        raise FileExistsError(f"File already exists: {path} (use --force to overwrite)")
    flags = os.O_WRONLY | os.O_CREAT | (os.O_TRUNC if force else os.O_EXCL)
    fd = os.open(path, flags, 0o644)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(content)


def handle_csr_generate(args: argparse.Namespace) -> int:
    """Handle 'csr generate' command."""
    is_interactive = (
        args.cn is None
        and not args.org
        and not args.ou
        and not args.city
        and not args.state
        and not args.country
        and not args.email
        and not args.san
    )

    if is_interactive:
        subject, sans, key_size = prompt_subject()
    else:
        if not args.cn or not args.cn.strip():
            raise ValueError("--cn (Common Name) is required in non-interactive mode")
        sans = [s.strip() for s in (args.san or "").split(",") if s.strip()]
        subject = CSRSubject(
            common_name=args.cn.strip(),
            organization=args.org or "",
            organizational_unit=args.ou or "",
            city=args.city or "",
            state=args.state or "",
            country=args.country or "",
            email=args.email or "",
        )
        key_size = args.key_size

    result = generate_csr(subject=subject, sans=sans, key_size=key_size)

    output_dir = args.output_dir or "./output"
    target_dir = os.path.join(output_dir, result.sanitized_cn)
    os.makedirs(target_dir, exist_ok=True)
    key_file = os.path.join(target_dir, f"{result.sanitized_cn}.key")
    csr_file = os.path.join(target_dir, f"{result.sanitized_cn}.csr")

    write_private_key_file(key_file, result.private_key_pem, force=args.force)
    write_file(csr_file, result.csr_pem, force=args.force)

    sys.stdout.write(result.private_key_pem)
    sys.stdout.write(result.csr_pem)
    sys.stdout.write(f"Saved private key to {key_file}\n")
    sys.stdout.write(f"Saved CSR to {csr_file}\n")
    return 0


def handle_csr_decode(args: argparse.Namespace) -> int:
    """Handle 'csr decode' command."""
    if args.in_file:
        with open(args.in_file, "r", encoding="utf-8") as f:
            csr_pem = f.read()
    else:
        csr_pem = sys.stdin.read()

    if not csr_pem.strip():
        raise ValueError("No CSR data provided")

    details = decode_csr(csr_pem)
    sans_str = ", ".join(details.sans) if details.sans else "(none)"
    output_lines = [
        f"Common Name:         {details.common_name}",
        f"Organization:        {details.organization or '(none)'}",
        f"Country:             {details.country or '(none)'}",
        f"SANs:                {sans_str}",
        f"Key Type:            {details.key_type}",
        f"Key Size:            {details.key_size}",
        f"Signature Algorithm: {details.signature_algorithm}",
    ]
    sys.stdout.write("\n".join(output_lines) + "\n")
    return 0


def register_csr_commands(subparsers: argparse._SubParsersAction) -> None:
    """Register 'csr' command group and subcommands."""
    csr_parser = subparsers.add_parser(
        "csr",
        help="PKI Certificate Signing Request (CSR) utilities",
        description="Generate and decode PKCS#10 Certificate Signing Requests",
    )
    csr_subparsers = csr_parser.add_subparsers(dest="subcommand")

    # csr generate
    gen_parser = csr_subparsers.add_parser(
        "generate",
        help="Generate private key and CSR",
        description="Generate a new RSA private key and PKCS#10 CSR",
    )
    gen_parser.add_argument("--cn", help="Common Name (domain or hostname)")
    gen_parser.add_argument("--org", default="", help="Organization name")
    gen_parser.add_argument("--ou", default="", help="Organizational Unit")
    gen_parser.add_argument("--city", default="", help="City / Locality")
    gen_parser.add_argument("--state", default="", help="State / Province")
    gen_parser.add_argument("--country", default="", help="2-letter ISO country code")
    gen_parser.add_argument("--email", default="", help="Email address")
    gen_parser.add_argument("--san", default="", help="Comma-separated Subject Alternative Names")
    gen_parser.add_argument("--key-size", type=int, default=2048, help="RSA key bit length (default: 2048)")
    gen_parser.add_argument("--force", action="store_true", help="Overwrite existing output files")
    gen_parser.add_argument("--output-dir", default="./output", help="Output directory (default: ./output)")
    gen_parser.set_defaults(handler=handle_csr_generate)

    # csr decode
    decode_parser = csr_subparsers.add_parser(
        "decode",
        help="Decode and inspect a CSR",
        description="Decode a PEM-encoded Certificate Signing Request from file or stdin",
    )
    decode_parser.add_argument("--in", dest="in_file", help="Path to CSR file (reads stdin if omitted)")
    decode_parser.set_defaults(handler=handle_csr_decode)
