"""Server TLS configuration generation commands."""

from __future__ import annotations

import argparse
import sys

from ittools.cli.commands.csr import write_file
from ittools.core.config_gen.generator import generate_server_config


def handle_config_generate(args: argparse.Namespace) -> int:
    """Handle 'config generate' command."""
    if args.out and not args.force and os.path.exists(args.out):
        raise FileExistsError(f"Target file already exists: {args.out} (use --force to overwrite)")

    config = generate_server_config(
        server=args.server,
        profile=args.profile,
        domain=args.domain,
        cert_path=args.cert,
        key_path=args.key,
        hsts=not args.no_hsts,
    )
    if args.out:
        write_file(args.out, config, force=args.force)
        sys.stderr.write(f"Saved configuration to {args.out}\n")
    else:
        sys.stdout.write(config)
    return 0


def register_config_commands(subparsers: argparse._SubParsersAction) -> None:
    """Register 'config' command group and subcommands."""
    config_parser = subparsers.add_parser(
        "config",
        help="Hardened server TLS configuration generator",
        description="Generate hardened TLS configurations adhering to Mozilla guidelines",
    )
    config_subparsers = config_parser.add_subparsers(dest="subcommand")

    # config generate
    gen_parser = config_subparsers.add_parser(
        "generate",
        help="Generate server TLS virtual host configuration",
        description="Generate Nginx, Apache, or Caddy TLS configuration blocks",
    )
    gen_parser.add_argument(
        "--server",
        required=True,
        help="Server software ('nginx', 'apache', 'caddy')",
    )
    gen_parser.add_argument(
        "--profile",
        default="intermediate",
        choices=["intermediate", "modern"],
        help="TLS configuration profile ('intermediate' or 'modern', default: 'intermediate')",
    )
    gen_parser.add_argument("--domain", default="example.com", help="Domain name (default: 'example.com')")
    gen_parser.add_argument("--cert", default="/etc/ssl/certs/cert.pem", help="Certificate path")
    gen_parser.add_argument("--key", default="/etc/ssl/private/key.pem", help="Private key path")
    gen_parser.add_argument("--no-hsts", action="store_true", help="Disable HTTP Strict Transport Security (HSTS)")
    gen_parser.add_argument("--out", default=None, help="Save generated configuration to file")
    gen_parser.add_argument("--force", action="store_true", help="Overwrite existing output file")
    gen_parser.set_defaults(handler=handle_config_generate)
