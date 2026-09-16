"""Remote SSL inspection and verification commands."""

from __future__ import annotations

import argparse
import dataclasses
import json
import sys

from ittools.core.pki.matcher import match_key_and_cert
from ittools.core.ssl_check.checker import check_remote_ssl
from ittools.core.ssl_check.headers import check_security_headers


def handle_ssl_check(args: argparse.Namespace) -> int:
    """Handle 'ssl check' command."""
    report = check_remote_ssl(host=args.host, port=args.port, timeout=args.timeout)

    if args.json:
        data = dataclasses.asdict(report)
        sys.stdout.write(json.dumps(data, indent=2) + "\n")
    else:
        sans_str = ", ".join(report.sans) if report.sans else "(none)"
        lines = [
            f"Host:            {report.host}:{report.port}",
            f"Subject:         {report.subject}",
            f"Issuer:          {report.issuer}",
            f"Valid From:      {report.valid_from}",
            f"Valid To:        {report.valid_to}",
            f"Days Remaining:  {report.days_remaining}",
            f"Expired:         {report.is_expired}",
            f"Valid Chain:     {report.is_valid_chain}",
            f"TLS Version:     {report.tls_version}",
            f"Cipher Suite:    {report.cipher_suite}",
            f"SANs:            {sans_str}",
            f"Warning:         {report.warning or 'None'}",
        ]
        sys.stdout.write("\n".join(lines) + "\n")

    # Exit code 3 if expired or <30 days remaining
    if report.is_expired or report.days_remaining < 30:
        return 3
    return 0


def handle_ssl_headers(args: argparse.Namespace) -> int:
    """Handle 'ssl headers' command."""
    report = check_security_headers(url=args.url, timeout=args.timeout)

    if args.json:
        data = dataclasses.asdict(report)
        sys.stdout.write(json.dumps(data, indent=2) + "\n")
    else:
        lines = [
            f"URL:             {report.url}",
            f"Status Code:     {report.status_code}",
            f"Security Score:  {report.security_score}",
            f"Present Headers ({len(report.present_headers)}):",
        ]
        for h, v in sorted(report.present_headers.items()):
            lines.append(f"  {h}: {v}")
        lines.append(f"Missing Headers ({len(report.missing_headers)}):")
        for h in report.missing_headers:
            lines.append(f"  - {h}")
        if report.recommendations:
            lines.append("Recommendations:")
            for r in report.recommendations:
                lines.append(f"  - {r}")
        sys.stdout.write("\n".join(lines) + "\n")

    return 0


def handle_ssl_match(args: argparse.Namespace) -> int:
    """Handle 'ssl match' command."""
    with open(args.key, "r", encoding="utf-8") as f:
        key_pem = f.read()
    with open(args.cert, "r", encoding="utf-8") as f:
        cert_pem = f.read()

    result = match_key_and_cert(
        private_key_pem=key_pem,
        cert_or_csr_pem=cert_pem,
        password=args.password,
    )
    lines = [
        f"Match:      {result.matched}",
        f"Key Hash:   {result.key_hash}",
        f"Cert Hash:  {result.cert_hash}",
        f"Message:    {result.message}",
    ]
    sys.stdout.write("\n".join(lines) + "\n")

    if result.matched:
        return 0
    return 3


def register_ssl_commands(subparsers: argparse._SubParsersAction) -> None:
    """Register 'ssl' command group and subcommands."""
    ssl_parser = subparsers.add_parser(
        "ssl",
        help="Remote SSL/TLS inspection and verification utilities",
        description="Check remote certificates, HTTP security headers, and match keypairs",
    )
    ssl_subparsers = ssl_parser.add_subparsers(dest="subcommand")

    # ssl check
    check_parser = ssl_subparsers.add_parser(
        "check",
        help="Inspect remote host SSL/TLS certificate",
        description="Connect to remote host via TLS and inspect its certificate",
    )
    check_parser.add_argument("host", help="Hostname or IP address to inspect")
    check_parser.add_argument("--port", type=int, default=443, help="Port number (default: 443)")
    check_parser.add_argument("--timeout", type=float, default=10.0, help="Connection timeout in seconds (default: 10.0)")
    check_parser.add_argument("--json", action="store_true", help="Output report in JSON format")
    check_parser.set_defaults(handler=handle_ssl_check)

    # ssl headers
    headers_parser = ssl_subparsers.add_parser(
        "headers",
        help="Analyze HTTP security headers of a URL",
        description="Inspect HTTP response headers and grade security configuration",
    )
    headers_parser.add_argument("url", help="URL to inspect (e.g. https://example.com)")
    headers_parser.add_argument("--timeout", type=float, default=10.0, help="HTTP request timeout in seconds (default: 10.0)")
    headers_parser.add_argument("--json", action="store_true", help="Output report in JSON format")
    headers_parser.set_defaults(handler=handle_ssl_headers)

    # ssl match
    match_parser = ssl_subparsers.add_parser(
        "match",
        help="Verify private key matches certificate or CSR",
        description="Compare SHA-256 public key hashes to check keypair match",
    )
    match_parser.add_argument("--key", required=True, help="Path to private key PEM file")
    match_parser.add_argument("--cert", required=True, help="Path to certificate or CSR PEM file")
    match_parser.add_argument("--password", default=None, help="Password to decrypt private key if encrypted")
    match_parser.set_defaults(handler=handle_ssl_match)
