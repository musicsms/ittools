"""CLI commands for Microsoft ADCS Web Enrollment."""

from __future__ import annotations

import argparse
import getpass
import os
from pathlib import Path
import sys

from ittools.core.adcs.client import ADCSClient
from ittools.core.adcs.exceptions import (
    ADCSAuthError,
    ADCSConnectionError,
    ADCSError,
    ADCSPendingError,
    ADCSRequestDeniedError,
)
from ittools.core.pki.pfx import create_pfx_bundle


def _get_password(password: str | None, prompt: str) -> str | None:
    """Prompt for password if omitted and running interactively."""
    if password is not None:
        return password
    if sys.stdin.isatty():
        try:
            pwd = getpass.getpass(prompt)
            return pwd if pwd else None
        except (EOFError, KeyboardInterrupt):
            return None
    return None


def _write_pfx_file(path: Path, content: bytes, force: bool = False) -> None:
    """Write PFX bundle to disk with restrictive 0600 permissions."""
    path.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | (os.O_TRUNC if force else os.O_EXCL)
    fd = os.open(str(path), flags, 0o600)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(content)
    finally:
        os.chmod(str(path), 0o600)


def _write_cert_file(path: Path, content: str) -> None:
    """Write certificate or CA bundle text to disk."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def register_adcs_commands(subparsers: argparse._SubParsersAction) -> None:
    """Register 'adcs' command group and subcommands."""
    parser = subparsers.add_parser(
        "adcs",
        help="Interact with Microsoft AD Certificate Services (ADCS)",
        description="Interact with Microsoft Active Directory Certificate Services (ADCS) Web Enrollment",
    )
    adcs_sub = parser.add_subparsers(dest="subcommand")

    # adcs sign
    sign_p = adcs_sub.add_parser(
        "sign",
        help="Submit CSR to ADCS and retrieve certificate",
        description="Submit a PKCS#10 CSR to Microsoft ADCS Web Enrollment and download issued certificate",
    )
    sign_p.add_argument("--server", required=True, help="ADCS server FQDN or IP")
    sign_p.add_argument("--csr", required=True, help="Path to CSR PEM file (or - for stdin)")
    sign_p.add_argument("--template", default="WebServer", help="Certificate template (default: WebServer)")
    sign_p.add_argument("--username", help="AD username (e.g. DOMAIN\\user)")
    sign_p.add_argument("--password", help="AD user password")
    sign_p.add_argument(
        "--auth",
        choices=["ntlm", "basic"],
        default="ntlm",
        help="Authentication method (default: ntlm)",
    )
    sign_p.add_argument("--ca-bundle", help="Custom CA PEM file to verify ADCS HTTPS certificate")
    sign_p.add_argument("--insecure", action="store_true", help="Disable SSL verification for ADCS")
    sign_p.add_argument("--timeout", type=float, default=30.0, help="Timeout in seconds (default: 30)")
    sign_p.add_argument("--out", help="Output path for issued certificate (.cer)")
    sign_p.add_argument("--key", help="Matching private key file to assemble PFX")
    sign_p.add_argument("--out-pfx", help="Output path for assembled PFX file")
    sign_p.add_argument("--pfx-password", help="Password for assembled PFX file")
    sign_p.add_argument("--name", help="Friendly name / alias for certificate in PFX")
    sign_p.add_argument("--force", action="store_true", help="Overwrite existing output files")
    sign_p.set_defaults(handler=handle_adcs_sign, func=handle_adcs_sign)

    # adcs retrieve
    ret_p = adcs_sub.add_parser(
        "retrieve",
        help="Retrieve approved certificate by Request ID",
        description="Retrieve an approved certificate from Microsoft ADCS by Request ID",
    )
    ret_p.add_argument("--server", required=True, help="ADCS server FQDN or IP")
    ret_p.add_argument("--req-id", required=True, help="ADCS Request ID")
    ret_p.add_argument("--username", help="AD username (e.g. DOMAIN\\user)")
    ret_p.add_argument("--password", help="AD user password")
    ret_p.add_argument(
        "--auth",
        choices=["ntlm", "basic"],
        default="ntlm",
        help="Authentication method (default: ntlm)",
    )
    ret_p.add_argument("--ca-bundle", help="Custom CA PEM file to verify ADCS HTTPS certificate")
    ret_p.add_argument("--insecure", action="store_true", help="Disable SSL verification for ADCS")
    ret_p.add_argument("--timeout", type=float, default=30.0, help="Timeout in seconds (default: 30)")
    ret_p.add_argument("--out", help="Output path for certificate (.cer)")
    ret_p.add_argument("--key", help="Matching private key file to assemble PFX")
    ret_p.add_argument("--out-pfx", help="Output path for assembled PFX file")
    ret_p.add_argument("--pfx-password", help="Password for assembled PFX file")
    ret_p.add_argument("--name", help="Friendly name / alias for certificate in PFX")
    ret_p.add_argument("--force", action="store_true", help="Overwrite existing output files")
    ret_p.set_defaults(handler=handle_adcs_retrieve, func=handle_adcs_retrieve)

    # adcs ca-cert
    ca_p = adcs_sub.add_parser(
        "ca-cert",
        help="Download CA certificate/chain from ADCS",
        description="Download CA certificate or chain (.p7b) from Microsoft ADCS Web Enrollment",
    )
    ca_p.add_argument("--server", required=True, help="ADCS server FQDN or IP")
    ca_p.add_argument("--username", help="AD username (e.g. DOMAIN\\user)")
    ca_p.add_argument("--password", help="AD user password")
    ca_p.add_argument(
        "--auth",
        choices=["ntlm", "basic"],
        default="ntlm",
        help="Authentication method (default: ntlm)",
    )
    ca_p.add_argument("--ca-bundle", help="Custom CA PEM file to verify ADCS HTTPS certificate")
    ca_p.add_argument("--insecure", action="store_true", help="Disable SSL verification for ADCS")
    ca_p.add_argument("--timeout", type=float, default=30.0, help="Timeout in seconds (default: 30)")
    ca_p.add_argument("--out", help="Output path for CA cert/bundle (.p7b)")
    ca_p.add_argument("--force", action="store_true", help="Overwrite existing output file")
    ca_p.set_defaults(handler=handle_adcs_ca_cert, func=handle_adcs_ca_cert)


def handle_adcs_sign(args: argparse.Namespace) -> int:
    """Handle 'ittools adcs sign'."""
    # 1. Validate CSR input upfront
    if args.csr == "-":
        csr_pem = sys.stdin.read()
    else:
        csr_path = Path(args.csr)
        if not csr_path.exists():
            sys.stderr.write(f"error: CSR file not found: {args.csr}\n")
            return 1
        csr_pem = csr_path.read_text(encoding="utf-8")

    # 2. Validate private key input upfront if specified
    key_pem: str | None = None
    if args.key:
        key_path = Path(args.key)
        if not key_path.exists():
            sys.stderr.write(f"error: Private key file not found: {args.key}\n")
            return 1
        key_pem = key_path.read_text(encoding="utf-8")

    # 3. Check --out-pfx requires --key
    if args.out_pfx and not args.key:
        sys.stderr.write("error: --key is required when --out-pfx is specified\n")
        return 1

    # 4. Check CA bundle upfront if specified
    ca_content: str | None = None
    if args.ca_bundle:
        ca_p = Path(args.ca_bundle)
        if not ca_p.exists():
            sys.stderr.write(f"error: CA bundle file not found: {args.ca_bundle}\n")
            return 1
        ca_content = ca_p.read_text(encoding="utf-8")

    # 5. Determine output target files
    out_cert_path = Path(args.out) if args.out else Path("./output/issued.cer")
    out_pfx_path = Path(args.out_pfx) if args.out_pfx else (out_cert_path.with_suffix(".pfx") if args.key else None)

    # 6. Upfront destination overwrite check
    targets: list[Path] = [out_cert_path]
    if out_pfx_path:
        targets.append(out_pfx_path)

    for target in targets:
        if target.exists() and not args.force:
            sys.stderr.write(f"error: Destination file '{target}' already exists. Use --force to overwrite.\n")
            return 1

    password = _get_password(args.password, f"Enter password for {args.username}: ") if args.username else args.password

    client = ADCSClient(
        server=args.server,
        username=args.username,
        password=password,
        auth_method=args.auth,
        ca_file=args.ca_bundle,
        insecure=args.insecure,
        timeout=args.timeout,
    )

    try:
        result = client.submit_csr(csr_pem, template=args.template)
    except ADCSPendingError as exc:
        sys.stderr.write("\n[PENDING] Your certificate request is pending administrator approval.\n")
        sys.stderr.write(f"Request ID: {exc.req_id}\n")
        sys.stderr.write("To retrieve once approved, run:\n")
        sys.stderr.write(f"  ittools adcs retrieve --server {args.server} --req-id {exc.req_id}\n")
        return 3
    except ADCSConnectionError as exc:
        sys.stderr.write(f"error: {exc}\n")
        return 2
    except (ADCSRequestDeniedError, ADCSAuthError, ADCSError) as exc:
        sys.stderr.write(f"error: {exc}\n")
        return 1
    except Exception as exc:
        sys.stderr.write(f"error: {exc}\n")
        return 1

    _write_cert_file(out_cert_path, result.cert_pem)
    sys.stdout.write(f"Certificate successfully issued! (Request ID: {result.req_id})\n")
    sys.stdout.write(f"Saved certificate to: {out_cert_path}\n")

    if key_pem and out_pfx_path:
        pfx_password = args.pfx_password
        if pfx_password is None and sys.stdin.isatty():
            try:
                pwd = getpass.getpass("Enter password for PFX (leave empty for none): ")
                pfx_password = pwd if pwd else None
            except (EOFError, KeyboardInterrupt):
                pfx_password = None

        try:
            pfx_bytes = create_pfx_bundle(
                private_key_pem=key_pem,
                cert_pem=result.cert_pem,
                ca_certs_pem=ca_content,
                password=pfx_password,
                friendly_name=args.name,
            )
            _write_pfx_file(out_pfx_path, pfx_bytes, force=args.force)
            sys.stdout.write(f"Assembled and saved PFX to: {out_pfx_path}\n")
        except Exception as exc:
            sys.stderr.write(f"error: Failed to assemble PFX: {exc}\n")
            return 1

    return 0


def handle_adcs_retrieve(args: argparse.Namespace) -> int:
    """Handle 'ittools adcs retrieve'."""
    # 1. Validate private key input upfront if specified
    key_pem: str | None = None
    if args.key:
        key_path = Path(args.key)
        if not key_path.exists():
            sys.stderr.write(f"error: Private key file not found: {args.key}\n")
            return 1
        key_pem = key_path.read_text(encoding="utf-8")

    # 2. Check --out-pfx requires --key
    if args.out_pfx and not args.key:
        sys.stderr.write("error: --key is required when --out-pfx is specified\n")
        return 1

    # 3. Check CA bundle upfront if specified
    ca_content: str | None = None
    if args.ca_bundle:
        ca_p = Path(args.ca_bundle)
        if not ca_p.exists():
            sys.stderr.write(f"error: CA bundle file not found: {args.ca_bundle}\n")
            return 1
        ca_content = ca_p.read_text(encoding="utf-8")

    # 4. Determine output target files
    out_cert_path = Path(args.out) if args.out else Path(f"./output/req_{args.req_id}.cer")
    out_pfx_path = Path(args.out_pfx) if args.out_pfx else (out_cert_path.with_suffix(".pfx") if args.key else None)

    # 5. Upfront destination overwrite check
    targets: list[Path] = [out_cert_path]
    if out_pfx_path:
        targets.append(out_pfx_path)

    for target in targets:
        if target.exists() and not args.force:
            sys.stderr.write(f"error: Destination file '{target}' already exists. Use --force to overwrite.\n")
            return 1

    password = _get_password(args.password, f"Enter password for {args.username}: ") if args.username else args.password

    client = ADCSClient(
        server=args.server,
        username=args.username,
        password=password,
        auth_method=args.auth,
        ca_file=args.ca_bundle,
        insecure=args.insecure,
        timeout=args.timeout,
    )

    try:
        cert_pem = client.retrieve_cert(args.req_id)
    except ADCSPendingError as exc:
        sys.stderr.write(f"\n[PENDING] Request ID {exc.req_id} is still pending administrator approval.\n")
        return 3
    except ADCSConnectionError as exc:
        sys.stderr.write(f"error: {exc}\n")
        return 2
    except (ADCSRequestDeniedError, ADCSAuthError, ADCSError) as exc:
        sys.stderr.write(f"error: {exc}\n")
        return 1
    except Exception as exc:
        sys.stderr.write(f"error: {exc}\n")
        return 1

    _write_cert_file(out_cert_path, cert_pem)
    sys.stdout.write(f"Retrieved certificate saved to: {out_cert_path}\n")

    if key_pem and out_pfx_path:
        pfx_password = args.pfx_password
        if pfx_password is None and sys.stdin.isatty():
            try:
                pwd = getpass.getpass("Enter password for PFX (leave empty for none): ")
                pfx_password = pwd if pwd else None
            except (EOFError, KeyboardInterrupt):
                pfx_password = None

        try:
            pfx_bytes = create_pfx_bundle(
                private_key_pem=key_pem,
                cert_pem=cert_pem,
                ca_certs_pem=ca_content,
                password=pfx_password,
                friendly_name=args.name,
            )
            _write_pfx_file(out_pfx_path, pfx_bytes, force=args.force)
            sys.stdout.write(f"Assembled and saved PFX to: {out_pfx_path}\n")
        except Exception as exc:
            sys.stderr.write(f"error: Failed to assemble PFX: {exc}\n")
            return 1

    return 0


def handle_adcs_ca_cert(args: argparse.Namespace) -> int:
    """Handle 'ittools adcs ca-cert'."""
    # 1. Check CA bundle upfront if specified
    if args.ca_bundle:
        ca_p = Path(args.ca_bundle)
        if not ca_p.exists():
            sys.stderr.write(f"error: CA bundle file not found: {args.ca_bundle}\n")
            return 1

    # 2. Determine output destination
    clean_server = args.server.replace("https://", "").replace("http://", "").strip("/").replace(":", "_")
    out_path = Path(args.out) if args.out else Path(f"./output/{clean_server}_ca.p7b")

    # 3. Upfront destination overwrite check
    if out_path.exists() and not args.force:
        sys.stderr.write(f"error: Destination file '{out_path}' already exists. Use --force to overwrite.\n")
        return 1

    password = _get_password(args.password, f"Enter password for {args.username}: ") if args.username else args.password

    client = ADCSClient(
        server=args.server,
        username=args.username,
        password=password,
        auth_method=args.auth,
        ca_file=args.ca_bundle,
        insecure=args.insecure,
        timeout=args.timeout,
    )

    try:
        ca_data = client.get_ca_cert()
    except ADCSConnectionError as exc:
        sys.stderr.write(f"error: {exc}\n")
        return 2
    except (ADCSRequestDeniedError, ADCSAuthError, ADCSError) as exc:
        sys.stderr.write(f"error: {exc}\n")
        return 1
    except Exception as exc:
        sys.stderr.write(f"error: {exc}\n")
        return 1

    _write_cert_file(out_path, ca_data)
    sys.stdout.write(f"Downloaded CA bundle to: {out_path}\n")
    return 0
