"""Main entrypoint and argument parser for ittools CLI."""

from __future__ import annotations

import argparse
import os
import socket
import ssl
import sys
import traceback
from typing import Sequence

import requests

from ittools.cli.commands.adcs import register_adcs_commands
from ittools.cli.commands.config import register_config_commands
from ittools.cli.commands.csr import register_csr_commands
from ittools.cli.commands.keypair import register_keypair_commands
from ittools.cli.commands.mcp_cmd import register_mcp_commands
from ittools.cli.commands.pfx import register_pfx_commands
from ittools.cli.commands.ssl import register_ssl_commands
from ittools.core.adcs.exceptions import ADCSConnectionError
from ittools.core.keypair.pgp import GPGNotInstalledError


class CLIParser(argparse.ArgumentParser):
    """Custom ArgumentParser exiting with code 1 on usage error."""

    def error(self, message: str) -> None:
        sys.stderr.write(f"error: {message}\n")
        sys.exit(1)


def is_network_error(exc: BaseException) -> bool:
    """Determine whether an exception represents a network/connection failure."""
    if isinstance(exc, (FileNotFoundError, FileExistsError, PermissionError, IsADirectoryError)):
        return False

    network_types = (
        socket.gaierror,
        socket.herror,
        ConnectionError,
        TimeoutError,
        ssl.SSLError,
        requests.RequestException,
        ADCSConnectionError,
    )
    if isinstance(exc, network_types):
        return True

    if isinstance(exc, OSError):
        msg = str(exc).lower()
        if any(term in msg for term in ("connection refused", "network unreachable", "host unreachable", "timed out", "timeout", "connection reset", "connection aborted")):
            return True

    if isinstance(exc, ValueError) and "No peer certificate received" in str(exc):
        return True

    return False


def build_parser() -> CLIParser:
    """Construct the top-level argument parser and subcommands."""
    parser = CLIParser(
        prog="ittools",
        description="A standard CLI toolkit of IT, PKI, and SSL/TLS utilities.",
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Print full Python exception tracebacks on error",
    )

    subparsers = parser.add_subparsers(
        dest="command",
        title="subcommands",
        parser_class=CLIParser,
    )

    register_csr_commands(subparsers)
    register_keypair_commands(subparsers)
    register_ssl_commands(subparsers)
    register_config_commands(subparsers)
    register_pfx_commands(subparsers)
    register_adcs_commands(subparsers)
    register_mcp_commands(subparsers)

    return parser


def main(args: Sequence[str] | None = None) -> int:
    """Main CLI dispatch entrypoint.

    Args:
        args: Command line arguments (defaults to sys.argv[1:] if None).

    Returns:
        Exit code: 0 on success, 1 on validation/user error, 2 on network error,
        3 on security warning/mismatch.
    """
    if args is None:
        args = sys.argv[1:]

    debug = "--debug" in args

    parser = build_parser()

    if not args:
        parser.print_help(file=sys.stderr)
        return 1

    try:
        parsed_args = parser.parse_args(args)
        if not hasattr(parsed_args, "handler"):
            parser.print_help(file=sys.stderr)
            return 1
        return parsed_args.handler(parsed_args)
    except SystemExit as e:
        return e.code if isinstance(e.code, int) else 0
    except GPGNotInstalledError as exc:
        if debug:
            traceback.print_exc(file=sys.stderr)
        else:
            sys.stderr.write(f"Error: {exc}\n")
        return 1
    except BaseException as exc:
        if is_network_error(exc):
            exit_code = 2
        else:
            exit_code = 1

        if debug:
            traceback.print_exc(file=sys.stderr)
        else:
            sys.stderr.write(f"Error: {exc}\n")

        return exit_code


if __name__ == "__main__":
    sys.exit(main())
