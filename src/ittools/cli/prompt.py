"""Interactive prompt for CSR field collection."""

from __future__ import annotations

import io
import sys

from ittools.core.pki.csr import CSRSubject


def _ask(label: str, in_stream: io.TextIOBase, prompt_stream: io.TextIOBase) -> str:
    """Print prompt to prompt_stream and read line from in_stream."""
    prompt_stream.write(f"{label}: ")
    prompt_stream.flush()
    line = in_stream.readline()
    if line == "":
        raise EOFError("Unexpected EOF while reading input")
    return line.strip()


def prompt_subject(
    stdin: io.TextIOBase | None = None,
    prompt_stream: io.TextIOBase | None = None,
) -> tuple[CSRSubject, list[str], int]:
    """Interactively prompt user for CSR fields.

    Prompts for Common Name, Organization, Organizational Unit, City,
    State, Country, Email, SANs, and Key size. Re-prompts on invalid inputs.

    Args:
        stdin: Input stream (defaults to sys.stdin).
        prompt_stream: Output stream for prompts (defaults to sys.stderr).

    Returns:
        Tuple of (CSRSubject, list of SANs, key_size).

    Raises:
        EOFError: If EOF is reached while reading input.
    """
    in_stream = stdin if stdin is not None else sys.stdin
    out_stream = prompt_stream if prompt_stream is not None else sys.stderr

    # 1. Common Name (required, reprompt on blank)
    common_name = ""
    while not common_name:
        cn = _ask("Common Name", in_stream, out_stream)
        if not cn:
            out_stream.write("Common Name is required.\n")
            out_stream.flush()
            continue
        common_name = cn

    # 2. Organization (optional)
    org = _ask("Organization", in_stream, out_stream)

    # 3. Organizational Unit (optional)
    ou = _ask("Organizational Unit", in_stream, out_stream)

    # 4. City (optional)
    city = _ask("City", in_stream, out_stream)

    # 5. State (optional)
    state = _ask("State", in_stream, out_stream)

    # 6. Country (optional, but must be 2-letter alpha if provided)
    country = ""
    while True:
        c = _ask("Country (2-letter code)", in_stream, out_stream)
        if not c:
            country = ""
            break
        c_clean = c.strip().upper()
        if len(c_clean) != 2 or not c_clean.isalpha():
            out_stream.write("Country must be a 2-letter ISO code.\n")
            out_stream.flush()
            continue
        country = c_clean
        break

    # 7. Email (optional)
    email = _ask("Email", in_stream, out_stream)

    # 8. Subject Alternative Names (optional)
    san_raw = _ask("Subject Alternative Names (comma-separated, optional)", in_stream, out_stream)
    sans = [s.strip() for s in san_raw.split(",") if s.strip()]

    # 9. Key size (defaults to 2048)
    key_size = 2048
    while True:
        ks_raw = _ask("Key size (2048, 3072, 4096) [2048]", in_stream, out_stream)
        if not ks_raw:
            key_size = 2048
            break
        try:
            val = int(ks_raw)
            if val < 512:
                out_stream.write("Key size must be at least 512.\n")
                out_stream.flush()
                continue
            key_size = val
            break
        except ValueError:
            out_stream.write("Key size must be a valid number.\n")
            out_stream.flush()
            continue

    subject = CSRSubject(
        common_name=common_name,
        organization=org,
        organizational_unit=ou,
        city=city,
        state=state,
        country=country,
        email=email,
    )
    return subject, sans, key_size
