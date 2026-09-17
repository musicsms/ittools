"""PKI and PFX tools for the Model Context Protocol (MCP) server subsystem."""

from __future__ import annotations

import base64
import os
from pathlib import Path

from ittools.core.pki.csr import CSRSubject, decode_csr, generate_csr, sanitize_name
from ittools.core.pki.matcher import match_key_and_cert
from ittools.core.pki.pfx import create_pfx_bundle, extract_pfx_bundle


def _write_secure_file(path: str, content: str | bytes, force: bool = False) -> None:
    """Write sensitive file (private key, PFX archive) with restrictive 0600 permissions.

    Args:
        path: Filesystem path to write to.
        content: String or byte content to write.
        force: Whether to overwrite if the file exists.

    Raises:
        FileExistsError: If path exists and force is False.
    """
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    if not force and os.path.exists(path):
        raise FileExistsError(f"Target file already exists: {path} (use force=True to overwrite)")
    flags = os.O_WRONLY | os.O_CREAT | (os.O_TRUNC if force else os.O_EXCL)
    fd = os.open(path, flags, 0o600)
    try:
        if isinstance(content, str):
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                f.write(content)
        else:
            with os.fdopen(fd, "wb") as f:
                f.write(content)
    finally:
        os.chmod(path, 0o600)


def _write_public_file(path: str, content: str | bytes, force: bool = False) -> None:
    """Write public file (CSR, public certificate) with default permissions.

    Args:
        path: Filesystem path to write to.
        content: String or byte content to write.
        force: Whether to overwrite if the file exists.

    Raises:
        FileExistsError: If path exists and force is False.
    """
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    if not force and os.path.exists(path):
        raise FileExistsError(f"Target file already exists: {path} (use force=True to overwrite)")
    flags = os.O_WRONLY | os.O_CREAT | (os.O_TRUNC if force else os.O_EXCL)
    fd = os.open(path, flags, 0o644)
    if isinstance(content, str):
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(content)
    else:
        with os.fdopen(fd, "wb") as f:
            f.write(content)


def csr_generate(
    common_name: str,
    organization: str = "",
    organizational_unit: str = "",
    city: str = "",
    state: str = "",
    country: str = "",
    email: str = "",
    sans: list[str] | None = None,
    key_size: int = 2048,
    output_dir: str | None = None,
    force: bool = False,
) -> dict:
    """Generate an RSA private key and PKCS#10 Certificate Signing Request.

    Args:
        common_name: Common Name / FQDN (e.g. 'api.example.com').
        organization: Organization name.
        organizational_unit: Department or Organizational Unit.
        city: City or locality.
        state: State or province.
        country: 2-letter ISO country code.
        email: Contact email address.
        sans: Optional list of Subject Alternative Names (DNS names or IP addresses).
        key_size: RSA key bit length (default: 2048).
        output_dir: Optional directory path to write .key (mode 0600) and .csr files.
        force: Overwrite existing target files if True.

    Returns:
        Dictionary containing:
            - common_name: Common name used.
            - private_key_pem: PEM-encoded RSA private key.
            - csr_pem: PEM-encoded PKCS#10 CSR.
            - saved_files: List of file paths written if output_dir provided, otherwise empty.

    Raises:
        ValueError: If common_name is empty or invalid parameters provided.
        FileExistsError: If target output files exist and force is False.
    """
    cn = common_name.strip()
    if not cn:
        raise ValueError("common_name is required")

    sanitized_cn = sanitize_name(cn)
    saved_files: list[str] = []

    key_file: str | None = None
    csr_file: str | None = None

    if output_dir:
        target_dir = os.path.join(output_dir, sanitized_cn)
        key_file = os.path.join(target_dir, f"{sanitized_cn}.key")
        csr_file = os.path.join(target_dir, f"{sanitized_cn}.csr")

        # Upfront overwrite check
        if not force:
            existing = [f for f in (key_file, csr_file) if os.path.exists(f)]
            if existing:
                raise FileExistsError(
                    f"Target file already exists: {', '.join(existing)} (use force=True to overwrite)"
                )

    subject = CSRSubject(
        common_name=cn,
        organization=organization,
        organizational_unit=organizational_unit,
        city=city,
        state=state,
        country=country,
        email=email,
    )
    result = generate_csr(subject=subject, sans=sans, key_size=key_size)

    if output_dir and key_file and csr_file:
        _write_secure_file(key_file, result.private_key_pem, force=force)
        _write_public_file(csr_file, result.csr_pem, force=force)
        saved_files = [key_file, csr_file]

    return {
        "common_name": cn,
        "private_key_pem": result.private_key_pem,
        "csr_pem": result.csr_pem,
        "saved_files": saved_files,
    }


def csr_decode(csr_pem: str) -> dict:
    """Decode and inspect a PEM-encoded Certificate Signing Request.

    Args:
        csr_pem: PEM-encoded CSR content.

    Returns:
        Dictionary containing:
            - common_name: Subject Common Name.
            - organization: Subject Organization.
            - country: Subject Country code.
            - sans: List of Subject Alternative Names.
            - key_type: Cryptographic key type (e.g. 'RSA').
            - key_size: Key length in bits.
            - signature_algorithm: Signing algorithm used.

    Raises:
        ValueError: If CSR PEM cannot be parsed.
    """
    details = decode_csr(csr_pem)
    return {
        "common_name": details.common_name,
        "organization": details.organization,
        "country": details.country,
        "sans": list(details.sans),
        "key_type": details.key_type,
        "key_size": details.key_size,
        "signature_algorithm": details.signature_algorithm,
    }


def pfx_create(
    private_key_pem: str,
    cert_pem: str,
    ca_certs_pem: str | None = None,
    password: str | None = None,
    friendly_name: str | None = None,
    key_password: str | None = None,
    output_path: str | None = None,
    force: bool = False,
) -> dict:
    """Bundle a private key, leaf certificate, and optional CA chain into a PKCS#12 archive.

    Args:
        private_key_pem: Private key PEM string.
        cert_pem: Leaf certificate PEM string.
        ca_certs_pem: Optional CA certificate chain PEM string.
        password: Password to encrypt the PFX container.
        friendly_name: Optional alias name for the certificate.
        key_password: Password to decrypt private_key_pem if encrypted.
        output_path: Optional file path to persist .pfx archive with mode 0600.
        force: Overwrite existing target file if True.

    Returns:
        Dictionary containing:
            - pfx_base64: Base64-encoded PKCS#12 binary bytes.
            - size_bytes: Total size of binary archive in bytes.
            - friendly_name: Alias name of the certificate if set.
            - saved_to: Destination file path if output_path provided, otherwise None.

    Raises:
        ValueError: If inputs cannot be loaded or parsed.
        FileExistsError: If output_path exists and force is False.
    """
    if output_path:
        if not force and os.path.exists(output_path):
            raise FileExistsError(
                f"Target file already exists: {output_path} (use force=True to overwrite)"
            )

    pfx_bytes = create_pfx_bundle(
        private_key_pem=private_key_pem,
        cert_pem=cert_pem,
        ca_certs_pem=ca_certs_pem,
        password=password,
        friendly_name=friendly_name,
        key_password=key_password,
    )

    if output_path:
        _write_secure_file(output_path, pfx_bytes, force=force)

    pfx_b64 = base64.b64encode(pfx_bytes).decode("ascii")

    return {
        "pfx_base64": pfx_b64,
        "size_bytes": len(pfx_bytes),
        "friendly_name": friendly_name,
        "saved_to": output_path if output_path else None,
    }


def pfx_extract(
    pfx_data_or_path: str,
    password: str | None = None,
    output_dir: str | None = None,
    force: bool = False,
) -> dict:
    """Extract private key, leaf certificate, and CA certificates from a PKCS#12 archive.

    Args:
        pfx_data_or_path: Base64-encoded PFX bytes or filesystem path to .pfx file.
        password: Archive decryption password.
        output_dir: Optional directory to persist extracted PEM files (private key written with mode 0600).
        force: Overwrite existing target files if True.

    Returns:
        Dictionary containing:
            - private_key_pem: PEM-encoded private key string if present.
            - cert_pem: PEM-encoded certificate string if present.
            - ca_certs_pem: List of PEM-encoded CA certificate strings.
            - friendly_name: Alias name of the certificate if present.
            - saved_files: List of file paths written if output_dir provided, otherwise empty.

    Raises:
        ValueError: If data cannot be parsed or decrypted.
        FileExistsError: If target output files exist and force is False.
    """
    stem = "extracted"
    if os.path.isfile(pfx_data_or_path):
        pfx_bytes = Path(pfx_data_or_path).read_bytes()
        stem = Path(pfx_data_or_path).stem
    else:
        try:
            pfx_bytes = base64.b64decode(pfx_data_or_path, validate=True)
        except Exception:
            preview = pfx_data_or_path[:50] + ("..." if len(pfx_data_or_path) > 50 else "")
            raise ValueError(f"File not found or invalid base64 PFX data: {preview}")

    result = extract_pfx_bundle(pfx_bytes, password=password)

    saved_files: list[str] = []
    if output_dir:
        if result.friendly_name and not os.path.isfile(pfx_data_or_path):
            stem = sanitize_name(result.friendly_name)

        key_path = os.path.join(output_dir, f"{stem}.key") if result.private_key_pem else None
        cert_path = os.path.join(output_dir, f"{stem}.crt") if result.cert_pem else None
        ca_path = os.path.join(output_dir, f"{stem}-ca.crt") if result.ca_certs_pem else None

        planned_files = [f for f in (key_path, cert_path, ca_path) if f is not None]

        # Upfront overwrite check
        if not force:
            existing = [f for f in planned_files if os.path.exists(f)]
            if existing:
                raise FileExistsError(
                    f"Target file already exists: {', '.join(existing)} (use force=True to overwrite)"
                )

        if key_path and result.private_key_pem:
            _write_secure_file(key_path, result.private_key_pem, force=force)
            saved_files.append(key_path)

        if cert_path and result.cert_pem:
            _write_public_file(cert_path, result.cert_pem, force=force)
            saved_files.append(cert_path)

        if ca_path and result.ca_certs_pem:
            ca_bundle = "".join(c if c.endswith("\n") else c + "\n" for c in result.ca_certs_pem)
            _write_public_file(ca_path, ca_bundle, force=force)
            saved_files.append(ca_path)

    return {
        "private_key_pem": result.private_key_pem,
        "cert_pem": result.cert_pem,
        "ca_certs_pem": result.ca_certs_pem,
        "friendly_name": result.friendly_name,
        "saved_files": saved_files,
    }


def ssl_match(
    private_key_pem: str,
    cert_or_csr_pem: str,
    password: str | None = None,
) -> dict:
    """Compare SHA-256 public key digests to verify whether a private key matches a certificate or CSR.

    Args:
        private_key_pem: PEM private key string.
        cert_or_csr_pem: PEM certificate or CSR string.
        password: Optional decryption password for encrypted private key.

    Returns:
        Dictionary containing:
            - matched: True if public key SHA-256 hashes match, False otherwise.
            - key_hash: SHA-256 hex digest of private key's public key info.
            - cert_hash: SHA-256 hex digest of cert/CSR's public key info.
            - message: Human-readable explanation of match result.

    Raises:
        ValueError: If private key or certificate/CSR PEM cannot be parsed.
    """
    res = match_key_and_cert(
        private_key_pem=private_key_pem,
        cert_or_csr_pem=cert_or_csr_pem,
        password=password,
    )
    return {
        "matched": res.matched,
        "key_hash": res.key_hash,
        "cert_hash": res.cert_hash,
        "message": res.message,
    }
