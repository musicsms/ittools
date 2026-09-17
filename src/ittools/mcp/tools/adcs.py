"""Microsoft Active Directory Certificate Services (ADCS) tools for MCP subsystem."""

from __future__ import annotations

import base64
import os
import re

from ittools.core.adcs.client import ADCSClient
from ittools.core.adcs.exceptions import (
    ADCSAuthError,
    ADCSConnectionError,
    ADCSError,
    ADCSPendingError,
    ADCSRequestDeniedError,
)
from ittools.core.pki.pfx import create_pfx_bundle
from ittools.mcp.tools.pki import _write_public_file, _write_secure_file


def adcs_sign(
    server: str,
    csr_pem: str,
    template: str = "WebServer",
    username: str | None = None,
    password: str | None = None,
    auth_method: str = "ntlm",
    ca_file: str | None = None,
    insecure: bool = False,
    timeout: float = 30.0,
    private_key_pem: str | None = None,
    pfx_password: str | None = None,
    output_cert_path: str | None = None,
    output_pfx_path: str | None = None,
    force: bool = False,
) -> dict:
    """Submit a CSR to Microsoft ADCS Web Enrollment and retrieve the issued certificate.

    Optionally packages a PKCS#12 (PFX) bundle if a private key is provided.

    Args:
        server: ADCS server hostname or IP address.
        csr_pem: PEM-encoded Certificate Signing Request (CSR).
        template: Certificate template name on CA (default: "WebServer").
        username: Domain username for authentication (e.g. 'CORP\\user').
        password: User password for authentication.
        auth_method: Authentication scheme, 'ntlm' or 'basic' (default: "ntlm").
        ca_file: Path to custom CA certificate for TLS verification.
        insecure: If True, disable SSL verification.
        timeout: HTTP request timeout in seconds (default: 30.0).
        private_key_pem: Optional matching private key PEM to assemble PFX.
        pfx_password: Optional password to protect the assembled PFX.
        output_cert_path: Optional destination path to persist leaf certificate (mode 0644).
        output_pfx_path: Optional destination path to persist PFX archive (mode 0600).
        force: If True, overwrite existing files.

    Returns:
        Structured dictionary with status and certificate/archive payloads:
            - If issued: {"status": "issued", "req_id": str, "cert_pem": str, "pfx_base64": str | None, "saved_files": list[str]}
            - If pending: {"status": "pending", "req_id": str, "message": str}
            - If error: {"status": "error", "error": str}

    Raises:
        FileExistsError: If target file exists and force is False.
        ValueError: If output_pfx_path is specified without private_key_pem.
    """
    # 1. Upfront collision check
    planned_files: list[str] = []
    if output_cert_path:
        planned_files.append(output_cert_path)
    if output_pfx_path:
        planned_files.append(output_pfx_path)

    if not force:
        existing = [f for f in planned_files if os.path.exists(f)]
        if existing:
            raise FileExistsError(
                f"Target file already exists: {', '.join(existing)} (use force=True to overwrite)"
            )

    if output_pfx_path and not private_key_pem:
        raise ValueError("private_key_pem is required when output_pfx_path is specified")

    # 2. Instantiate client and submit CSR
    client = ADCSClient(
        server=server,
        username=username,
        password=password,
        auth_method=auth_method,
        ca_file=ca_file,
        insecure=insecure,
        timeout=timeout,
    )

    try:
        result = client.submit_csr(csr_pem=csr_pem, template=template)
    except ADCSPendingError as exc:
        return {
            "status": "pending",
            "req_id": str(exc.req_id),
            "message": (
                f"Certificate request is pending CA administrator approval. "
                f"Use 'adcs_retrieve' with req_id '{exc.req_id}' once approved."
            ),
        }
    except (ADCSConnectionError, ADCSAuthError, ADCSRequestDeniedError, ADCSError) as exc:
        return {
            "status": "error",
            "error": str(exc),
        }

    # 3. Optional PFX bundle creation and file persistence
    pfx_b64: str | None = None
    saved_files: list[str] = []

    if private_key_pem:
        pfx_bytes = create_pfx_bundle(
            private_key_pem=private_key_pem,
            cert_pem=result.cert_pem,
            password=pfx_password,
        )
        pfx_b64 = base64.b64encode(pfx_bytes).decode("ascii")
        if output_pfx_path:
            _write_secure_file(output_pfx_path, pfx_bytes, force=force)
            saved_files.append(output_pfx_path)

    if output_cert_path:
        _write_public_file(output_cert_path, result.cert_pem, force=force)
        saved_files.append(output_cert_path)

    return {
        "status": "issued",
        "req_id": result.req_id,
        "cert_pem": result.cert_pem,
        "pfx_base64": pfx_b64,
        "saved_files": saved_files,
    }


def adcs_retrieve(
    server: str,
    req_id: str,
    username: str | None = None,
    password: str | None = None,
    auth_method: str = "ntlm",
    ca_file: str | None = None,
    insecure: bool = False,
    timeout: float = 30.0,
    private_key_pem: str | None = None,
    pfx_password: str | None = None,
    output_cert_path: str | None = None,
    output_pfx_path: str | None = None,
    force: bool = False,
) -> dict:
    """Download an approved certificate from ADCS by Request ID, with optional PFX assembly.

    Args:
        server: ADCS server hostname or IP address.
        req_id: ADCS certificate request ID.
        username: Domain username for authentication.
        password: User password for authentication.
        auth_method: Authentication scheme, 'ntlm' or 'basic' (default: "ntlm").
        ca_file: Path to custom CA certificate for TLS verification.
        insecure: If True, disable SSL verification.
        timeout: HTTP request timeout in seconds (default: 30.0).
        private_key_pem: Optional matching private key PEM to assemble PFX.
        pfx_password: Optional password to protect the assembled PFX.
        output_cert_path: Optional destination path to persist leaf certificate (mode 0644).
        output_pfx_path: Optional destination path to persist PFX archive (mode 0600).
        force: If True, overwrite existing files.

    Returns:
        Structured dictionary with status and certificate/archive payloads:
            - If retrieved: {"status": "retrieved", "req_id": str, "cert_pem": str, "pfx_base64": str | None, "saved_files": list[str]}
            - If pending: {"status": "pending", "req_id": str, "message": str}
            - If error: {"status": "error", "error": str}

    Raises:
        FileExistsError: If target file exists and force is False.
        ValueError: If output_pfx_path is specified without private_key_pem.
    """
    # 1. Upfront collision check
    planned_files: list[str] = []
    if output_cert_path:
        planned_files.append(output_cert_path)
    if output_pfx_path:
        planned_files.append(output_pfx_path)

    if not force:
        existing = [f for f in planned_files if os.path.exists(f)]
        if existing:
            raise FileExistsError(
                f"Target file already exists: {', '.join(existing)} (use force=True to overwrite)"
            )

    if output_pfx_path and not private_key_pem:
        raise ValueError("private_key_pem is required when output_pfx_path is specified")

    # 2. Instantiate client and retrieve cert
    client = ADCSClient(
        server=server,
        username=username,
        password=password,
        auth_method=auth_method,
        ca_file=ca_file,
        insecure=insecure,
        timeout=timeout,
    )

    try:
        cert_pem = client.retrieve_cert(req_id=req_id)
        if "Certificate Pending" in cert_pem:
            return {
                "status": "pending",
                "req_id": str(req_id),
                "message": (
                    f"Certificate request is pending CA administrator approval. "
                    f"Use 'adcs_retrieve' with req_id '{req_id}' once approved."
                ),
            }
    except ADCSPendingError as exc:
        return {
            "status": "pending",
            "req_id": str(exc.req_id),
            "message": (
                f"Certificate request is pending CA administrator approval. "
                f"Use 'adcs_retrieve' with req_id '{exc.req_id}' once approved."
            ),
        }
    except (ADCSConnectionError, ADCSAuthError, ADCSRequestDeniedError, ADCSError) as exc:
        return {
            "status": "error",
            "error": str(exc),
        }

    # 3. Optional PFX bundle creation and file persistence
    pfx_b64: str | None = None
    saved_files: list[str] = []

    if private_key_pem:
        pfx_bytes = create_pfx_bundle(
            private_key_pem=private_key_pem,
            cert_pem=cert_pem,
            password=pfx_password,
        )
        pfx_b64 = base64.b64encode(pfx_bytes).decode("ascii")
        if output_pfx_path:
            _write_secure_file(output_pfx_path, pfx_bytes, force=force)
            saved_files.append(output_pfx_path)

    if output_cert_path:
        _write_public_file(output_cert_path, cert_pem, force=force)
        saved_files.append(output_cert_path)

    return {
        "status": "retrieved",
        "req_id": str(req_id),
        "cert_pem": cert_pem,
        "pfx_base64": pfx_b64,
        "saved_files": saved_files,
    }


def adcs_ca_cert(
    server: str,
    username: str | None = None,
    password: str | None = None,
    auth_method: str = "ntlm",
    ca_file: str | None = None,
    insecure: bool = False,
    timeout: float = 30.0,
    output_path: str | None = None,
    force: bool = False,
) -> dict:
    """Download the Enterprise CA certificate chain (.p7b) from Microsoft ADCS.

    Args:
        server: ADCS server hostname or IP address.
        username: Domain username for authentication.
        password: User password for authentication.
        auth_method: Authentication scheme, 'ntlm' or 'basic' (default: "ntlm").
        ca_file: Path to custom CA certificate for TLS verification.
        insecure: If True, disable SSL verification.
        timeout: HTTP request timeout in seconds (default: 30.0).
        output_path: Optional destination path to persist CA bundle (mode 0644).
        force: If True, overwrite existing files.

    Returns:
        Structured dictionary with status and CA bundle payload:
            - {"status": "success", "ca_data": str, "ca_cert_p7b_base64": str, "saved_to": str | None, "saved_files": list[str]}
            - If error: {"status": "error", "error": str}

    Raises:
        FileExistsError: If output_path exists and force is False.
    """
    # 1. Upfront collision check
    if output_path and not force and os.path.exists(output_path):
        raise FileExistsError(
            f"Target file already exists: {output_path} (use force=True to overwrite)"
        )

    # 2. Instantiate client and fetch CA cert
    client = ADCSClient(
        server=server,
        username=username,
        password=password,
        auth_method=auth_method,
        ca_file=ca_file,
        insecure=insecure,
        timeout=timeout,
    )

    try:
        ca_data = client.get_ca_cert()
    except (ADCSConnectionError, ADCSAuthError, ADCSRequestDeniedError, ADCSError) as exc:
        return {
            "status": "error",
            "error": str(exc),
        }

    # 3. Derive base64 payload
    if isinstance(ca_data, bytes):
        ca_text = ca_data.decode("utf-8", errors="replace")
        ca_b64 = base64.b64encode(ca_data).decode("ascii")
    else:
        ca_text = ca_data
        clean_text = re.sub(r"-----BEGIN [^-]+-----|-----END [^-]+-----", "", ca_text).strip()
        clean_text_no_ws = "".join(clean_text.split())
        try:
            base64.b64decode(clean_text_no_ws, validate=True)
            ca_b64 = clean_text_no_ws
        except Exception:
            ca_b64 = base64.b64encode(ca_text.encode("utf-8")).decode("ascii")

    # 4. File persistence
    saved_to: str | None = None
    saved_files: list[str] = []

    if output_path:
        _write_public_file(output_path, ca_data, force=force)
        saved_to = output_path
        saved_files.append(output_path)

    return {
        "status": "success",
        "ca_data": ca_text,
        "ca_cert_p7b_base64": ca_b64,
        "saved_to": saved_to,
        "saved_files": saved_files,
    }
