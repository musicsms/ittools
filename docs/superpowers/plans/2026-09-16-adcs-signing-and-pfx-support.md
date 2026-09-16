# ADCS Certificate Signing & PKCS#12 (PFX) Management Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement PKCS#12 (PFX) container creation/extraction and a cross-platform Microsoft Active Directory Certificate Services (AD CS) signing client with unified CLI subcommands.

**Architecture:** Layered clean architecture extending `ittools`: core cryptographic bundling in `src/ittools/core/pki/pfx.py` using `cryptography`, core ADCS Web Enrollment HTTP client in `src/ittools/core/adcs/client.py` using `requests`, and CLI command dispatchers in `src/ittools/cli/commands/pfx.py` and `src/ittools/cli/commands/adcs.py`.

**Tech Stack:** Python >= 3.10, `cryptography` (X.509 and PKCS#12), `requests`, `argparse`, `pytest`.

**Spec:** `docs/superpowers/specs/2026-09-16-adcs-signing-and-pfx-support.md`

## Global Constraints
- Requires Python >= 3.10.
- All private key files written to disk (via extraction or generation) must be saved with restrictive permissions `0600`.
- Overwriting existing files requires the explicit `--force` flag; all planned target destinations must be checked upfront before generating or writing any files.
- Exit codes: `0` for success, `1` for validation/user error, `2` for network/connection failure, `3` for pending approval (ADCS request requires CA admin approval).
- Passwords must not be exposed in shell command lines when omitted; interactive prompts must use `getpass.getpass()`.

---

### Task 1: Core PKCS#12 (PFX) Bundle & Extraction Service

**Files:**
- Create: `src/ittools/core/pki/pfx.py`
- Modify: `src/ittools/core/pki/__init__.py`
- Test: `tests/test_pki_pfx.py`

**Interfaces:**
- Consumes: `cryptography.hazmat.primitives.serialization.pkcs12`, `cryptography.x509`, `cryptography.hazmat.primitives.serialization`
- Produces:
  - `PFXExtractResult(private_key_pem: str | None, cert_pem: str | None, ca_certs_pem: list[str], friendly_name: str | None)`
  - `create_pfx_bundle(private_key_pem: str, cert_pem: str, ca_certs_pem: list[str] | str | None = None, password: str | None = None, friendly_name: str | None = None, key_password: str | None = None) -> bytes`
  - `extract_pfx_bundle(pfx_bytes: bytes, password: str | None = None) -> PFXExtractResult`

- [ ] **Step 1: Write failing tests for PFX creation and extraction**

Create `tests/test_pki_pfx.py`:
```python
"""Tests for PKCS#12 / PFX creation and extraction service."""

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from datetime import datetime, timezone, timedelta

from ittools.core.pki.pfx import create_pfx_bundle, extract_pfx_bundle, PFXExtractResult


def _generate_test_key_and_cert(cn: str = "example.com", is_ca: bool = False):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, cn)])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc) - timedelta(days=1))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=365))
        .sign(key, hashes.SHA256())
    )
    key_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")
    cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode("utf-8")
    return key_pem, cert_pem


def test_create_and_extract_pfx_with_password():
    key_pem, cert_pem = _generate_test_key_and_cert("server.local")
    pfx_bytes = create_pfx_bundle(
        private_key_pem=key_pem,
        cert_pem=cert_pem,
        password="secretpassword",
        friendly_name="TestServer",
    )
    assert isinstance(pfx_bytes, bytes)
    assert len(pfx_bytes) > 0

    result = extract_pfx_bundle(pfx_bytes, password="secretpassword")
    assert isinstance(result, PFXExtractResult)
    assert result.private_key_pem is not None
    assert "BEGIN PRIVATE KEY" in result.private_key_pem
    assert result.cert_pem is not None
    assert "BEGIN CERTIFICATE" in result.cert_pem
    assert result.friendly_name == "TestServer"


def test_create_and_extract_pfx_without_password():
    key_pem, cert_pem = _generate_test_key_and_cert("nopass.local")
    pfx_bytes = create_pfx_bundle(
        private_key_pem=key_pem,
        cert_pem=cert_pem,
        password=None,
    )
    result = extract_pfx_bundle(pfx_bytes, password=None)
    assert result.private_key_pem is not None
    assert result.cert_pem is not None


def test_create_pfx_with_ca_chain():
    key_pem, cert_pem = _generate_test_key_and_cert("leaf.local")
    _, ca1_pem = _generate_test_key_and_cert("Intermediate CA", is_ca=True)
    _, ca2_pem = _generate_test_key_and_cert("Root CA", is_ca=True)

    pfx_bytes = create_pfx_bundle(
        private_key_pem=key_pem,
        cert_pem=cert_pem,
        ca_certs_pem=[ca1_pem, ca2_pem],
        password="chainpwd",
    )
    result = extract_pfx_bundle(pfx_bytes, password="chainpwd")
    assert len(result.ca_certs_pem) == 2


def test_extract_pfx_invalid_password():
    key_pem, cert_pem = _generate_test_key_and_cert("pwd.local")
    pfx_bytes = create_pfx_bundle(key_pem, cert_pem, password="correct")
    with pytest.raises(ValueError, match="Failed to decrypt or parse PKCS#12"):
        extract_pfx_bundle(pfx_bytes, password="wrong")
```

- [ ] **Step 2: Run test to verify failure**

Run: `pytest tests/test_pki_pfx.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'ittools.core.pki.pfx'`

- [ ] **Step 3: Implement `src/ittools/core/pki/pfx.py`**

Create `src/ittools/core/pki/pfx.py`:
```python
"""PKCS#12 (PFX) container serialization and extraction service."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Sequence

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import pkcs12


@dataclass(frozen=True)
class PFXExtractResult:
    """Result of extracting a PKCS#12 bundle."""

    private_key_pem: str | None
    cert_pem: str | None
    ca_certs_pem: list[str]
    friendly_name: str | None


def create_pfx_bundle(
    private_key_pem: str,
    cert_pem: str,
    ca_certs_pem: list[str] | str | None = None,
    password: str | None = None,
    friendly_name: str | None = None,
    key_password: str | None = None,
) -> bytes:
    """Serialize a private key, certificate, and optional CA certificates into PKCS#12 bytes.

    Args:
        private_key_pem: PEM-encoded private key.
        cert_pem: PEM-encoded end-entity certificate.
        ca_certs_pem: Optional list of PEM CA certificates or multi-cert PEM bundle string.
        password: Password for the PFX container.
        friendly_name: Optional alias name for the certificate.
        key_password: Password to decrypt private_key_pem if encrypted.

    Returns:
        Binary bytes of the PKCS#12 container.
    """
    key_pass_bytes = key_password.encode("utf-8") if key_password else None
    try:
        private_key = serialization.load_pem_private_key(
            private_key_pem.encode("utf-8"),
            password=key_pass_bytes,
        )
    except Exception as exc:
        raise ValueError(f"Failed to load private key: {exc}") from exc

    try:
        leaf_cert = x509.load_pem_x509_certificate(cert_pem.encode("utf-8"))
    except Exception as exc:
        raise ValueError(f"Failed to load certificate: {exc}") from exc

    cas: list[x509.Certificate] = []
    if ca_certs_pem:
        if isinstance(ca_certs_pem, str):
            try:
                cas = list(x509.load_pem_x509_certificates(ca_certs_pem.encode("utf-8")))
            except Exception as exc:
                raise ValueError(f"Failed to load CA certificate bundle: {exc}") from exc
        else:
            for item in ca_certs_pem:
                try:
                    cas.extend(x509.load_pem_x509_certificates(item.encode("utf-8")))
                except Exception as exc:
                    raise ValueError(f"Failed to load CA certificate: {exc}") from exc

    encryption_algo: serialization.KeySerializationEncryption
    if password:
        encryption_algo = serialization.BestAvailableEncryption(password.encode("utf-8"))
    else:
        encryption_algo = serialization.NoEncryption()

    name_bytes = friendly_name.encode("utf-8") if friendly_name else None

    return pkcs12.serialize_key_and_certificates(
        name=name_bytes,
        key=private_key,
        cert=leaf_cert,
        cas=cas if cas else None,
        encryption_algorithm=encryption_algo,
    )


def extract_pfx_bundle(
    pfx_bytes: bytes,
    password: str | None = None,
) -> PFXExtractResult:
    """Extract private key, leaf certificate, and CA certificates from PKCS#12 bytes.

    Args:
        pfx_bytes: Binary bytes of .pfx/.p12 file.
        password: Password for the PFX archive (None if unencrypted).

    Returns:
        PFXExtractResult containing extracted PEM components.
    """
    pwd_bytes = password.encode("utf-8") if password else None
    try:
        key, cert, additional_certs = pkcs12.load_key_and_certificates(
            pfx_bytes,
            password=pwd_bytes,
        )
    except Exception as exc:
        raise ValueError(f"Failed to decrypt or parse PKCS#12: {exc}") from exc

    key_pem: str | None = None
    if key is not None:
        key_pem = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode("utf-8")

    cert_pem: str | None = None
    friendly_name: str | None = None
    if cert is not None:
        cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode("utf-8")

    ca_pems: list[str] = []
    if additional_certs:
        for ca in additional_certs:
            ca_pems.append(ca.public_bytes(serialization.Encoding.PEM).decode("utf-8"))

    return PFXExtractResult(
        private_key_pem=key_pem,
        cert_pem=cert_pem,
        ca_certs_pem=ca_pems,
        friendly_name=friendly_name,
    )
```

Export symbols in `src/ittools/core/pki/__init__.py`.

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_pki_pfx.py -v`
Expected: PASS (all 4 tests pass)

- [ ] **Step 5: Commit**

```bash
git add src/ittools/core/pki/pfx.py src/ittools/core/pki/__init__.py tests/test_pki_pfx.py
git commit -m "feat(pki): implement PKCS#12 PFX bundle and extract service"
```

---

### Task 2: Core ADCS Client Service

**Files:**
- Create: `src/ittools/core/adcs/__init__.py`
- Create: `src/ittools/core/adcs/exceptions.py`
- Create: `src/ittools/core/adcs/client.py`
- Test: `tests/test_adcs_client.py`

**Interfaces:**
- Consumes: `requests`, `requests.Session`, `requests_ntlm.HttpNtlmAuth` (optional fallback to basic), standard library `re`
- Produces:
  - `ADCSResult(req_id: str, cert_pem: str, chain_pem: str | None = None)`
  - `ADCSError`, `ADCSConnectionError`, `ADCSRequestDeniedError`, `ADCSPendingError`, `ADCSAuthError`
  - `ADCSClient(server, username, password, auth_method="ntlm", ca_file=None, insecure=False, timeout=30.0)`
  - `ADCSClient.submit_csr(csr_pem: str, template: str = "WebServer", attributes: str | None = None) -> ADCSResult`
  - `ADCSClient.retrieve_cert(req_id: str | int, encoding: str = "b64") -> str`
  - `ADCSClient.get_ca_cert(encoding: str = "b64") -> str`

- [ ] **Step 1: Write failing tests for ADCS client**

Create `tests/test_adcs_client.py`:
```python
"""Tests for ADCS Client service."""

import pytest
from unittest.mock import MagicMock, patch
import requests

from ittools.core.adcs.client import ADCSClient, ADCSResult
from ittools.core.adcs.exceptions import (
    ADCSError,
    ADCSPendingError,
    ADCSRequestDeniedError,
    ADCSAuthError,
    ADCSConnectionError,
)

FAKE_CSR = "-----BEGIN CERTIFICATE REQUEST-----\nMIIB...fake...=\n-----END CERTIFICATE REQUEST-----\n"
FAKE_CERT = "-----BEGIN CERTIFICATE-----\nMIID...fakecert...=\n-----END CERTIFICATE-----\n"


@patch("requests.Session")
def test_adcs_submit_csr_success(mock_session_cls):
    mock_session = MagicMock()
    mock_session_cls.return_value = mock_session

    # Response 1: certfnsh.asp with ReqID in text
    resp_post = MagicMock()
    resp_post.status_code = 200
    resp_post.text = '<html><a href="certnew.cer?ReqID=105&Enc=b64">Certificate</a></html>'
    resp_post.headers = {"Content-Type": "text/html"}

    # Response 2: certnew.cer with cert PEM
    resp_get = MagicMock()
    resp_get.status_code = 200
    resp_get.text = FAKE_CERT
    resp_get.headers = {"Content-Type": "application/pkix-cert"}

    mock_session.post.return_value = resp_post
    mock_session.get.return_value = resp_get

    client = ADCSClient(server="ca.corp.local", username="admin", password="password", auth_method="basic")
    result = client.submit_csr(FAKE_CSR, template="WebServer")

    assert isinstance(result, ADCSResult)
    assert result.req_id == "105"
    assert result.cert_pem == FAKE_CERT


@patch("requests.Session")
def test_adcs_submit_csr_pending(mock_session_cls):
    mock_session = MagicMock()
    mock_session_cls.return_value = mock_session

    resp = MagicMock()
    resp.status_code = 200
    resp.text = "<html>Certificate Pending. Your Request Id is 999. You must wait for an administrator.</html>"
    mock_session.post.return_value = resp

    client = ADCSClient(server="ca.corp.local", username="admin", password="password", auth_method="basic")
    with pytest.raises(ADCSPendingError) as exc_info:
        client.submit_csr(FAKE_CSR, template="WebServer")

    assert exc_info.value.req_id == "999"


@patch("requests.Session")
def test_adcs_submit_csr_denied(mock_session_cls):
    mock_session = MagicMock()
    mock_session_cls.return_value = mock_session

    resp = MagicMock()
    resp.status_code = 200
    resp.text = '<html>The disposition message is "Denied by Policy Module 0x80094800".</html>'
    mock_session.post.return_value = resp

    client = ADCSClient(server="ca.corp.local", username="admin", password="password", auth_method="basic")
    with pytest.raises(ADCSRequestDeniedError) as exc_info:
        client.submit_csr(FAKE_CSR, template="WebServer")

    assert "Denied by Policy Module" in str(exc_info.value)


@patch("requests.Session")
def test_adcs_auth_error(mock_session_cls):
    mock_session = MagicMock()
    mock_session_cls.return_value = mock_session

    resp = MagicMock()
    resp.status_code = 401
    resp.raise_for_status.side_effect = requests.HTTPError(response=resp)
    mock_session.post.return_value = resp

    client = ADCSClient(server="ca.corp.local", username="admin", password="wrong", auth_method="basic")
    with pytest.raises(ADCSAuthError):
        client.submit_csr(FAKE_CSR)


@patch("requests.Session")
def test_adcs_connection_error(mock_session_cls):
    mock_session = MagicMock()
    mock_session_cls.return_value = mock_session
    mock_session.post.side_effect = requests.ConnectionError("Failed to connect")

    client = ADCSClient(server="ca.invalid", username="admin", password="pwd", auth_method="basic")
    with pytest.raises(ADCSConnectionError):
        client.submit_csr(FAKE_CSR)
```

- [ ] **Step 2: Run test to verify failure**

Run: `pytest tests/test_adcs_client.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'ittools.core.adcs'`

- [ ] **Step 3: Implement `src/ittools/core/adcs/exceptions.py` and `client.py`**

Create `src/ittools/core/adcs/exceptions.py`:
```python
"""Exceptions for Microsoft ADCS integration."""


class ADCSError(Exception):
    """Base exception for ADCS operations."""


class ADCSConnectionError(ADCSError):
    """Network connection failure or timeout communicating with ADCS server."""


class ADCSAuthError(ADCSError):
    """Authentication to ADCS failed (e.g. HTTP 401)."""


class ADCSRequestDeniedError(ADCSError):
    """The ADCS server rejected or denied the certificate request."""

    def __init__(self, message: str, response_text: str = "") -> None:
        super().__init__(message)
        self.response_text = response_text


class ADCSPendingError(ADCSError):
    """The certificate request is pending CA administrator approval."""

    def __init__(self, req_id: str, message: str = "") -> None:
        super().__init__(f"Certificate request pending approval. Request ID: {req_id}")
        self.req_id = req_id
```

Create `src/ittools/core/adcs/client.py`:
```python
"""Client for Microsoft Active Directory Certificate Services Web Enrollment."""

from __future__ import annotations

import re
from dataclasses import dataclass
import requests

from ittools.core.adcs.exceptions import (
    ADCSError,
    ADCSAuthError,
    ADCSConnectionError,
    ADCSPendingError,
    ADCSRequestDeniedError,
)


@dataclass(frozen=True)
class ADCSResult:
    """Result of an ADCS certificate issuance request."""

    req_id: str
    cert_pem: str
    chain_pem: str | None = None


class ADCSClient:
    """Client for ADCS Web Enrollment (/certsrv)."""

    def __init__(
        self,
        server: str,
        username: str | None = None,
        password: str | None = None,
        auth_method: str = "ntlm",
        ca_file: str | None = None,
        insecure: bool = False,
        timeout: float = 30.0,
    ) -> None:
        self.server = server
        self.username = username
        self.password = password
        self.auth_method = auth_method.lower()
        self.timeout = timeout
        self.session = requests.Session()

        if insecure:
            self.session.verify = False
        elif ca_file:
            self.session.verify = ca_file

        self.session.headers.update(
            {"User-Agent": "Mozilla/5.0 (compatible; ittools-adcs/0.2.0)"}
        )
        self._setup_auth()

    def _setup_auth(self) -> None:
        if not self.username or self.password is None:
            return

        if self.auth_method == "ntlm":
            try:
                from requests_ntlm import HttpNtlmAuth

                self.session.auth = HttpNtlmAuth(self.username, self.password)
            except ImportError:
                # Fallback to basic auth if requests_ntlm not installed
                self.session.auth = (self.username, self.password)
        else:
            self.session.auth = (self.username, self.password)

    def _handle_request_error(self, exc: Exception) -> None:
        if isinstance(exc, requests.HTTPError):
            if exc.response is not None and exc.response.status_code == 401:
                raise ADCSAuthError("Authentication failed: invalid username or password (HTTP 401)") from exc
            raise ADCSError(f"HTTP request failed: {exc}") from exc
        if isinstance(exc, (requests.ConnectionError, requests.Timeout)):
            raise ADCSConnectionError(f"Connection to ADCS server '{self.server}' failed: {exc}") from exc
        raise ADCSError(f"Unexpected ADCS error: {exc}") from exc

    def submit_csr(
        self,
        csr_pem: str,
        template: str = "WebServer",
        attributes: str | None = None,
    ) -> ADCSResult:
        """Submit a CSR to the ADCS Web Enrollment page.

        Args:
            csr_pem: PEM formatted CSR string.
            template: ADCS certificate template name.
            attributes: Additional request attributes.

        Returns:
            ADCSResult containing req_id and cert_pem.
        """
        url = f"https://{self.server}/certsrv/certfnsh.asp"
        attrib = f"CertificateTemplate:{template}\r\n"
        if attributes:
            attrib += attributes

        data = {
            "Mode": "newreq",
            "CertRequest": csr_pem,
            "CertAttrib": attrib,
            "FriendlyType": "Saved-Request Certificate",
            "TargetStoreFlags": "0",
            "SaveCert": "yes",
        }

        try:
            response = self.session.post(url, data=data, timeout=self.timeout)
            response.raise_for_status()
        except Exception as exc:
            self._handle_request_error(exc)

        # Parse Request ID
        text = response.text
        req_id_match = re.search(r"certnew\.cer\?ReqID=(\d+)&", text)
        if req_id_match:
            req_id = req_id_match.group(1)
            cert_pem = self.retrieve_cert(req_id)
            return ADCSResult(req_id=req_id, cert_pem=cert_pem)

        if "Certificate Pending" in text:
            pending_match = re.search(r"Your Request Id is (\d+)\.", text)
            pending_id = pending_match.group(1) if pending_match else "unknown"
            raise ADCSPendingError(pending_id)

        denied_match = re.search(r'The disposition message is "([^"]+)"', text)
        error_msg = denied_match.group(1) if denied_match else "Request was denied by ADCS server"
        raise ADCSRequestDeniedError(error_msg, text)

    def retrieve_cert(self, req_id: str | int, encoding: str = "b64") -> str:
        """Download an issued certificate by Request ID.

        Args:
            req_id: Request ID.
            encoding: 'b64' (PEM) or 'bin'.

        Returns:
            PEM encoded certificate string.
        """
        url = f"https://{self.server}/certsrv/certnew.cer"
        params = {"ReqID": str(req_id), "Enc": encoding}
        try:
            response = self.session.get(url, params=params, timeout=self.timeout)
            response.raise_for_status()
        except Exception as exc:
            self._handle_request_error(exc)

        return response.text

    def get_ca_cert(self, encoding: str = "b64") -> str:
        """Download the ADCS CA certificate or chain."""
        url = f"https://{self.server}/certsrv/certnew.p7b"
        params = {"ReqID": "CACert", "Enc": encoding}
        try:
            response = self.session.get(url, params=params, timeout=self.timeout)
            response.raise_for_status()
        except Exception as exc:
            self._handle_request_error(exc)

        return response.text
```

Export symbols in `src/ittools/core/adcs/__init__.py`.

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_adcs_client.py -v`
Expected: PASS (all 5 tests pass)

- [ ] **Step 5: Commit**

```bash
git add src/ittools/core/adcs/ tests/test_adcs_client.py
git commit -m "feat(adcs): implement ADCS web enrollment client service"
```

---

### Task 3: CLI Subcommands for PKCS#12 (`ittools pfx`)

**Files:**
- Create: `src/ittools/cli/commands/pfx.py`
- Modify: `src/ittools/cli/main.py`
- Test: `tests/test_cli_pfx.py`

**Interfaces:**
- Consumes: `ittools.core.pki.pfx`, `argparse`, `sys`, `os`, `getpass`
- Produces:
  - `register_pfx_commands(subparsers)`
  - Subcommands: `ittools pfx create`, `ittools pfx extract`

- [ ] **Step 1: Write failing CLI tests for `ittools pfx`**

Create `tests/test_cli_pfx.py`:
```python
"""CLI integration tests for ittools pfx commands."""

import os
import pytest
from ittools.cli.main import main
from tests.test_pki_pfx import _generate_test_key_and_cert


def test_cli_pfx_create_and_extract_flow(tmp_path):
    key_pem, cert_pem = _generate_test_key_and_cert("cli.test.local")
    key_file = tmp_path / "server.key"
    cert_file = tmp_path / "server.crt"
    pfx_file = tmp_path / "server.pfx"
    extract_dir = tmp_path / "extracted"

    key_file.write_text(key_pem)
    cert_file.write_text(cert_pem)

    # 1. Create PFX with password
    code = main([
        "pfx", "create",
        "--key", str(key_file),
        "--cert", str(cert_file),
        "--out", str(pfx_file),
        "--password", "clipassword",
        "--name", "MyCert",
    ])
    assert code == 0
    assert pfx_file.exists()

    # 2. Extract PFX
    code = main([
        "pfx", "extract",
        "--in", str(pfx_file),
        "--password", "clipassword",
        "--out-dir", str(extract_dir),
    ])
    assert code == 0
    assert (extract_dir / "server.key").exists()
    assert (extract_dir / "server.crt").exists()

    # Verify 0600 permissions on extracted private key
    stat = os.stat(extract_dir / "server.key")
    assert stat.st_mode & 0o777 == 0o600


def test_cli_pfx_create_target_exists_without_force(tmp_path):
    key_pem, cert_pem = _generate_test_key_and_cert("guard.local")
    key_file = tmp_path / "guard.key"
    cert_file = tmp_path / "guard.crt"
    pfx_file = tmp_path / "guard.pfx"

    key_file.write_text(key_pem)
    cert_file.write_text(cert_pem)
    pfx_file.write_text("existing")

    code = main([
        "pfx", "create",
        "--key", str(key_file),
        "--cert", str(cert_file),
        "--out", str(pfx_file),
        "--password", "pwd",
    ])
    assert code == 1
```

- [ ] **Step 2: Run test to verify failure**

Run: `pytest tests/test_cli_pfx.py -v`
Expected: FAIL (subcommand pfx not registered)

- [ ] **Step 3: Implement `src/ittools/cli/commands/pfx.py` and register in `main.py`**

Create `src/ittools/cli/commands/pfx.py`:
```python
"""CLI commands for PKCS#12 (PFX) containers."""

from __future__ import annotations

import argparse
import getpass
import os
import sys
from pathlib import Path

from ittools.core.pki.pfx import create_pfx_bundle, extract_pfx_bundle


def register_pfx_commands(subparsers: argparse._SubParsersAction) -> None:
    """Register 'pfx' subcommands."""
    parser = subparsers.add_parser(
        "pfx",
        help="Create and extract PKCS#12 (.pfx / .p12) archives",
    )
    pfx_sub = parser.add_subparsers(dest="pfx_command", required=True)

    # pfx create
    create_p = pfx_sub.add_parser("create", help="Bundle Private Key + Cert into .pfx")
    create_p.add_argument("--key", required=True, help="Path to private key PEM file")
    create_p.add_argument("--cert", required=True, help="Path to certificate PEM file")
    create_p.add_argument("--ca", help="Path to CA certificate PEM file or bundle")
    create_p.add_argument("--out", help="Output .pfx file path")
    create_p.add_argument("--password", help="Password for PFX archive")
    create_p.add_argument("--no-password", action="store_true", help="Do not encrypt PFX with password")
    create_p.add_argument("--key-password", help="Password to decrypt private key if encrypted")
    create_p.add_argument("--name", help="Friendly name / alias for certificate")
    create_p.add_argument("--force", action="store_true", help="Overwrite existing output file")
    create_p.set_defaults(func=handle_pfx_create)

    # pfx extract
    extract_p = pfx_sub.add_parser("extract", help="Extract components from .pfx")
    extract_p.add_argument("--in", dest="in_file", required=True, help="Path to .pfx/.p12 file")
    extract_p.add_argument("--password", help="Password for PFX archive")
    extract_p.add_argument("--out-dir", help="Output directory for extracted files")
    extract_p.add_argument("--key-out", help="Custom path for extracted private key")
    extract_p.add_argument("--cert-out", help="Custom path for extracted certificate")
    extract_p.add_argument("--ca-out", help="Custom path for extracted CA bundle")
    extract_p.add_argument("--force", action="store_true", help="Overwrite existing output files")
    extract_p.set_defaults(func=handle_pfx_extract)


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
    if not password and not args.no_password:
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

    # Upfront overwrite checks
    targets = [key_dest, cert_dest]
    if result.ca_certs_pem:
        targets.append(ca_dest)

    for target in targets:
        if target.exists() and not args.force:
            sys.stderr.write(f"error: Destination file '{target}' already exists. Use --force to overwrite.\n")
            return 1

    out_dir.mkdir(parents=True, exist_ok=True)

    if result.private_key_pem:
        # Enforce 0600 permissions on extracted private key
        flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
        fd = os.open(str(key_dest), flags, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(result.private_key_pem)
        sys.stdout.write(f"Private key extracted to: {key_dest} (mode 0600)\n")

    if result.cert_pem:
        cert_dest.write_text(result.cert_pem, encoding="utf-8")
        sys.stdout.write(f"Certificate extracted to: {cert_dest}\n")

    if result.ca_certs_pem:
        ca_dest.write_text("\n".join(result.ca_certs_pem), encoding="utf-8")
        sys.stdout.write(f"CA chain extracted to: {ca_dest}\n")

    return 0
```

Register `register_pfx_commands(subparsers)` in `src/ittools/cli/main.py`.

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_cli_pfx.py -v`
Expected: PASS (all tests pass)

- [ ] **Step 5: Commit**

```bash
git add src/ittools/cli/commands/pfx.py src/ittools/cli/main.py tests/test_cli_pfx.py
git commit -m "feat(cli): add ittools pfx create and extract commands"
```

---

### Task 4: CLI Subcommands for ADCS (`ittools adcs`)

**Files:**
- Create: `src/ittools/cli/commands/adcs.py`
- Modify: `src/ittools/cli/main.py`
- Test: `tests/test_cli_adcs.py`

**Interfaces:**
- Consumes: `ittools.core.adcs.client`, `ittools.core.adcs.exceptions`, `ittools.core.pki.pfx`, `getpass`, `argparse`
- Produces:
  - `register_adcs_commands(subparsers)`
  - Subcommands: `ittools adcs sign`, `ittools adcs retrieve`, `ittools adcs ca-cert`

- [ ] **Step 1: Write failing CLI tests for `ittools adcs`**

Create `tests/test_cli_adcs.py`:
```python
"""CLI integration tests for ittools adcs commands."""

from unittest.mock import patch, MagicMock
from ittools.cli.main import main
from ittools.core.adcs.client import ADCSResult
from ittools.core.adcs.exceptions import ADCSPendingError, ADCSConnectionError
from tests.test_pki_pfx import _generate_test_key_and_cert


@patch("ittools.core.adcs.client.ADCSClient.submit_csr")
def test_cli_adcs_sign_success(mock_submit, tmp_path):
    mock_submit.return_value = ADCSResult(
        req_id="501",
        cert_pem="-----BEGIN CERTIFICATE-----\nMIID...fake...=\n-----END CERTIFICATE-----\n",
    )
    csr_file = tmp_path / "req.csr"
    csr_file.write_text("-----BEGIN CERTIFICATE REQUEST-----\nfake\n-----END CERTIFICATE REQUEST-----\n")
    out_file = tmp_path / "issued.cer"

    code = main([
        "adcs", "sign",
        "--server", "ca.corp.local",
        "--csr", str(csr_file),
        "--username", "user",
        "--password", "pass",
        "--out", str(out_file),
    ])
    assert code == 0
    assert out_file.exists()


@patch("ittools.core.adcs.client.ADCSClient.submit_csr")
def test_cli_adcs_sign_pending_exits_code_3(mock_submit, tmp_path, capsys):
    mock_submit.side_effect = ADCSPendingError("777")
    csr_file = tmp_path / "req.csr"
    csr_file.write_text("CSR")

    code = main([
        "adcs", "sign",
        "--server", "ca.corp.local",
        "--csr", str(csr_file),
        "--username", "user",
        "--password", "pass",
    ])
    assert code == 3
    captured = capsys.readouterr()
    assert "777" in captured.out or "777" in captured.err


@patch("ittools.core.adcs.client.ADCSClient.submit_csr")
def test_cli_adcs_sign_network_error_exits_code_2(mock_submit, tmp_path):
    mock_submit.side_effect = ADCSConnectionError("Network unreachable")
    csr_file = tmp_path / "req.csr"
    csr_file.write_text("CSR")

    code = main([
        "adcs", "sign",
        "--server", "ca.unreachable",
        "--csr", str(csr_file),
        "--username", "user",
        "--password", "pass",
    ])
    assert code == 2


@patch("ittools.core.adcs.client.ADCSClient.submit_csr")
def test_cli_adcs_sign_with_pfx_export(mock_submit, tmp_path):
    key_pem, cert_pem = _generate_test_key_and_cert("adcs.pfx.local")
    mock_submit.return_value = ADCSResult(req_id="601", cert_pem=cert_pem)

    csr_file = tmp_path / "test.csr"
    key_file = tmp_path / "test.key"
    pfx_file = tmp_path / "final.pfx"

    csr_file.write_text("CSR CONTENT")
    key_file.write_text(key_pem)

    code = main([
        "adcs", "sign",
        "--server", "ca.corp.local",
        "--csr", str(csr_file),
        "--key", str(key_file),
        "--out-pfx", str(pfx_file),
        "--pfx-password", "secretpfx",
        "--username", "user",
        "--password", "pass",
    ])
    assert code == 0
    assert pfx_file.exists()
```

- [ ] **Step 2: Run test to verify failure**

Run: `pytest tests/test_cli_adcs.py -v`
Expected: FAIL (subcommand adcs not registered)

- [ ] **Step 3: Implement `src/ittools/cli/commands/adcs.py` and register in `main.py`**

Create `src/ittools/cli/commands/adcs.py`:
```python
"""CLI commands for Microsoft ADCS Web Enrollment."""

from __future__ import annotations

import argparse
import getpass
import os
import sys
from pathlib import Path

from ittools.core.adcs.client import ADCSClient
from ittools.core.adcs.exceptions import (
    ADCSError,
    ADCSConnectionError,
    ADCSPendingError,
    ADCSRequestDeniedError,
    ADCSAuthError,
)
from ittools.core.pki.pfx import create_pfx_bundle


def register_adcs_commands(subparsers: argparse._SubParsersAction) -> None:
    """Register 'adcs' subcommands."""
    parser = subparsers.add_parser(
        "adcs",
        help="Interact with Microsoft AD Certificate Services (ADCS)",
    )
    adcs_sub = parser.add_subparsers(dest="adcs_command", required=True)

    # adcs sign
    sign_p = adcs_sub.add_parser("sign", help="Submit CSR to ADCS and retrieve certificate")
    sign_p.add_argument("--server", required=True, help="ADCS server FQDN or IP")
    sign_p.add_argument("--csr", required=True, help="Path to CSR PEM file (or - for stdin)")
    sign_p.add_argument("--template", default="WebServer", help="Certificate template (default: WebServer)")
    sign_p.add_argument("--username", help="AD username (e.g. DOMAIN\\user)")
    sign_p.add_argument("--password", help="AD user password")
    sign_p.add_argument("--auth", choices=["ntlm", "basic"], default="ntlm", help="Authentication method (default: ntlm)")
    sign_p.add_argument("--ca-bundle", help="Custom CA PEM file to verify ADCS HTTPS certificate")
    sign_p.add_argument("--insecure", action="store_true", help="Disable SSL verification for ADCS")
    sign_p.add_argument("--timeout", type=float, default=30.0, help="Timeout in seconds (default: 30)")
    sign_p.add_argument("--out", help="Output path for issued certificate (.cer)")
    # PFX pipeline options
    sign_p.add_argument("--key", help="Matching private key file to assemble PFX")
    sign_p.add_argument("--out-pfx", help="Output path for assembled PFX file")
    sign_p.add_argument("--pfx-password", help="Password for assembled PFX file")
    sign_p.add_argument("--name", help="Friendly name for certificate in PFX")
    sign_p.add_argument("--force", action="store_true", help="Overwrite destination files")
    sign_p.set_defaults(func=handle_adcs_sign)

    # adcs retrieve
    ret_p = adcs_sub.add_parser("retrieve", help="Retrieve approved certificate by Request ID")
    ret_p.add_argument("--server", required=True, help="ADCS server FQDN or IP")
    ret_p.add_argument("--req-id", required=True, help="ADCS Request ID")
    ret_p.add_argument("--username", help="AD username")
    ret_p.add_argument("--password", help="AD user password")
    ret_p.add_argument("--auth", choices=["ntlm", "basic"], default="ntlm", help="Authentication method")
    ret_p.add_argument("--ca-bundle", help="Custom CA PEM file")
    ret_p.add_argument("--insecure", action="store_true", help="Disable SSL verification")
    ret_p.add_argument("--timeout", type=float, default=30.0, help="Timeout in seconds")
    ret_p.add_argument("--out", help="Output path for certificate")
    ret_p.add_argument("--key", help="Matching private key file to assemble PFX")
    ret_p.add_argument("--out-pfx", help="Output path for assembled PFX file")
    ret_p.add_argument("--pfx-password", help="Password for assembled PFX file")
    ret_p.add_argument("--force", action="store_true", help="Overwrite destination files")
    ret_p.set_defaults(func=handle_adcs_retrieve)

    # adcs ca-cert
    ca_p = adcs_sub.add_parser("ca-cert", help="Download CA certificate/chain from ADCS")
    ca_p.add_argument("--server", required=True, help="ADCS server FQDN or IP")
    ca_p.add_argument("--username", help="AD username")
    ca_p.add_argument("--password", help="AD user password")
    ca_p.add_argument("--auth", choices=["ntlm", "basic"], default="ntlm")
    ca_p.add_argument("--ca-bundle", help="Custom CA PEM file")
    ca_p.add_argument("--insecure", action="store_true", help="Disable SSL verification")
    ca_p.add_argument("--timeout", type=float, default=30.0)
    ca_p.add_argument("--out", help="Output path for CA cert/bundle")
    ca_p.add_argument("--force", action="store_true", help="Overwrite destination file")
    ca_p.set_defaults(func=handle_adcs_ca_cert)


def _get_password(password: str | None, prompt: str) -> str | None:
    if password is not None:
        return password
    if sys.stdin.isatty():
        return getpass.getpass(prompt)
    return None


def handle_adcs_sign(args: argparse.Namespace) -> int:
    """Handle 'ittools adcs sign'."""
    if args.csr == "-":
        csr_pem = sys.stdin.read()
    else:
        csr_path = Path(args.csr)
        if not csr_path.exists():
            sys.stderr.write(f"error: CSR file not found: {args.csr}\n")
            return 1
        csr_pem = csr_path.read_text(encoding="utf-8")

    out_cert_path = Path(args.out) if args.out else Path("./output/issued.cer")
    out_pfx_path = Path(args.out_pfx) if args.out_pfx else None

    # Upfront file overwrite checks
    targets = [out_cert_path]
    if out_pfx_path:
        targets.append(out_pfx_path)

    for target in targets:
        if target.exists() and not args.force:
            sys.stderr.write(f"error: Destination file '{target}' already exists. Use --force to overwrite.\n")
            return 1

    password = _get_password(args.password, f"Enter password for {args.username or 'AD user'}: ")

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
        sys.stderr.write(f"\n[PENDING] Your certificate request is pending administrator approval.\n")
        sys.stderr.write(f"Request ID: {exc.req_id}\n")
        sys.stderr.write(f"To retrieve once approved, run:\n")
        sys.stderr.write(f"  ittools adcs retrieve --server {args.server} --req-id {exc.req_id}\n")
        return 3
    except ADCSConnectionError as exc:
        sys.stderr.write(f"error: {exc}\n")
        return 2
    except (ADCSRequestDeniedError, ADCSAuthError, ADCSError) as exc:
        sys.stderr.write(f"error: {exc}\n")
        return 1

    out_cert_path.parent.mkdir(parents=True, exist_ok=True)
    out_cert_path.write_text(result.cert_pem, encoding="utf-8")
    sys.stdout.write(f"Certificate successfully issued! (Request ID: {result.req_id})\n")
    sys.stdout.write(f"Saved certificate to: {out_cert_path}\n")

    if args.key and out_pfx_path:
        key_path = Path(args.key)
        if not key_path.exists():
            sys.stderr.write(f"error: Private key file not found: {args.key}\n")
            return 1
        key_pem = key_path.read_text(encoding="utf-8")
        try:
            pfx_bytes = create_pfx_bundle(
                private_key_pem=key_pem,
                cert_pem=result.cert_pem,
                password=args.pfx_password,
                friendly_name=args.name,
            )
            out_pfx_path.parent.mkdir(parents=True, exist_ok=True)
            out_pfx_path.write_bytes(pfx_bytes)
            sys.stdout.write(f"Assembled and saved PFX to: {out_pfx_path}\n")
        except Exception as exc:
            sys.stderr.write(f"error: Failed to assemble PFX: {exc}\n")
            return 1

    return 0


def handle_adcs_retrieve(args: argparse.Namespace) -> int:
    """Handle 'ittools adcs retrieve'."""
    out_path = Path(args.out) if args.out else Path(f"./output/req_{args.req_id}.cer")
    if out_path.exists() and not args.force:
        sys.stderr.write(f"error: Destination file '{out_path}' already exists. Use --force to overwrite.\n")
        return 1

    password = _get_password(args.password, "Enter AD password: ")
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
    except ADCSConnectionError as exc:
        sys.stderr.write(f"error: {exc}\n")
        return 2
    except Exception as exc:
        sys.stderr.write(f"error: {exc}\n")
        return 1

    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(cert_pem, encoding="utf-8")
    sys.stdout.write(f"Retrieved certificate saved to: {out_path}\n")

    if args.key and args.out_pfx:
        pfx_path = Path(args.out_pfx)
        key_path = Path(args.key)
        if not key_path.exists():
            sys.stderr.write(f"error: Private key not found: {args.key}\n")
            return 1
        key_pem = key_path.read_text(encoding="utf-8")
        try:
            pfx_bytes = create_pfx_bundle(
                private_key_pem=key_pem,
                cert_pem=cert_pem,
                password=args.pfx_password,
            )
            pfx_path.parent.mkdir(parents=True, exist_ok=True)
            pfx_path.write_bytes(pfx_bytes)
            sys.stdout.write(f"Assembled and saved PFX to: {pfx_path}\n")
        except Exception as exc:
            sys.stderr.write(f"error: Failed to assemble PFX: {exc}\n")
            return 1

    return 0


def handle_adcs_ca_cert(args: argparse.Namespace) -> int:
    """Handle 'ittools adcs ca-cert'."""
    out_path = Path(args.out) if args.out else Path(f"./output/{args.server}_ca.p7b")
    if out_path.exists() and not args.force:
        sys.stderr.write(f"error: Destination file '{out_path}' already exists. Use --force to overwrite.\n")
        return 1

    password = _get_password(args.password, "Enter AD password: ")
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
    except Exception as exc:
        sys.stderr.write(f"error: {exc}\n")
        return 1

    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(ca_data, encoding="utf-8")
    sys.stdout.write(f"Downloaded CA bundle to: {out_path}\n")
    return 0
```

Register `register_adcs_commands(subparsers)` in `src/ittools/cli/main.py`.

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_cli_adcs.py -v`
Expected: PASS (all 4 tests pass)

- [ ] **Step 5: Commit**

```bash
git add src/ittools/cli/commands/adcs.py src/ittools/cli/main.py tests/test_cli_adcs.py
git commit -m "feat(cli): add ittools adcs sign, retrieve, and ca-cert commands"
```

---

### Task 5: Documentation Update & End-to-End Verification

**Files:**
- Modify: `README.md`
- Run: `pytest tests/`

- [ ] **Step 1: Update README.md**

Document `ittools pfx` (`create`, `extract`) and `ittools adcs` (`sign`, `retrieve`, `ca-cert`) with practical examples, flags, and exit code explanations in `README.md`.

- [ ] **Step 2: Run full test suite**

Run: `pytest -v`
Expected: All existing (83) and new tests pass with 100% pass rate.

- [ ] **Step 3: Smoke test CLI commands live**

Run:
```bash
python3 -m ittools.cli.main pfx --help
python3 -m ittools.cli.main adcs --help
```
Verify help menus render cleanly without errors.

- [ ] **Step 4: Commit**

```bash
git add README.md
git commit -m "docs: document ittools pfx and ittools adcs subcommands"
```
