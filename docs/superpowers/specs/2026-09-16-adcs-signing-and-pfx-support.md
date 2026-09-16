# Design Spec: ADCS Certificate Signing & PKCS#12 (PFX) Management

## 1. Overview & Objectives

This specification defines the architecture, service interfaces, CLI commands, error handling, security policies, and test suite for adding two major capabilities to `ittools`:
1. **PKCS#12 / PFX Management (`ittools pfx`)**: Creation and extraction of `.pfx` / `.p12` container archives (combining private keys, X.509 certificates, and CA certificate bundles) using pure Python `cryptography` primitives with industrial-grade encryption.
2. **Microsoft ADCS Certificate Signing (`ittools adcs`)**: Cross-platform client communicating with Microsoft Active Directory Certificate Services (AD CS) Web Enrollment endpoints (`/certsrv/certfnsh.asp`) via HTTP/HTTPS, supporting CSR submission, template selection, NTLM/Basic authentication, pending request tracking, CA chain retrieval, and an integrated 1-step CSR-to-PFX packaging pipeline.

Reference implementations and standards:
- [magnuswatn/certsrv](https://github.com/magnuswatn/certsrv)
- Microsoft AD CS Web Enrollment Protocol & Templates
- RFC 7292 (PKCS #12: Personal Information Exchange Syntax v1.1)

---

## 2. Architecture & File Structure

```
src/ittools/
├── core/
│   ├── pki/
│   │   ├── csr.py                 # Existing CSR generate/decode
│   │   ├── matcher.py             # Existing Key/Cert matcher
│   │   └── pfx.py                 # NEW: PKCS#12 bundle & extract service
│   └── adcs/                      # NEW: ADCS integration service
│       ├── __init__.py
│       ├── exceptions.py          # NEW: ADCS domain exceptions
│       └── client.py              # NEW: ADCS HTTP client (requests-based)
├── cli/
│   ├── commands/
│   │   ├── pfx.py                 # NEW: ittools pfx {create, extract}
│   │   └── adcs.py                # NEW: ittools adcs {sign, retrieve, ca-cert}
│   └── main.py                    # Subcommand registration & exit code routing
tests/
├── test_pki_pfx.py                # NEW: Unit tests for core/pki/pfx.py
├── test_adcs_client.py            # NEW: Unit tests for core/adcs/client.py
├── test_cli_pfx.py                # NEW: Integration tests for CLI pfx commands
└── test_cli_adcs.py               # NEW: Integration tests for CLI adcs commands
```

---

## 3. Core Services Specification

### 3.1. PKCS#12 / PFX Service (`src/ittools/core/pki/pfx.py`)

#### Data Structures
```python
from dataclasses import dataclass

@dataclass(frozen=True)
class PFXExtractResult:
    """Result of extracting a PKCS#12 bundle."""
    private_key_pem: str | None
    cert_pem: str | None
    ca_certs_pem: list[str]
    friendly_name: str | None
```

#### Public Functions
```python
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
        private_key_pem: PEM-encoded RSA or EC private key.
        cert_pem: PEM-encoded X.509 end-entity certificate.
        ca_certs_pem: Optional list of PEM-encoded CA certificates or a multi-cert PEM bundle string.
        password: Password for the PFX archive. If None or empty, NoEncryption is used.
        friendly_name: Optional alias / friendly name embedded in the PFX bag attributes.
        key_password: Password to decrypt private_key_pem if it is encrypted.

    Returns:
        Raw bytes of the serialized PKCS#12 (.pfx / .p12) container.

    Raises:
        ValueError: If key, cert, or CA certs cannot be parsed or are invalid PEM.
    """
```

```python
def extract_pfx_bundle(
    pfx_bytes: bytes,
    password: str | None = None,
) -> PFXExtractResult:
    """Extract private key, leaf certificate, and CA certificates from PKCS#12 bytes.

    Args:
        pfx_bytes: Binary contents of the .pfx/.p12 file.
        password: Password to open the PKCS#12 archive (None if unencrypted).

    Returns:
        PFXExtractResult containing PEM strings and friendly name.

    Raises:
        ValueError: If password is incorrect, corrupt, or unsupported format.
    """
```

#### Cryptographic Details
- Uses `cryptography.hazmat.primitives.serialization.pkcs12.serialize_key_and_certificates`.
- Uses `cryptography.hazmat.primitives.serialization.BestAvailableEncryption(password.encode())` when `password` is provided.
- Decodes private keys with `serialization.load_pem_private_key(private_key_pem.encode(), password=key_password.encode() if key_password else None)`.
- Parses certificates via `cryptography.x509.load_pem_x509_certificate` and bundles via `cryptography.x509.load_pem_x509_certificates`.

---

### 3.2. ADCS Client Service (`src/ittools/core/adcs/client.py` & `exceptions.py`)

#### Exceptions (`src/ittools/core/adcs/exceptions.py`)
```python
class ADCSError(Exception):
    """Base exception for all ADCS errors."""

class ADCSConnectionError(ADCSError):
    """Network connection or SSL handshake failure communicating with ADCS."""

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

class ADCSAuthError(ADCSError):
    """Authentication to ADCS failed (e.g. HTTP 401)."""
```

#### Data Structures
```python
@dataclass(frozen=True)
class ADCSResult:
    """Result of an ADCS signing request."""
    req_id: str
    cert_pem: str
    chain_pem: str | None = None
```

#### Client Interface (`src/ittools/core/adcs/client.py`)
```python
class ADCSClient:
    """Client for Microsoft ADCS Web Enrollment (/certsrv)."""

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
        """Initialize ADCS client.

        Args:
            server: FQDN or IP of ADCS server (e.g. 'ca.corp.local').
            username: AD user (e.g. 'CORP\\admin' or 'admin@corp.local').
            password: Password for user.
            auth_method: 'ntlm' or 'basic'.
            ca_file: Path to custom CA PEM bundle to trust the ADCS server.
            insecure: Disable SSL verification if True.
            timeout: Request timeout in seconds.
        """
```

#### Client Methods
1. `submit_csr(csr_pem: str, template: str = "WebServer", attributes: str | None = None) -> ADCSResult`:
   - Submits POST to `https://{server}/certsrv/certfnsh.asp` with `requests.Session`.
   - Sets headers: `User-Agent: Mozilla/5.0 (compatible; ittools-adcs)` (ensures correct `application/pkix-cert` MIME responses).
   - Form parameters:
     - `Mode`: `"newreq"`
     - `CertRequest`: `csr_pem`
     - `CertAttrib`: `f"CertificateTemplate:{template}\r\n"` (+ optional `attributes`)
     - `FriendlyType`: `"Saved-Request Certificate"`
     - `TargetStoreFlags`: `"0"`
     - `SaveCert`: `"yes"`
   - Parses response:
     - If approved: Matches `certnew.cer\?ReqID=(\d+)&` to obtain `req_id`, then calls `retrieve_cert(req_id)`.
     - If pending: Matches `Certificate Pending` and `Your Request Id is (\d+)\.` -> raises `ADCSPendingError(req_id)`.
     - If denied: Matches `The disposition message is "([^"]+)` -> raises `ADCSRequestDeniedError(reason, response.text)`.
2. `retrieve_cert(req_id: str | int, encoding: str = "b64") -> str`:
   - Submits GET to `https://{server}/certsrv/certnew.cer?ReqID={req_id}&Enc={encoding}`.
   - Validates response header `Content-Type` is `application/pkix-cert`.
   - Returns standard PEM string (`-----BEGIN CERTIFICATE-----...`).
3. `get_ca_cert(encoding: str = "b64") -> str`:
   - Submits GET to `https://{server}/certsrv/certnew.p7b?ReqID=CACert&Enc={encoding}` (or `certnew.cer`).
   - Returns PEM or PKCS#7 bundle.

---

## 4. CLI Subcommand Specifications

### 4.1. `ittools pfx` Subcommands (`src/ittools/cli/commands/pfx.py`)

#### `ittools pfx create`
Pack Private Key, Certificate, and optional CA bundle into `.pfx`:
```
usage: ittools pfx create --key KEY --cert CERT [OPTIONS]

required arguments:
  --key PATH            Path to private key PEM file
  --cert PATH           Path to certificate PEM file

optional arguments:
  --ca PATH             Path to CA certificate PEM file or bundle
  --out PATH            Output path for .pfx file (default: ./output/<cert_basename>.pfx)
  --password PWD        Password to encrypt PFX (prompts securely if omitted and not --no-password)
  --no-password         Create PFX without encryption password
  --key-password PWD    Password to decrypt private key if encrypted
  --name NAME           Friendly name / alias for certificate in PFX
  --force               Overwrite output file if it exists
```

#### `ittools pfx extract`
Extract Private Key, Certificate, and CA bundle from `.pfx`:
```
usage: ittools pfx extract --in FILE [OPTIONS]

required arguments:
  --in PATH             Path to .pfx / .p12 archive file

optional arguments:
  --password PWD        Password to decrypt PFX (prompts if needed)
  --out-dir DIR         Output directory for extracted files (default: ./output/<pfx_basename>/)
  --key-out PATH        Custom filename for extracted private key (permissions: 0600)
  --cert-out PATH       Custom filename for extracted leaf certificate
  --ca-out PATH         Custom filename for extracted CA bundle
  --force               Overwrite existing output files
```

### 4.2. `ittools adcs` Subcommands (`src/ittools/cli/commands/adcs.py`)

#### `ittools adcs sign`
Submit CSR to ADCS Web Enrollment:
```
usage: ittools adcs sign --server FQDN --csr FILE [OPTIONS]

required arguments:
  --server FQDN         ADCS server hostname or IP (e.g. ca.corp.internal)
  --csr PATH            Path to CSR PEM file (or - for stdin)

optional arguments:
  --template NAME       ADCS Certificate Template name (default: WebServer)
  --username USER       AD username (e.g. CORP\user or user@corp.local)
  --password PWD        AD password (prompts securely if omitted)
  --auth {ntlm,basic}   Authentication scheme (default: ntlm)
  --ca-bundle PATH      Custom CA certificate file to verify ADCS HTTPS certificate
  --insecure            Disable SSL certificate verification for ADCS server
  --timeout SEC         Network timeout in seconds (default: 30.0)
  --out PATH            Output path for issued certificate PEM (default: ./output/<req_id>.cer)

All-in-one PFX options:
  --key PATH            Matching private key file to automatically assemble PFX
  --out-pfx PATH        Output path for assembled .pfx file
  --pfx-password PWD    Password for the created PFX file
  --name NAME           Friendly name for PFX certificate
  --force               Overwrite destination files if they exist
```

#### `ittools adcs retrieve`
Retrieve pending certificate once approved:
```
usage: ittools adcs retrieve --server FQDN --req-id ID [OPTIONS]

required arguments:
  --server FQDN         ADCS server hostname or IP
  --req-id ID           ADCS Request ID to retrieve

optional arguments:
  --username USER       AD username
  --password PWD        AD password
  --auth {ntlm,basic}   Authentication scheme (default: ntlm)
  --ca-bundle PATH      Custom CA certificate file to verify ADCS HTTPS certificate
  --insecure            Disable SSL verification
  --timeout SEC         Network timeout in seconds (default: 30.0)
  --out PATH            Output path for retrieved certificate PEM
  --key PATH            Matching private key file to assemble PFX
  --out-pfx PATH        Output path for assembled .pfx file
  --pfx-password PWD    Password for assembled PFX file
  --force               Overwrite destination files
```

#### `ittools adcs ca-cert`
Download CA certificate / chain from ADCS:
```
usage: ittools adcs ca-cert --server FQDN [OPTIONS]

required arguments:
  --server FQDN         ADCS server hostname or IP

optional arguments:
  --username USER       AD username
  --password PWD        AD password
  --auth {ntlm,basic}   Authentication scheme (default: ntlm)
  --ca-bundle PATH      Custom CA certificate file
  --insecure            Disable SSL verification
  --timeout SEC         Network timeout in seconds (default: 30.0)
  --out PATH            Output path for CA certificate / chain
  --force               Overwrite destination file
```

---

## 5. Security & Error Handling

### 5.1. File Security & Permissions
- All private keys written to disk (`ittools pfx extract` and any intermediate key files) must have restrictive `0600` permissions (`os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)`).
- Upfront destination checks: Before creating or writing any files, inspect all planned target files. If any exist and `--force` is False, abort immediately with exit code 1 to avoid leaving orphan files.

### 5.2. Credential Security
- If `--password` or `--pfx-password` is not provided in interactive CLI mode, the tool prompts using Python's standard `getpass.getpass()`, avoiding plaintext credentials in shell history (`.bash_history`).
- PFX serialization uses `BestAvailableEncryption` (PBKDF2 with SHA-256 and AES-256-CBC).

### 5.3. Exit Codes
- `0`: Success (PFX created/extracted, certificate signed/retrieved).
- `1`: User/validation error (missing file, invalid PEM/DER, password incorrect, request denied by CA policy).
- `2`: Network connection error (ADCS connection refused, timeout, DNS resolution failure, SSL handshake failure without `--insecure`).
- `3`: Pending approval (ADCS request was accepted but requires CA administrator approval; displays Request ID).

---

## 6. Verification & Test Plan

1. **Unit Tests (`tests/test_pki_pfx.py`)**:
   - `test_create_pfx_bundle_with_password`: Generate RSA key + cert, bundle with password, verify bytes valid PKCS#12.
   - `test_create_pfx_bundle_without_password`: Bundle with `password=None`, verify readable.
   - `test_create_pfx_bundle_with_ca_chain`: Bundle with leaf cert + intermediate CA + root CA, verify all certs preserved.
   - `test_extract_pfx_bundle_roundtrip`: Create bundle, extract, verify private key modulus and cert serial match original.
   - `test_extract_pfx_bundle_invalid_password`: Expect ValueError when wrong password provided.
   - `test_create_pfx_with_encrypted_private_key`: Ensure key password is used to decrypt key before bundling.

2. **Unit Tests (`tests/test_adcs_client.py`)**:
   - `test_adcs_submit_csr_success`: Mock POST to `/certsrv/certfnsh.asp` returning `certnew.cer?ReqID=42&`, mock GET returning valid cert PEM.
   - `test_adcs_submit_csr_pending`: Mock response with `Certificate Pending ... Your Request Id is 99.`, verify `ADCSPendingError(req_id="99")` raised.
   - `test_adcs_submit_csr_denied`: Mock response with `The disposition message is "Denied by Policy Module"`, verify `ADCSRequestDeniedError` raised.
   - `test_adcs_auth_error`: Mock HTTP 401 response, verify `ADCSAuthError` or `requests.HTTPError`.
   - `test_adcs_retrieve_cert`: Mock GET with `ReqID=42`, verify PEM returned.
   - `test_adcs_get_ca_cert`: Mock GET for CA chain, verify payload returned.

3. **CLI Integration Tests (`tests/test_cli_pfx.py` & `tests/test_cli_adcs.py`)**:
   - `test_cli_pfx_create_and_extract`: CLI run `ittools pfx create`, then `ittools pfx extract`, verify `0600` permissions on extracted key file.
   - `test_cli_pfx_create_overwrite_guard`: Verify exit code 1 when target file exists without `--force`.
   - `test_cli_adcs_sign_success`: Mock ADCS network calls, verify exit code 0 and output `.cer` written.
   - `test_cli_adcs_sign_pending`: Mock pending response, verify exit code 3 and printed Request ID.
   - `test_cli_adcs_sign_network_error`: Mock connection error, verify exit code 2.
   - `test_cli_adcs_sign_with_pfx_export`: Verify `--key` and `--out-pfx` creates valid `.pfx` file in one step.
