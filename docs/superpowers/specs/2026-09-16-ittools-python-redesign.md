# ittools: Python IT Utilities & SSL/TLS Toolkit — Design Specification

- **Date:** 2026-09-16
- **Status:** Approved / In Spec Review
- **Branch:** `musicsms/fork-to-python`

---

## 1. Context & Motivation

The `ittools` repository was previously initiated as a Go CLI with a single subcommand (`csr generate`). The project direction is now being standardized and ported to **Python** (matching the branch `musicsms/fork-to-python`), integrating and expanding upon cryptographic and IT utility features from:
1. **`musicsms/generate-keypair`**: Proven Python implementations for generating passphrases, RSA keys, SSH keypairs (Ed25519 & RSA), and PGP keys.
2. **`ssl.org`**: Standard tools for SSL/TLS inspection, CSR decoding, SSL certificate/key matching, HTTP security headers analysis, and server TLS configuration generation.

Web UI (Streamlit) is intentionally excluded in this phase to keep the toolkit lightweight, instant to start, and optimized for developers, sysadmins, and CI/CD automation pipelines.

---

## 2. Goals & Non-Goals

### Goals
- **Unified Python CLI**: Single command entrypoint `ittools <subcommand> [flags]` installed via `pyproject.toml`.
- **Decoupled Architecture**: All core logic lives in `src/ittools/core/` without CLI formatting or I/O coupling, making it fully reusable as an importable library.
- **Full Utility Coverage**:
  - **Keypair**: Passphrase generator, RSA keypair, SSH keypair (Ed25519, RSA), PGP keypair (with graceful system check for `gpg`).
  - **PKI**: CSR generator (with interactive and flag-based modes, matching previous Go CLI), CSR decoder, and Key/Cert matcher.
  - **SSL Network Analysis**: Remote host SSL checker (expiry, days remaining, chain, SANs, protocol), Security headers inspection.
  - **Config Generation**: Hardened TLS configurations for Nginx, Apache, and Caddy.
- **Scriptability & Standards**: Support `--json` flag for automated tooling and exit codes indicating success (`0`), user error (`1`), network failure (`2`), or security alerts (`3`).
- **Comprehensive Testing**: Full Pytest suite covering unit and CLI integration tests.

### Non-Goals
- No Web UI / Streamlit interface in this phase.
- No third-party network proxies required; network checks use standard TLS socket / HTTP requests.
- No proprietary cloud APIs or paid services.

---

## 3. Architecture & Directory Structure

```
ittools/
├── pyproject.toml
├── README.md
├── src/
│   └── ittools/
│       ├── __init__.py
│       ├── core/
│       │   ├── __init__.py
│       │   ├── keypair/
│       │   │   ├── __init__.py
│       │   │   ├── passphrase.py
│       │   │   ├── rsa.py
│       │   │   ├── ssh.py
│       │   │   └── pgp.py
│       │   ├── pki/
│       │   │   ├── __init__.py
│       │   │   ├── csr.py
│       │   │   └── matcher.py
│       │   ├── ssl_check/
│       │   │   ├── __init__.py
│       │   │   ├── checker.py
│       │   │   └── headers.py
│       │   └── config_gen/
│       │       ├── __init__.py
│       │       └── generator.py
│       └── cli/
│           ├── __init__.py
│           ├── main.py              # CLI entry point, argument parser dispatch
│           ├── prompt.py            # Interactive prompt helper for CSR generator
│           └── commands/
│               ├── __init__.py
│               ├── csr.py
│               ├── keypair.py
│               ├── ssl.py
│               └── config.py
└── tests/
    ├── __init__.py
    ├── test_keypair_passphrase.py
    ├── test_keypair_rsa.py
    ├── test_keypair_ssh.py
    ├── test_keypair_pgp.py
    ├── test_pki_csr.py
    ├── test_pki_matcher.py
    ├── test_ssl_checker.py
    ├── test_ssl_headers.py
    ├── test_config_gen.py
    └── test_cli.py
```

---

## 4. Dependencies & Packaging

Configured in `pyproject.toml` with `setuptools`:

```toml
[build-system]
requires = ["setuptools>=61.0"]
build-backend = "setuptools.build_meta"

[project]
name = "ittools"
version = "0.2.0"
description = "A standard CLI toolkit of IT, PKI, and SSL/TLS utilities."
readme = "README.md"
requires-python = ">=3.10"
dependencies = [
    "cryptography>=42.0.0",
    "paramiko>=3.4.0",
    "python-gnupg>=0.5.2",
    "requests>=2.31.0",
]

[project.optional-dependencies]
dev = [
    "pytest>=8.0.0",
    "pytest-cov>=4.1.0",
]

[project.scripts]
ittools = "ittools.cli.main:main"
```

---

## 5. Core Services Specification

### 5.1 `core/keypair`
- **`passphrase.py`**:
  - `generate_passphrase(words_count: int = 4, separator: str = "-", capitalize: bool = False, include_numbers: bool = False, include_special: bool = False) -> str`: Uses system CSPRNG (`secrets.choice`) over a built-in curated EFF-style wordlist.
- **`rsa.py`**:
  - `generate_rsa_keypair(key_size: int = 2048, password: str | None = None) -> RSAKeyPair`: Generates RSA private/public keys, returns PEM-encoded strings. If `password` is provided, encrypts private key using `BestAvailableEncryption`.
- **`ssh.py`**:
  - `generate_ssh_keypair(key_type: str = "ed25519", key_size: int = 2048, password: str | None = None, comment: str = "") -> SSHKeyPair`: Supports `ed25519` and `rsa`. Exports OpenSSH formatted private and public keys.
- **`pgp.py`**:
  - `generate_pgp_key(name: str, email: str, comment: str = "", key_type: str = "RSA", key_size: int = 2048, expire_years: int = 1, passphrase: str | None = None) -> PGPKeyPair`:
  - Validates whether system `gpg` binary exists using `shutil.which("gpg")`. If absent, raises a descriptive `GPGNotInstalledError`.
  - Runs inside isolated `tempfile.TemporaryDirectory` to prevent polluting host user GPG keyrings.

### 5.2 `core/pki`
- **`csr.py`**:
  - Dataclasses: `CSRSubject`, `CSRResult`, `CSRDetails`.
  - `generate_csr(subject: CSRSubject, sans: list[str] | None = None, key_size: int = 2048) -> CSRResult`:
    - Generates RSA private key (2048, 3072, 4096).
    - Signs PKCS#10 request with requested Key Usage (Digital Signature, Key Encipherment) and Extended Key Usage (Server Auth, Client Auth).
    - `sanitize_name(cn: str) -> str`: Normalizes wildcard CNs (e.g. `*.domain.com` $\to$ `wildcard.domain.com`).
  - `decode_csr(csr_pem: str) -> CSRDetails`: Parses CSR PEM bytes using `cryptography.x509.load_pem_x509_csr`, extracts Subject attributes, SANs, public key type/size, and signature algorithm.
- **`matcher.py`**:
  - `match_key_and_cert(private_key_pem: str, cert_or_csr_pem: str) -> MatchResult`:
    - Extracts public numbers / modulus from private key and certificate/CSR.
    - Calculates SHA256 hashes of public key DER bytes.
    - Returns `matched: bool`, modulus SHA256, and human-readable explanation.

### 5.3 `core/ssl_check`
- **`checker.py`**:
  - `check_remote_ssl(host: str, port: int = 443, timeout: float = 10.0) -> SSLReport`:
    - Opens a TLS socket (`ssl.create_default_context()`) to `(host, port)`.
    - Retrieves peer binary DER certificate and parses it with `cryptography.x509`.
    - Computes `valid_from`, `valid_to`, `days_remaining`, `is_expired`, `issuer`, `subject`, `sans`, `serial_number`, `tls_version`, `cipher_suite`.
    - Detects whether days remaining is $< 30$ (warning threshold).
- **`headers.py`**:
  - `check_security_headers(url: str, timeout: float = 10.0) -> HeadersReport`:
    - Sends an HTTP HEAD/GET request to `url` with redirect following.
    - Analyzes headers: `Strict-Transport-Security`, `Content-Security-Policy`, `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`, `Permissions-Policy`.
    - Reports present vs missing headers and provides security hardening recommendations.

### 5.4 `core/config_gen`
- **`generator.py`**:
  - `generate_server_config(server: str, profile: str, domain: str, cert_path: str, key_path: str, hsts: bool = True) -> str`:
    - Supports `server` in `["nginx", "apache", "caddy"]`.
    - Supports `profile` in `["intermediate", "modern"]` adhering to Mozilla SSL Configuration guidelines.
    - Renders ready-to-use virtual host blocks.

---

## 6. CLI Command Specifications

### 6.1 `ittools csr`
- `ittools csr generate`:
  - Flags: `--cn` (required for non-interactive), `--org`, `--ou`, `--city`, `--state`, `--country`, `--email`, `--san` (comma-separated), `--key-size` (default 2048), `--force`, `--output-dir` (default `./output/<name>/`).
  - Interactive mode triggered if no flags are provided, prompting field-by-field.
  - Writes `<name>.key` and `<name>.csr` to output directory (0600 file permission for key) and echoes PEM to stdout.
- `ittools csr decode [--in <file>]`:
  - Decodes file or reads from `sys.stdin`.
  - Displays formatted table of Subject, SANs, Key size, Signature Algorithm.

### 6.2 `ittools keypair`
- `ittools keypair passphrase [--words 4] [--sep -] [--capitalize] [--numbers] [--special]`
- `ittools keypair rsa [--size 2048] [--password <pwd>] [--out <file>]`
- `ittools keypair ssh [--type ed25519|rsa] [--size 2048] [--comment <cmt>] [--password <pwd>] [--out <file>]`
- `ittools keypair pgp --name <name> --email <email> [--comment <cmt>] [--expire <years>] [--out-dir <dir>]`

### 6.3 `ittools ssl`
- `ittools ssl check <domain_or_host> [--port 443] [--json]`:
  - Connects to host:port via TLS.
  - Formats output table or outputs JSON.
  - Exits with `0` if valid, `2` on connection failure, `3` if expired or $<30$ days left.
- `ittools ssl headers <url> [--json]`:
  - Evaluates security headers of given URL.
- `ittools ssl match --key <key_file> --cert <cert_or_csr_file>`:
  - Validates key pair match. Exits with `0` on match, `3` on mismatch.

### 6.4 `ittools config`
- `ittools config generate --server nginx|apache|caddy [--profile modern|intermediate] [--domain example.com] [--cert /path/to/cert.pem] [--key /path/to/key.pem] [--no-hsts]`

---

## 7. Security, Error Handling & Permissions

1. **Private Key Storage**: Every private key written to disk is saved using `os.open(..., os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)`.
2. **File Overwrite Protection**: Existing files will not be replaced unless `--force` is specified.
3. **Exit Codes**:
   - `0`: Success
   - `1`: User / Validation error (e.g. invalid key size, malformed country code)
   - `2`: Network / Connection failure
   - `3`: Security warning (certificate expired, keys mismatch)
4. **Stderr vs Stdout**: Errors and interactive prompts write to `stderr`, data outputs (PEM, JSON, configs) write to `stdout`.

---

## 8. Verification & Testing Plan

1. **Unit Tests (`tests/`)**:
   - `test_keypair_passphrase.py`: Word count, separator, casing, special characters.
   - `test_keypair_rsa.py`: 2048/3072/4096-bit generation, password encryption / decryption.
   - `test_keypair_ssh.py`: Ed25519 and RSA OpenSSH formats.
   - `test_keypair_pgp.py`: Key creation in temp dir, handling missing `gpg`.
   - `test_pki_csr.py`: Subject mapping, SANs inclusion, Key Usage extensions, decode CSR round-trip.
   - `test_pki_matcher.py`: Matching vs mismatched key and cert/CSR.
   - `test_ssl_checker.py`: Mock TLS sockets verifying report generation, expiry calculations.
   - `test_ssl_headers.py`: Mock HTTP response verifying header checks and warnings.
   - `test_config_gen.py`: Nginx, Apache, Caddy template rendering tests.
   - `test_cli.py`: End-to-end CLI execution with exit code validation.
2. **Backward Compatibility Verification**:
   - Verify that running `ittools csr generate --cn example.com --country VN` produces the exact equivalent output as the former Go implementation.
