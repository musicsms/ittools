# ittools: Python IT Utilities & SSL/TLS Toolkit Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Standardize and port `ittools` to a clean, modular Python CLI toolkit covering Keypair generation (Passphrase, RSA, SSH, PGP), PKI tools (CSR generate/decode, Key/Cert matcher), SSL/TLS network checks (certificate validation, expiry, security headers), and Server TLS configuration generation.

**Architecture:** Clean Layered Architecture separating pure Python business logic (`src/ittools/core/`) from command-line interface orchestration (`src/ittools/cli/`). Core services are 100% decoupled from console I/O and fully testable in isolation. The CLI exposes a hierarchical subcommand tree (`ittools <subcommand>`) supporting both human-readable text and machine-readable JSON output.

**Tech Stack:** Python >= 3.10, `cryptography` (RSA, Ed25519, X.509 CSR & Certs), `paramiko` (OpenSSH keys), `python-gnupg` (PGP keys), `requests` (HTTP security headers), `pytest` (unit & integration testing).

**Spec:** `docs/superpowers/specs/2026-09-16-ittools-python-redesign.md`

## Global Constraints

- Requires Python >= 3.10.
- All private key files written to disk must be saved with restrictive permissions `0600` (`chmod 600`).
- Overwriting existing files requires the explicit `--force` flag; never silently overwrite existing keys or CSRs.
- Exit codes: `0` for success, `1` for validation/usage errors, `2` for network connection failures, `3` for security alerts/mismatches.
- PGP operations must execute inside temporary directories (`tempfile.TemporaryDirectory`) and cleanly handle absent system `gpg` binaries.
- All network checks must enforce a default timeout of 10 seconds.
- Every core function must have comprehensive unit tests with assertions on returned dataclasses or exceptions.

---

### Task 1: Python Project Scaffold & Packaging

**Files:**
- Create: `pyproject.toml`
- Create: `src/ittools/__init__.py`
- Create: `src/ittools/core/__init__.py`
- Create: `src/ittools/cli/__init__.py`
- Test: `tests/test_package.py`

**Interfaces:**
- Consumes: None
- Produces: `ittools.__version__ == "0.2.0"`, package installable via `pip install -e .`

- [ ] **Step 1: Write the failing test**

```python
# tests/test_package.py
import ittools

def test_package_metadata():
    assert ittools.__version__ == "0.2.0"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_package.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'ittools'` or `AttributeError`

- [ ] **Step 3: Write minimal implementation**

```toml
# pyproject.toml
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

```python
# src/ittools/__init__.py
"""ittools: IT Utilities and SSL/TLS Toolkit."""

__version__ = "0.2.0"
```

```python
# src/ittools/core/__init__.py
"""Core domain services for ittools."""
```

```python
# src/ittools/cli/__init__.py
"""CLI orchestration and command handlers for ittools."""
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python3 -m pip install -e . && pytest tests/test_package.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add pyproject.toml src/ tests/test_package.py
git commit -m "feat: scaffold python project and packaging"
```

---

### Task 2: Core Keypair Services (Passphrase, RSA, SSH, PGP)

**Files:**
- Create: `src/ittools/core/keypair/__init__.py`
- Create: `src/ittools/core/keypair/passphrase.py`
- Create: `src/ittools/core/keypair/rsa.py`
- Create: `src/ittools/core/keypair/ssh.py`
- Create: `src/ittools/core/keypair/pgp.py`
- Test: `tests/test_keypair_passphrase.py`
- Test: `tests/test_keypair_rsa.py`
- Test: `tests/test_keypair_ssh.py`
- Test: `tests/test_keypair_pgp.py`

**Interfaces:**
- Consumes: None
- Produces:
  - `generate_passphrase(words_count: int, separator: str, capitalize: bool, include_numbers: bool, include_special: bool) -> str`
  - `RSAKeyPair(private_key_pem: str, public_key_pem: str)`
  - `generate_rsa_keypair(key_size: int, password: str | None) -> RSAKeyPair`
  - `SSHKeyPair(private_key: str, public_key: str, key_type: str)`
  - `generate_ssh_keypair(key_type: str, key_size: int, password: str | None, comment: str) -> SSHKeyPair`
  - `PGPKeyPair(private_key: str, public_key: str, fingerprint: str)`
  - `generate_pgp_key(name: str, email: str, comment: str, key_type: str, key_size: int, expire_years: int, passphrase: str | None) -> PGPKeyPair`
  - `GPGNotInstalledError`

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_keypair_passphrase.py
from ittools.core.keypair.passphrase import generate_passphrase

def test_generate_passphrase_defaults():
    phrase = generate_passphrase(words_count=4, separator="-")
    words = phrase.split("-")
    assert len(words) == 4
    assert phrase == phrase.lower()

def test_generate_passphrase_options():
    phrase = generate_passphrase(words_count=3, separator="_", capitalize=True, include_numbers=True, include_special=True)
    words = phrase.split("_")
    assert len(words) == 3
    assert any(c.isupper() for c in phrase)
    assert any(c.isdigit() for c in phrase)
```

```python
# tests/test_keypair_rsa.py
from ittools.core.keypair.rsa import generate_rsa_keypair
from cryptography.hazmat.primitives import serialization

def test_generate_rsa_keypair_unencrypted():
    pair = generate_rsa_keypair(key_size=2048)
    assert "BEGIN RSA PRIVATE KEY" in pair.private_key_pem or "BEGIN PRIVATE KEY" in pair.private_key_pem
    assert "BEGIN PUBLIC KEY" in pair.public_key_pem

def test_generate_rsa_keypair_encrypted():
    pair = generate_rsa_keypair(key_size=2048, password="secretpassword")
    assert "ENCRYPTED" in pair.private_key_pem or "BEGIN ENCRYPTED PRIVATE KEY" in pair.private_key_pem
    # Loading with wrong password fails
    try:
        serialization.load_pem_private_key(pair.private_key_pem.encode(), password=b"wrong")
        assert False, "Should have failed with wrong password"
    except (ValueError, TypeError):
        pass
```

```python
# tests/test_keypair_ssh.py
from ittools.core.keypair.ssh import generate_ssh_keypair

def test_generate_ssh_ed25519():
    pair = generate_ssh_keypair(key_type="ed25519", comment="user@example.com")
    assert "BEGIN OPENSSH PRIVATE KEY" in pair.private_key
    assert pair.public_key.startswith("ssh-ed25519 ")
    assert pair.public_key.endswith("user@example.com")

def test_generate_ssh_rsa():
    pair = generate_ssh_keypair(key_type="rsa", key_size=2048, comment="rsa-key")
    assert "BEGIN OPENSSH PRIVATE KEY" in pair.private_key
    assert pair.public_key.startswith("ssh-rsa ")
```

```python
# tests/test_keypair_pgp.py
import shutil
import pytest
from ittools.core.keypair.pgp import generate_pgp_key, GPGNotInstalledError

def test_generate_pgp_key():
    if not shutil.which("gpg"):
        with pytest.raises(GPGNotInstalledError):
            generate_pgp_key(name="Alice", email="alice@example.com")
    else:
        key = generate_pgp_key(name="Alice", email="alice@example.com", key_size=2048)
        assert "-----BEGIN PGP PRIVATE KEY BLOCK-----" in key.private_key
        assert "-----BEGIN PGP PUBLIC KEY BLOCK-----" in key.public_key
        assert len(key.fingerprint) > 0
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/test_keypair_*.py -v`
Expected: FAIL with `ModuleNotFoundError`

- [ ] **Step 3: Write minimal implementation**

Implement `src/ittools/core/keypair/passphrase.py`:
- Use `secrets.choice` with a list of common English words (min 200 words embedded or loaded).
- Append random digit if `include_numbers`, special character if `include_special`.
- Capitalize words if `capitalize` is True.

Implement `src/ittools/core/keypair/rsa.py`:
- Use `cryptography.hazmat.primitives.asymmetric.rsa.generate_private_key(public_exponent=65537, key_size=key_size)`.
- If `password` is given, serialize using `serialization.BestAvailableEncryption(password.encode())`, else `serialization.NoEncryption()`.
- Export PKCS#8 or PKCS#1 private key and SubjectPublicKeyInfo public key.

Implement `src/ittools/core/keypair/ssh.py`:
- For `ed25519`: `ed25519.Ed25519PrivateKey.generate()`.
- For `rsa`: `rsa.generate_private_key(65537, key_size)`.
- Serialize private key to OpenSSH PEM format with `serialization.PrivateFormat.OpenSSH`.
- Serialize public key to OpenSSH format with `serialization.PublicFormat.OpenSSH`.

Implement `src/ittools/core/keypair/pgp.py`:
- Check `shutil.which("gpg")`. If None, raise `GPGNotInstalledError("System gpg binary is not installed.")`.
- Use `tempfile.TemporaryDirectory()`, initialize `gnupg.GPG(gnupghome=temp_dir)`.
- Call `gpg.gen_key_input()` and `gpg.gen_key()`.
- Export ASCII armored private and public keys.

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/test_keypair_*.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/ittools/core/keypair/ tests/test_keypair_*.py
git commit -m "feat(core): implement keypair generation services (passphrase, rsa, ssh, pgp)"
```

---

### Task 3: Core PKI Services (CSR Generate/Decode & Key/Cert Matcher)

**Files:**
- Create: `src/ittools/core/pki/__init__.py`
- Create: `src/ittools/core/pki/csr.py`
- Create: `src/ittools/core/pki/matcher.py`
- Test: `tests/test_pki_csr.py`
- Test: `tests/test_pki_matcher.py`

**Interfaces:**
- Consumes: `generate_rsa_keypair` from `core.keypair.rsa`
- Produces:
  - `CSRSubject(common_name: str, organization: str, organizational_unit: str, city: str, state: str, country: str, email: str)`
  - `CSRResult(private_key_pem: str, csr_pem: str, sanitized_cn: str)`
  - `CSRDetails(common_name: str, organization: str, country: str, sans: list[str], key_type: str, key_size: int, signature_algorithm: str)`
  - `generate_csr(subject: CSRSubject, sans: list[str] | None, key_size: int) -> CSRResult`
  - `decode_csr(csr_pem: str) -> CSRDetails`
  - `sanitize_name(cn: str) -> str`
  - `MatchResult(matched: bool, key_hash: str, cert_hash: str, message: str)`
  - `match_key_and_cert(private_key_pem: str, cert_or_csr_pem: str) -> MatchResult`

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_pki_csr.py
from ittools.core.pki.csr import CSRSubject, generate_csr, decode_csr, sanitize_name

def test_sanitize_name():
    assert sanitize_name("example.com") == "example.com"
    assert sanitize_name("*.example.com") == "wildcard.example.com"
    assert sanitize_name("*.sub.domain.co") == "wildcard.sub.domain.co"

def test_generate_and_decode_csr():
    subj = CSRSubject(
        common_name="example.com",
        organization="Acme Corp",
        organizational_unit="SecOps",
        city="Hanoi",
        state="Hanoi",
        country="VN",
        email="admin@example.com"
    )
    result = generate_csr(subj, sans=["example.com", "www.example.com"], key_size=2048)
    assert "-----BEGIN RSA PRIVATE KEY-----" in result.private_key_pem or "-----BEGIN PRIVATE KEY-----" in result.private_key_pem
    assert "-----BEGIN CERTIFICATE REQUEST-----" in result.csr_pem
    assert result.sanitized_cn == "example.com"

    details = decode_csr(result.csr_pem)
    assert details.common_name == "example.com"
    assert details.organization == "Acme Corp"
    assert details.country == "VN"
    assert "www.example.com" in details.sans
    assert details.key_size == 2048
```

```python
# tests/test_pki_matcher.py
from ittools.core.pki.csr import CSRSubject, generate_csr
from ittools.core.pki.matcher import match_key_and_cert

def test_match_key_and_csr_success():
    subj = CSRSubject(common_name="test.com")
    res1 = generate_csr(subj, key_size=2048)
    match = match_key_and_cert(res1.private_key_pem, res1.csr_pem)
    assert match.matched is True
    assert match.key_hash == match.cert_hash

def test_match_key_and_csr_mismatch():
    res1 = generate_csr(CSRSubject(common_name="test1.com"), key_size=2048)
    res2 = generate_csr(CSRSubject(common_name="test2.com"), key_size=2048)
    match = match_key_and_cert(res1.private_key_pem, res2.csr_pem)
    assert match.matched is False
    assert match.key_hash != match.cert_hash
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/test_pki_*.py -v`
Expected: FAIL with `ModuleNotFoundError`

- [ ] **Step 3: Write minimal implementation**

Implement `src/ittools/core/pki/csr.py`:
- `sanitize_name(cn: str) -> str`: replace `*` with `wildcard`, replace path-unsafe chars.
- `generate_csr(subject, sans, key_size)`:
  - Generate RSA key with `cryptography.hazmat.primitives.asymmetric.rsa`.
  - Build `x509.CertificateRequestBuilder` using `x509.Name` attributes (`COMMON_NAME`, `ORGANIZATION_NAME`, `ORGANIZATIONAL_UNIT_NAME`, `LOCALITY_NAME`, `STATE_OR_PROVINCE_NAME`, `COUNTRY_NAME`, `EMAIL_ADDRESS`).
  - Add `x509.SubjectAlternativeName` if `sans` provided.
  - Add Key Usage (Digital Signature, Key Encipherment) and Extended Key Usage (Server Auth, Client Auth) matching Go implementation.
  - Sign CSR using SHA256 and serialize to PEM.
- `decode_csr(csr_pem)`:
  - Load with `x509.load_pem_x509_csr`.
  - Parse attributes and extensions (SANs).
  - Return `CSRDetails`.

Implement `src/ittools/core/pki/matcher.py`:
- Extract public key bytes from private key using `key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)`.
- Extract public key bytes from certificate/CSR using `cert_or_csr.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)`.
- Compare SHA256 hashes of the public key bytes.
- Return `MatchResult(matched, key_hash, cert_hash, message)`.

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/test_pki_*.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/ittools/core/pki/ tests/test_pki_*.py
git commit -m "feat(core): implement PKI CSR generator, decoder, and key/cert matcher"
```

---

### Task 4: Core SSL/TLS Network Inspector & Security Headers

**Files:**
- Create: `src/ittools/core/ssl_check/__init__.py`
- Create: `src/ittools/core/ssl_check/checker.py`
- Create: `src/ittools/core/ssl_check/headers.py`
- Test: `tests/test_ssl_checker.py`
- Test: `tests/test_ssl_headers.py`

**Interfaces:**
- Consumes: None
- Produces:
  - `SSLReport(host: str, port: int, subject: str, issuer: str, valid_from: str, valid_to: str, days_remaining: int, is_expired: bool, sans: list[str], tls_version: str, cipher_suite: str, warning: str | None)`
  - `check_remote_ssl(host: str, port: int = 443, timeout: float = 10.0) -> SSLReport`
  - `HeadersReport(url: str, status_code: int, present_headers: dict[str, str], missing_headers: list[str], security_score: str, recommendations: list[str])`
  - `check_security_headers(url: str, timeout: float = 10.0) -> HeadersReport`

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_ssl_checker.py
import datetime
from unittest.mock import patch, MagicMock
from ittools.core.ssl_check.checker import check_remote_ssl, SSLReport

def test_check_remote_ssl_logic():
    # Test with mock TLS socket returning dummy peer cert
    with patch("ittools.core.ssl_check.checker._fetch_peer_cert_and_info") as mock_fetch:
        mock_fetch.return_value = {
            "subject": "CN=example.com",
            "issuer": "CN=DigiCert Global Root CA",
            "valid_from": "2026-01-01T00:00:00Z",
            "valid_to": (datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=60)).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "days_remaining": 60,
            "is_expired": False,
            "sans": ["example.com", "www.example.com"],
            "tls_version": "TLSv1.3",
            "cipher_suite": "TLS_AES_256_GCM_SHA384"
        }
        report = check_remote_ssl("example.com")
        assert report.host == "example.com"
        assert report.days_remaining == 60
        assert report.is_expired is False
        assert "www.example.com" in report.sans
        assert report.warning is None
```

```python
# tests/test_ssl_headers.py
from unittest.mock import patch, MagicMock
from ittools.core.ssl_check.headers import check_security_headers

def test_check_security_headers_present_and_missing():
    with patch("requests.get") as mock_get:
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.headers = {
            "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
            "X-Frame-Options": "DENY"
        }
        mock_get.return_value = mock_resp

        report = check_security_headers("https://example.com")
        assert "Strict-Transport-Security" in report.present_headers
        assert "X-Frame-Options" in report.present_headers
        assert "Content-Security-Policy" in report.missing_headers
        assert len(report.recommendations) > 0
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/test_ssl_*.py -v`
Expected: FAIL with `ModuleNotFoundError`

- [ ] **Step 3: Write minimal implementation**

Implement `src/ittools/core/ssl_check/checker.py`:
- Use `ssl.create_default_context()` and `socket.create_connection((host, port), timeout=timeout)`.
- Connect and wrap socket with TLS: `context.wrap_socket(sock, server_hostname=host)`.
- Retrieve DER certificate: `ssock.getpeercert(binary_form=True)`.
- Load certificate using `x509.load_der_x509_certificate(der)`.
- Compute `valid_from` (`cert.not_valid_before_utc`), `valid_to` (`cert.not_valid_after_utc`), and `days_remaining = (valid_to - now).days`.
- Set warning if `days_remaining < 30` or `is_expired`.
- Extract cipher and TLS version from `ssock.cipher()`, `ssock.version()`.

Implement `src/ittools/core/ssl_check/headers.py`:
- Target standard headers: `Strict-Transport-Security`, `Content-Security-Policy`, `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`, `Permissions-Policy`.
- Perform `requests.get(url, timeout=timeout, allow_redirects=True)`.
- Check case-insensitively which headers exist and which are missing.
- Generate security score (e.g. A, B, C, D, F) based on percentage of present headers.
- Return `HeadersReport`.

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/test_ssl_*.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/ittools/core/ssl_check/ tests/test_ssl_*.py
git commit -m "feat(core): implement remote SSL cert checker and HTTP security headers analyzer"
```

---

### Task 5: Core Server TLS Config Generator

**Files:**
- Create: `src/ittools/core/config_gen/__init__.py`
- Create: `src/ittools/core/config_gen/generator.py`
- Test: `tests/test_config_gen.py`

**Interfaces:**
- Consumes: None
- Produces: `generate_server_config(server: str, profile: str, domain: str, cert_path: str, key_path: str, hsts: bool = True) -> str`

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_config_gen.py
from ittools.core.config_gen.generator import generate_server_config

def test_generate_nginx_config():
    cfg = generate_server_config(
        server="nginx",
        profile="intermediate",
        domain="example.com",
        cert_path="/etc/ssl/certs/example.com.crt",
        key_path="/etc/ssl/private/example.com.key",
        hsts=True
    )
    assert "server_name example.com;" in cfg
    assert "ssl_certificate /etc/ssl/certs/example.com.crt;" in cfg
    assert "ssl_certificate_key /etc/ssl/private/example.com.key;" in cfg
    assert "Strict-Transport-Security" in cfg

def test_generate_apache_config():
    cfg = generate_server_config(server="apache", domain="example.com", cert_path="/etc/cert.pem", key_path="/etc/key.pem")
    assert "<VirtualHost *:443>" in cfg
    assert "SSLEngine on" in cfg
    assert "ServerName example.com" in cfg

def test_generate_caddy_config():
    cfg = generate_server_config(server="caddy", domain="example.com", cert_path="/etc/cert.pem", key_path="/etc/key.pem")
    assert "example.com {" in cfg
    assert "tls /etc/cert.pem /etc/key.pem" in cfg
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/test_config_gen.py -v`
Expected: FAIL with `ModuleNotFoundError`

- [ ] **Step 3: Write minimal implementation**

Implement `src/ittools/core/config_gen/generator.py`:
- Support Mozilla SSL Modern and Intermediate guidelines.
- For Nginx: configure `listen 443 ssl http2;`, TLS protocols, safe cipher lists, session caching, and optional HSTS header.
- For Apache: configure `<VirtualHost *:443>`, `SSLCertificateFile`, `SSLCertificateKeyFile`, `SSLProtocol`, `SSLCipherSuite`.
- For Caddy: configure standard Caddyfile block with `tls <cert> <key>`.
- Raise `ValueError` if unsupported `server` or `profile` is requested.

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/test_config_gen.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/ittools/core/config_gen/ tests/test_config_gen.py
git commit -m "feat(core): implement server TLS configuration generator (nginx, apache, caddy)"
```

---

### Task 6: CLI Subcommand Dispatch & Commands

**Files:**
- Create: `src/ittools/cli/prompt.py`
- Create: `src/ittools/cli/commands/__init__.py`
- Create: `src/ittools/cli/commands/csr.py`
- Create: `src/ittools/cli/commands/keypair.py`
- Create: `src/ittools/cli/commands/ssl.py`
- Create: `src/ittools/cli/commands/config.py`
- Create: `src/ittools/cli/main.py`
- Test: `tests/test_cli.py`

**Interfaces:**
- Consumes: All `ittools.core.*` services
- Produces: `ittools.cli.main.main(args=None) -> int` console script entrypoint

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_cli.py
from ittools.cli.main import main

def test_cli_help(capsys):
    ret = main(["--help"])
    assert ret == 0
    captured = capsys.readouterr()
    assert "ittools" in captured.out
    assert "csr" in captured.out
    assert "keypair" in captured.out
    assert "ssl" in captured.out
    assert "config" in captured.out

def test_cli_passphrase(capsys):
    ret = main(["keypair", "passphrase", "--words", "3", "--sep", "_"])
    assert ret == 0
    captured = capsys.readouterr()
    assert len(captured.out.strip().split("_")) == 3

def test_cli_csr_generate_non_interactive(tmp_path, capsys):
    out_dir = str(tmp_path / "output")
    ret = main(["csr", "generate", "--cn", "test.example.com", "--country", "VN", "--output-dir", out_dir])
    assert ret == 0
    captured = capsys.readouterr()
    assert "CERTIFICATE REQUEST" in captured.out
    assert (tmp_path / "output" / "test.example.com" / "test.example.com.key").exists()
    assert (tmp_path / "output" / "test.example.com" / "test.example.com.csr").exists()

def test_cli_config_generate(capsys):
    ret = main(["config", "generate", "--server", "nginx", "--domain", "mytest.com"])
    assert ret == 0
    captured = capsys.readouterr()
    assert "server_name mytest.com;" in captured.out
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/test_cli.py -v`
Expected: FAIL with `ModuleNotFoundError`

- [ ] **Step 3: Write minimal implementation**

Implement `src/ittools/cli/prompt.py`:
- Helper to prompt for Common Name, Organization, Country, etc., if `csr generate` has no arguments.
Implement `src/ittools/cli/commands/csr.py`:
- `csr generate` and `csr decode`. Handle file writing with `os.open(..., 0o600)` for keys, stdout printing, overwrite guard with `--force`.
Implement `src/ittools/cli/commands/keypair.py`:
- Subparsers for `passphrase`, `rsa`, `ssh`, `pgp`.
Implement `src/ittools/cli/commands/ssl.py`:
- Subparsers for `check`, `headers`, `match`. Support `--json` flag and appropriate exit codes (`0`, `1`, `2`, `3`).
Implement `src/ittools/cli/commands/config.py`:
- `config generate` parser and handler.
Implement `src/ittools/cli/main.py`:
- Top-level `argparse.ArgumentParser(prog="ittools")` dispatching to command modules.
- Return exit code `int`.

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/test_cli.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/ittools/cli/ tests/test_cli.py
git commit -m "feat(cli): implement full ittools CLI subcommand routing and commands"
```

---

### Task 7: End-to-End Verification & Documentation Update

**Files:**
- Modify: `README.md`
- Test: Full pytest suite (`pytest tests/ --cov=ittools`)

**Interfaces:**
- Consumes: Complete `ittools` package
- Produces: Updated comprehensive documentation with Python installation, usage commands, and verified test suite.

- [ ] **Step 1: Write updated README.md**

Update `README.md` to document:
- Installation via `pip install -e .`
- Quickstart examples for `ittools csr generate`, `ittools csr decode`, `ittools keypair`, `ittools ssl check`, `ittools ssl headers`, `ittools ssl match`, and `ittools config generate`.
- Developer testing instructions (`pytest tests/`).

- [ ] **Step 2: Run full test suite with coverage**

Run: `pytest tests/ -v`
Expected: All tests pass (100% pass rate).

- [ ] **Step 3: Perform live CLI sanity checks**

Run manual test commands:
```bash
ittools --help
ittools keypair passphrase --words 4 --sep -
ittools config generate --server nginx --domain demo.local
```
Expected: Clean outputs, exit code 0.

- [ ] **Step 4: Commit**

```bash
git add README.md
git commit -m "docs: update README with python ittools installation and CLI usage"
```
