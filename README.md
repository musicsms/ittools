# ittools

A command-line toolkit of IT, PKI, and SSL/TLS utilities organized as subcommands (similar to `git` or `kubectl`).

`ittools` provides standard, reliable utilities for TLS certificate generation and decoding, PKCS#12 (PFX) container creation and extraction, Microsoft Active Directory Certificate Services (ADCS) Web Enrollment, cryptographic keypair creation (RSA, OpenSSH, PGP, and secure passphrases), remote SSL/TLS certificate and HTTP security header inspection, certificate/key matching, and hardened server TLS configuration generation adhering to Mozilla recommendations.

---

## Table of Contents

- [Quick Reference](#quick-reference)
- [End-to-End Enterprise Workflow](#end-to-end-enterprise-workflow)
- [Installation](#installation)
  - [Prerequisites](#prerequisites)
  - [Install with pip](#install-with-pip)
  - [Run Without Installing](#run-without-installing)
- [CLI Architecture & Security](#cli-architecture--security)
  - [Global Options](#global-options)
  - [Security Guarantees & File Permissions](#security-guarantees--file-permissions)
  - [Standard Exit Codes](#standard-exit-codes)
- [Subcommands Reference](#subcommands-reference)
  - [PKI & CSR (`ittools csr`)](#pki--csr-ittools-csr)
    - [`csr generate`](#csr-generate)
    - [`csr decode`](#csr-decode)
  - [PKCS#12 Archives (`ittools pfx`)](#pkcs12-archives-ittools-pfx)
    - [`pfx create`](#pfx-create)
    - [`pfx extract`](#pfx-extract)
  - [Active Directory Certificate Services (`ittools adcs`)](#active-directory-certificate-services-ittools-adcs)
    - [`adcs sign`](#adcs-sign)
    - [`adcs retrieve`](#adcs-retrieve)
    - [`adcs ca-cert`](#adcs-ca-cert)
  - [Cryptographic Keypairs (`ittools keypair`)](#cryptographic-keypairs-ittools-keypair)
    - [`keypair passphrase`](#keypair-passphrase)
    - [`keypair rsa`](#keypair-rsa)
    - [`keypair ssh`](#keypair-ssh)
    - [`keypair pgp`](#keypair-pgp)
  - [SSL/TLS Inspection & Verification (`ittools ssl`)](#ssltls-inspection--verification-ittools-ssl)
    - [`ssl check`](#ssl-check)
    - [`ssl headers`](#ssl-headers)
    - [`ssl match`](#ssl-match)
  - [Hardened Server TLS Config (`ittools config`)](#hardened-server-tls-config-ittools-config)
    - [`config generate`](#config-generate)
- [Model Context Protocol (MCP) Server (`ittools mcp`)](#model-context-protocol-mcp-server-ittools-mcp)
  - [Overview & Assistant Integration](#overview--assistant-integration)
  - [Running the MCP Server](#running-the-mcp-server)
  - [Client Configuration](#client-configuration)
    - [Claude Desktop](#claude-desktop)
    - [Cursor](#cursor)
    - [Google Antigravity](#google-antigravity)
    - [VS Code / Windsurf / Generic Clients](#vs-code--windsurf--generic-clients)
  - [MCP Tools Reference](#mcp-tools-reference)
  - [Security & In-Memory Guarantees](#security--in-memory-guarantees)
- [Development & Testing](#development--testing)
  - [Running Tests](#running-tests)
  - [Project Structure](#project-structure)
- [License](#license)

---

## Quick Reference

| Command | Subcommand | Purpose | Key Flags |
|---|---|---|---|
| `ittools csr` | `generate` | Generate RSA private key & PKCS#10 CSR | `--cn`, `--san`, `--org`, `--key-size`, `--force` |
| `ittools csr` | `decode` | Inspect & decode PEM CSR details | `--in` (or stdin) |
| `ittools pfx` | `create` | Bundle private key, certificate, and CA chain into `.pfx` | `--key`, `--cert`, `--ca`, `--out`, `--password`, `--no-password` |
| `ittools pfx` | `extract` | Extract key (0600 mode), cert, and CA chain from `.pfx` | `--in`, `--password`, `--out-dir`, `--key-out`, `--cert-out` |
| `ittools adcs` | `sign` | Submit CSR to Microsoft ADCS & download cert (optional PFX) | `--server`, `--csr`, `--template`, `--username`, `--key`, `--out-pfx` |
| `ittools adcs` | `retrieve` | Download approved certificate by Request ID (optional PFX) | `--server`, `--req-id`, `--username`, `--key`, `--out-pfx` |
| `ittools adcs` | `ca-cert` | Download Enterprise CA certificate chain (`.p7b`) | `--server`, `--username`, `--out` |
| `ittools keypair` | `passphrase` | Generate EFF-style cryptographic passphrase | `--words`, `--sep`, `--capitalize`, `--numbers`, `--special` |
| `ittools keypair` | `rsa` | Generate PKCS#8 RSA keypair (2048/3072/4096-bit) | `--size`, `--password`, `--out`, `--force` |
| `ittools keypair` | `ssh` | Generate OpenSSH keypair (Ed25519 or RSA) | `--type`, `--size`, `--comment`, `--password`, `--out` |
| `ittools keypair` | `pgp` | Generate ASCII-armored PGP keypair via GnuPG | `--name`, `--email`, `--comment`, `--expire`, `--out-dir` |
| `ittools ssl` | `check` | Inspect remote TLS endpoint validity, cipher & expiration | `host`, `--port`, `--timeout`, `--json` |
| `ittools ssl` | `headers` | Audit and score HTTP security response headers | `url`, `--timeout`, `--json` |
| `ittools ssl` | `match` | Verify private key matches public cert or CSR | `--key`, `--cert`, `--password` |
| `ittools config` | `generate` | Generate Mozilla TLS config for Nginx, Apache, Caddy | `--server`, `--profile`, `--domain`, `--cert`, `--key`, `--no-hsts` |
| `ittools mcp` | - | Run native Model Context Protocol (MCP) server for AI assistants | `--transport {stdio,sse}`, `--port` |

---

## End-to-End Enterprise Workflow

`ittools` simplifies the full certificate lifecycle into a unified, secure toolchain:

```bash
# 1. Generate CSR and 2048-bit RSA Private Key
ittools csr generate \
  --cn "api.corp.local" \
  --org "Enterprise IT" \
  --san "api.corp.local,api-backup.corp.local" \
  --output-dir ./output

# 2. Submit CSR to Microsoft ADCS, download cert, and directly assemble a PFX bundle in one step
ittools adcs sign \
  --server ca.corp.local \
  --csr output/api.corp.local/api.corp.local.csr \
  --key output/api.corp.local/api.corp.local.key \
  --out output/api.corp.local/api.corp.local.cer \
  --out-pfx output/api.corp.local/api.corp.local.pfx \
  --pfx-password "SecretPass123" \
  --name "API Server Certificate" \
  --username "CORP\admin"

# 3. Deploy to server: Extract components with secure 0600 private key permissions
ittools pfx extract \
  --in output/api.corp.local/api.corp.local.pfx \
  --password "SecretPass123" \
  --out-dir /etc/ssl/myapp

# 4. Generate hardened Nginx virtual host configuration block
ittools config generate \
  --server nginx \
  --profile intermediate \
  --domain api.corp.local \
  --cert /etc/ssl/myapp/api.corp.local.crt \
  --key /etc/ssl/myapp/api.corp.local.key \
  --out /etc/nginx/sites-available/api.conf

# 5. Verify live deployment and security posture
ittools ssl check api.corp.local
ittools ssl headers https://api.corp.local
```

---

## Installation

### Prerequisites

- **Python:** 3.10 or higher
- **GnuPG:** `gpg` binary installed on system `PATH` (only required for `ittools keypair pgp`)

### Install with pip

Clone the repository and install in editable mode:

```bash
git clone https://github.com/musicsms/ittools.git
cd ittools

# Recommended: create and activate a virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install ittools in editable mode
pip install -e .
```

To install development dependencies (e.g. `pytest`):

```bash
pip install -e ".[dev]"
```

To enable NTLM authentication for Active Directory ADCS enrollment:

```bash
pip install -e ".[ntlm]"
# or directly:
pip install requests-ntlm
```

To install with Model Context Protocol (MCP) server support:

```bash
pip install -e ".[mcp]"
```

To install all optional dependencies (NTLM authentication and MCP server):

```bash
pip install -e ".[all]"
```

*Note on Debian/Ubuntu/Kali (PEP 668 externally-managed environments):* If installing into system/user Python outside a virtual environment, pass `--break-system-packages`:
```bash
pip install -e . --break-system-packages
```

### Run Without Installing

You can also run commands directly using Python's module syntax without installing to `PATH`:

```bash
python3 -m ittools.cli.main --help
```

---

## CLI Architecture & Security

```
ittools [--debug] <command> <subcommand> [options]
```

### Global Options

- `--help`, `-h`: Show help and usage for any command or subcommand.
- `--debug`: Print full Python tracebacks when an unhandled error or exception occurs (default: writes clean, user-facing error message to stderr).

### Security Guarantees & File Permissions

- **Restrictive Private Key Permissions (`0600`)**: All private key files written to disk (`.key`, `private.asc`, and keys extracted from `.pfx` archives) are created with `os.open` using `0o600` (`-rw-------`), ensuring only the owner can read them.
- **Upfront Overwrite Protection**: Destructive overwrites are prevented by default. All target destination paths are inspected upfront before performing network calls or generating keys. Pass `--force` to explicitly permit overwriting existing files.
- **Interactive Password Masking**: Sensitive passwords (for PFX archives, encrypted private keys, and Active Directory authentication) can be omitted from command line history and entered securely via `getpass` prompts.

### Standard Exit Codes

| Exit Code | Meaning | Context |
|---|---|---|
| `0` | Success | Command completed successfully; checks passed. |
| `1` | Validation / User Error | Invalid arguments, missing required fields, rejected CSR, or output file collision without `--force`. |
| `2` | Network / Connection Error | Remote host unreachable, DNS lookup failed, ADCS connection failure, or connection timed out. |
| `3` | Security Warning / Mismatch / Approval Pending | Remote SSL certificate expired or expiring within 30 days (`ssl check`), private key and certificate mismatch (`ssl match`), or ADCS certificate request pending CA administrator approval (`adcs sign`). |

---

## Subcommands Reference

### PKI & CSR (`ittools csr`)

Generate and inspect PKCS#10 Certificate Signing Requests and associated private keys.

#### `csr generate`

Generates an RSA private key and a PKCS#10 CSR. Can run non-interactively via flags or interactively when flags are omitted.

```bash
ittools csr generate [options]
```

**Options:**
- `--cn CN`: Common Name / FQDN (e.g., `example.com` or `*.example.com`). Required in non-interactive mode.
- `--org ORG`: Organization name.
- `--ou OU`: Organizational Unit.
- `--city CITY`: Locality / City.
- `--state STATE`: State / Province.
- `--country COUNTRY`: Two-letter ISO country code (e.g., `US`, `FR`, `VN`). Normalized to uppercase.
- `--email EMAIL`: Contact email address.
- `--san SAN`: Comma-separated Subject Alternative Names (e.g., `example.com,www.example.com`).
- `--key-size KEY_SIZE`: RSA key length: `2048` (default), `3072`, or `4096`.
- `--output-dir OUTPUT_DIR`: Target directory (default: `./output`).
- `--force`: Overwrite existing output files if they already exist.

**Example (Non-interactive):**
```bash
ittools csr generate \
  --cn "api.example.com" \
  --org "Acme Corporation" \
  --country "US" \
  --san "api.example.com,api-backup.example.com" \
  --key-size 2048
```

Output files are written under `./output/<sanitized-cn>/` (e.g. `./output/api.example.com/api.example.com.key` and `./output/api.example.com/api.example.com.csr`). Private key files are written with secure `0600` permissions.

**Example (Interactive):**
```bash
ittools csr generate
```
Prompts sequentially for Common Name, Organization, Unit, City, State, Country, Email, SANs, and Key Size.

#### `csr decode`

Decodes and displays the details of a PEM-encoded Certificate Signing Request from a file or standard input.

```bash
ittools csr decode [--in <file>]
```

**Examples:**
```bash
# Read from file
ittools csr decode --in output/api.example.com/api.example.com.csr

# Read from stdin / pipe
cat output/api.example.com/api.example.com.csr | ittools csr decode
```

Displays Common Name, Organization, Country, SANs, Key Type & Size, and Signature Algorithm.

---

### PKCS#12 Archives (`ittools pfx`)

Create and extract PKCS#12 (`.pfx` / `.p12`) archives containing private keys, certificates, and CA certificate bundles using industrial-grade PBES2 AES-256-CBC encryption.

#### `pfx create`

Bundles a private key PEM file and a certificate PEM file (with optional CA certificate chain) into an encrypted or unencrypted `.pfx` container.

```bash
ittools pfx create --key <key.pem> --cert <cert.pem> [options]
```

**Options:**
- `--key KEY`: Path to private key PEM file (required).
- `--cert CERT`: Path to certificate PEM file (required).
- `--ca CA`: Path to CA certificate PEM file or bundle to include in the archive.
- `--out OUT`: Output `.pfx` file path (default: `./output/<cert-stem>.pfx`).
- `--password PASSWORD`: Password protecting the PFX archive (if omitted and running interactively, prompts securely).
- `--no-password`: Do not encrypt the PFX container with a password.
- `--key-password KEY_PASSWORD`: Password to decrypt the input private key if encrypted.
- `--name NAME`: Friendly name / alias for the certificate inside the archive.
- `--force`: Overwrite existing output file.

**Examples:**
```bash
# Create password-protected PFX bundle with CA chain
ittools pfx create \
  --key server.key \
  --cert server.crt \
  --ca ca-bundle.crt \
  --out bundle.pfx \
  --password "SecretPassword123" \
  --name "Production Web"

# Create unencrypted PFX archive
ittools pfx create \
  --key server.key \
  --cert server.crt \
  --out server.pfx \
  --no-password
```

#### `pfx extract`

Extracts the private key, leaf certificate, and any bundled CA chain certificates from a PKCS#12 archive into separate PEM files. Extracted private keys are always saved with restrictive `0600` permissions.

```bash
ittools pfx extract --in <archive.pfx> [options]
```

**Options:**
- `--in IN_FILE`: Path to `.pfx` or `.p12` archive file (required).
- `--password PASSWORD`: Password for the PFX archive (prompts interactively if required).
- `--out-dir OUT_DIR`: Output directory for extracted components (default: `./output/<pfx-stem>`).
- `--key-out KEY_OUT`: Custom destination path for extracted private key PEM.
- `--cert-out CERT_OUT`: Custom destination path for extracted leaf certificate PEM.
- `--ca-out CA_OUT`: Custom destination path for extracted CA bundle PEM.
- `--force`: Overwrite existing output files.

**Examples:**
```bash
# Extract components to default directory (./output/bundle/)
ittools pfx extract --in bundle.pfx --password "SecretPassword123"
# Extracted:
#   ./output/bundle/bundle.key  (mode 0600)
#   ./output/bundle/bundle.crt
#   ./output/bundle/bundle-ca.crt

# Extract with custom output destinations
ittools pfx extract \
  --in bundle.pfx \
  --key-out /etc/ssl/private/app.key \
  --cert-out /etc/ssl/certs/app.crt \
  --ca-out /etc/ssl/certs/app-ca.crt \
  --force
```

---

### Active Directory Certificate Services (`ittools adcs`)

Interact with Microsoft Active Directory Certificate Services (ADCS) Web Enrollment (`/certsrv/certfnsh.asp`) to submit Certificate Signing Requests, retrieve issued certificates, and download the Enterprise CA certificate chain. Supports NTLM and Basic authentication, custom CA bundles, and an all-in-one PFX assembly pipeline.

#### `adcs sign`

Submits a PKCS#10 CSR to ADCS Web Enrollment and retrieves the issued certificate. If the request requires CA administrator approval, the command exits with code `3` and displays the assigned Request ID and the exact command to retrieve it once approved.

Using `--key` and `--out-pfx`, you can automatically combine the private key and newly signed certificate into a ready-to-deploy `.pfx` bundle in a single step.

```bash
ittools adcs sign --server <server> --csr <csr.pem> [options]
```

**Options:**
- `--server SERVER`: ADCS server FQDN or IP address (required, e.g. `ca.corp.local` or `192.168.1.10`).
- `--csr CSR`: Path to CSR PEM file, or `-` to read from standard input (required).
- `--template TEMPLATE`: Certificate template name (default: `WebServer`).
- `--username USERNAME`: Active Directory username (e.g. `CORP\admin` or `admin@corp.local`).
- `--password PASSWORD`: Active Directory user password (prompts securely if omitted interactively).
- `--auth {ntlm,basic}`: Authentication method: `ntlm` (default) or `basic`.
- `--ca-bundle CA_BUNDLE`: Custom CA certificate bundle to verify the ADCS server's HTTPS certificate.
- `--insecure`: Disable SSL verification for the ADCS server (for self-signed test environments).
- `--timeout TIMEOUT`: Network timeout in seconds (default: `30.0`).
- `--out OUT`: Output file path for issued certificate (default: `./output/issued.cer`).
- `--key KEY`: Path to matching private key file to assemble a PFX bundle.
- `--out-pfx OUT_PFX`: Output path for assembled PFX archive.
- `--pfx-password PFX_PASSWORD`: Password to encrypt the assembled PFX archive.
- `--name NAME`: Friendly name / alias for certificate in PFX.
- `--force`: Overwrite existing output files.

**Exit Codes:**
- `0`: Certificate successfully issued (and PFX assembled if requested).
- `1`: Validation error, rejected CSR, or authentication failure.
- `2`: Network connection error or timeout.
- `3`: Certificate request is pending CA administrator approval.

**Examples:**
```bash
# Standard certificate issuance
ittools adcs sign \
  --server ca.corp.local \
  --csr output/api.example.com/api.example.com.csr \
  --template WebServer \
  --username "CORP\admin" \
  --out output/api.example.com/api.example.com.cer

# All-in-one: Sign CSR and directly assemble PFX bundle
ittools adcs sign \
  --server ca.corp.local \
  --csr output/api.example.com/api.example.com.csr \
  --key output/api.example.com/api.example.com.key \
  --out output/api.example.com/api.example.com.cer \
  --out-pfx output/api.example.com/api.example.com.pfx \
  --pfx-password "SecretPassphrase123" \
  --name "API Server Certificate" \
  --username "CORP\admin"

# Piping CSR from stdin
cat server.csr | ittools adcs sign --server ca.corp.local --csr - --username "CORP\admin"
```

#### `adcs retrieve`

Retrieves a previously submitted certificate from ADCS using its Request ID (e.g., after CA administrator approval). Can also assemble a PFX bundle using `--key` and `--out-pfx`.

```bash
ittools adcs retrieve --server <server> --req-id <id> [options]
```

**Options:**
- `--server SERVER`: ADCS server FQDN or IP address (required).
- `--req-id REQ_ID`: ADCS Request ID (required).
- `--username USERNAME`: AD username.
- `--password PASSWORD`: AD password.
- `--auth {ntlm,basic}`: Authentication method: `ntlm` (default) or `basic`.
- `--ca-bundle CA_BUNDLE`: Custom CA certificate bundle.
- `--insecure`: Disable SSL verification.
- `--timeout TIMEOUT`: Network timeout in seconds (default: `30.0`).
- `--out OUT`: Output file path for retrieved certificate (default: `./output/req_<id>.cer`).
- `--key KEY`: Path to matching private key file to assemble a PFX bundle.
- `--out-pfx OUT_PFX`: Output path for assembled PFX archive.
- `--pfx-password PFX_PASSWORD`: Password for assembled PFX archive.
- `--name NAME`: Friendly name for certificate in PFX.
- `--force`: Overwrite existing output files.

**Example:**
```bash
# Retrieve approved certificate and assemble PFX
ittools adcs retrieve \
  --server ca.corp.local \
  --req-id 1042 \
  --key server.key \
  --out server.cer \
  --out-pfx server.pfx \
  --pfx-password "SecretPassphrase123" \
  --username "CORP\admin"
```

#### `adcs ca-cert`

Downloads the root or issuing CA certificate chain (`.p7b` PKCS#7 format) from Microsoft ADCS Web Enrollment.

```bash
ittools adcs ca-cert --server <server> [options]
```

**Options:**
- `--server SERVER`: ADCS server FQDN or IP address (required).
- `--username USERNAME`: AD username.
- `--password PASSWORD`: AD password.
- `--auth {ntlm,basic}`: Authentication method: `ntlm` (default) or `basic`.
- `--ca-bundle CA_BUNDLE`: Custom CA certificate bundle.
- `--insecure`: Disable SSL verification.
- `--timeout TIMEOUT`: Network timeout in seconds (default: `30.0`).
- `--out OUT`: Output file path (default: `./output/<server>_ca.p7b`).
- `--force`: Overwrite existing output file.

**Example:**
```bash
ittools adcs ca-cert --server ca.corp.local --username "CORP\admin" --out corp-ca.p7b
```

---

### Cryptographic Keypairs (`ittools keypair`)

Generate secure passphrases, RSA keypairs, OpenSSH keypairs, and PGP keypairs.

#### `keypair passphrase`

Generates a cryptographically strong multi-word passphrase from an embedded EFF-style wordlist.

```bash
ittools keypair passphrase [options]
```

**Options:**
- `--words WORDS`: Number of words (default: `4`).
- `--sep SEP`: Word separator character (default: `-`).
- `--capitalize`: Capitalize each word.
- `--numbers`: Append a random digit (0-9).
- `--special`: Append a random special character (`!@#$%^&*`).

**Examples:**
```bash
# Default (4 lowercase words, hyphen-separated)
ittools keypair passphrase
# Output: correct-horse-battery-staple

# 5 capitalized words with number and special character
ittools keypair passphrase --words 5 --sep "_" --capitalize --numbers --special
# Output: Velvet_Sunrise_Dragon_Cascade_Falcon7!
```

#### `keypair rsa`

Generates an RSA private and public keypair in PEM format (PKCS#8 private key, SubjectPublicKeyInfo public key).

```bash
ittools keypair rsa [options]
```

**Options:**
- `--size SIZE`: Key length: `2048` (default), `3072`, or `4096`.
- `--password PASSWORD`: Optional passphrase to encrypt the private key (AES-256-CBC).
- `--out OUT`: Base path for saving keys. Writes `<out>` (or `<out>.key`) and `<out>.pub`.
- `--force`: Overwrite existing output files.

**Examples:**
```bash
# Output both keys to stdout
ittools keypair rsa --size 2048

# Encrypt private key and save to disk
ittools keypair rsa --size 4096 --password "SecretPassphrase123" --out id_rsa
# Writes id_rsa (mode 0600) and id_rsa.pub (mode 0644)
```

#### `keypair ssh`

Generates an OpenSSH-compatible keypair (`ed25519` or `rsa`).

```bash
ittools keypair ssh [options]
```

**Options:**
- `--type {ed25519,rsa}`: Key algorithm: `ed25519` (default) or `rsa`.
- `--size SIZE`: Bit length for RSA keys (default: `2048`).
- `--comment COMMENT`: Comment appended to the OpenSSH public key (e.g. `user@host`).
- `--password PASSWORD`: Passphrase to encrypt the private key.
- `--out OUT`: Base path for output files. Writes `<out>` and `<out>.pub`.
- `--force`: Overwrite existing files.

**Examples:**
```bash
# Fast, modern Ed25519 keypair saved to ~/.ssh/mykey
ittools keypair ssh --type ed25519 --comment "deploy@server" --out ~/.ssh/mykey

# 4096-bit RSA SSH key with passphrase encryption
ittools keypair ssh --type rsa --size 4096 --password "SecurePass123" --out ~/.ssh/id_rsa_legacy
```

#### `keypair pgp`

Generates an ASCII-armored PGP keypair using the system GnuPG installation.

```bash
ittools keypair pgp --name NAME --email EMAIL [options]
```

**Options:**
- `--name NAME`: Full name / identity (required).
- `--email EMAIL`: Email address (required).
- `--comment COMMENT`: Optional comment string.
- `--expire EXPIRE`: Expiration in years (`0` for never, default: `1`).
- `--password PASSWORD`: Passphrase protecting the private key.
- `--out-dir OUT_DIR`: Directory to write `private.asc` and `public.asc`. If omitted, prints keys to stdout.
- `--force`: Overwrite existing files.

**Examples:**
```bash
# Print PGP keypair and fingerprint to stdout
ittools keypair pgp --name "Alice Smith" --email "alice@example.com"

# Save keys to a protected directory with 2-year expiration
ittools keypair pgp \
  --name "Bob Jones" \
  --email "bob@example.com" \
  --expire 2 \
  --password "GpgPassphrase456" \
  --out-dir ~/.gnupg/keys
```

---

### SSL/TLS Inspection & Verification (`ittools ssl`)

Inspect remote TLS endpoints, audit HTTP response security headers, and verify that private keys correspond to certificates or CSRs.

#### `ssl check`

Connects to a remote host over TLS, extracts the leaf certificate, and reports validity dates, issuer, cipher suite, protocol version, and expiration warnings. If the certificate is untrusted or self-signed, `ittools` gracefully falls back to an unverified TLS connection to inspect the certificate metadata while highlighting the chain validation status.

```bash
ittools ssl check <host> [options]
```

**Options:**
- `host`: Remote domain name or IP address.
- `--port PORT`: Port number (default: `443`).
- `--timeout TIMEOUT`: Connection timeout in seconds (default: `10.0`).
- `--json`: Output report as formatted JSON.

**Exit Codes:**
- `0`: Certificate is valid and has at least 30 days remaining.
- `2`: Network connection or resolution error.
- `3`: Certificate is expired or has fewer than 30 days remaining.

**Examples:**
```bash
# Human-readable check
ittools ssl check example.com

# Check alternative port with custom timeout
ittools ssl check internal.corp --port 8443 --timeout 5.0

# JSON output for automated scripting
ittools ssl check github.com --json
```

#### `ssl headers`

Queries an HTTP/HTTPS URL and grades security headers (HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy).

```bash
ittools ssl headers <url> [options]
```

**Options:**
- `url`: Target URL (e.g. `https://example.com` or `example.com`).
- `--timeout TIMEOUT`: Request timeout in seconds (default: `10.0`).
- `--json`: Output report as formatted JSON.

**Exit Codes:**
- `0`: Successful header analysis.
- `2`: Network connection or request failure.

**Examples:**
```bash
# Inspect headers
ittools ssl headers https://example.com

# Machine-readable output
ittools ssl headers https://example.com --json
```

#### `ssl match`

Verifies that a private key matches a public certificate or CSR by calculating and comparing their SHA-256 public key digests. Supports password-protected encrypted private keys.

```bash
ittools ssl match --key <private-key.pem> --cert <cert-or-csr.pem> [options]
```

**Options:**
- `--key KEY`: Path to PEM-encoded private key file (required).
- `--cert CERT`: Path to PEM-encoded certificate or CSR file (required).
- `--password PASSWORD`: Optional passphrase to decrypt private key if encrypted.

**Exit Codes:**
- `0`: Public key hashes match.
- `3`: Hashes do not match (keypair mismatch).

**Examples:**
```bash
# Check key matches CSR
ittools ssl match --key output/example.com/example.com.key --cert output/example.com/example.com.csr

# Check encrypted key matches certificate
ittools ssl match --key encrypted.key --cert server.crt --password "SecretPass123"
```

---

### Hardened Server TLS Config (`ittools config`)

Generate production-ready, hardened server TLS virtual host configurations adhering to [Mozilla's TLS Configuration Guidelines](https://ssl-config.mozilla.org/).

#### `config generate`

Generates virtual host blocks for Nginx, Apache HTTP Server, or Caddy with secure cipher suites, protocol settings, session cache, and HSTS headers.

```bash
ittools config generate --server <server> [options]
```

**Options:**
- `--server {nginx,apache,caddy}`: Target web server software (required).
- `--profile {intermediate,modern}`: Mozilla profile: `intermediate` (default, supports TLS 1.2 & 1.3) or `modern` (TLS 1.3 only).
- `--domain DOMAIN`: Domain name / server name (default: `example.com`).
- `--cert CERT`: Certificate file path (default: `/etc/ssl/certs/cert.pem`).
- `--key KEY`: Private key file path (default: `/etc/ssl/private/key.pem`).
- `--no-hsts`: Disable HTTP Strict Transport Security (`Strict-Transport-Security` header).
- `--out OUT`: Save configuration block directly to a file.
- `--force`: Overwrite existing output file.

**Examples:**
```bash
# Generate Nginx intermediate configuration
ittools config generate --server nginx --domain myapp.local

# Modern Apache configuration without HSTS saved to file
ittools config generate \
  --server apache \
  --profile modern \
  --domain secure.example.com \
  --cert /etc/pki/tls/certs/secure.crt \
  --key /etc/pki/tls/private/secure.key \
  --no-hsts \
  --out /etc/apache2/sites-available/secure.conf

# Caddy configuration
ittools config generate --server caddy --domain example.org
```

---

## Model Context Protocol (MCP) Server (`ittools mcp`)

`ittools` provides a native [Model Context Protocol (MCP)](https://modelcontextprotocol.io/) server subsystem that exposes all 15 IT, PKI, ADCS, Keypair, and SSL inspection capabilities directly as structured tools to AI models and coding assistants.

Assistants such as **Claude Desktop**, **Cursor**, **Google Antigravity**, **VS Code** (via Cline, Roo Code, or Continue), and **Windsurf** can invoke these tools to generate keys, create and extract PFX bundles, request certificates from Active Directory, audit SSL/TLS endpoints, and produce hardened configurations safely and reliably without shell parsing or custom glue scripts.

### Overview & Assistant Integration

Every MCP tool in `ittools` is implemented with:
- **In-Memory Payloads by Default**: Operations return pure PEM text, base64 blobs, and structured data dictionaries directly to the model context without forcing disk I/O.
- **Optional Safe Persistence**: Files are only written to disk when output paths or directories are explicitly passed by the assistant or user.
- **Strict 0600 Permissions**: Private keys and PFX archives are written with restrictive owner-only permissions (`0600`).
- **Non-Blocking Asynchronous ADCS**: ADCS requests requiring CA administrator approval return structured `pending` states with Request IDs for later retrieval, without raising exceptions or hanging agent turns.

### Installation

Install `ittools` with MCP server support:

```bash
pip install "ittools[mcp]"
```

Or install all optional dependencies (NTLM authentication for ADCS + MCP server):

```bash
pip install "ittools[all]"
```

### Running the MCP Server

`ittools` provides a built-in CLI command to start the MCP server:

```bash
# Standard input/output transport (default, recommended for local desktop clients)
ittools mcp

# Equivalent using module syntax
python3 -m ittools.cli.main mcp

# Server-Sent Events (SSE) HTTP transport (for containerized or network deployments)
ittools mcp --transport sse --port 8000
```

**Options:**
- `--transport {stdio,sse}`: Transport protocol (`stdio` default, or `sse`).
- `--port PORT`: Port for SSE HTTP transport (default: `8000`).

### Client Configuration

#### Claude Desktop

Add `ittools` to your `claude_desktop_config.json`:
- **macOS**: `~/Library/Application Support/Claude/claude_desktop_config.json`
- **Linux**: `~/.config/Claude/claude_desktop_config.json`
- **Windows**: `%APPDATA%\Claude\claude_desktop_config.json`

```json
{
  "mcpServers": {
    "ittools": {
      "command": "ittools",
      "args": ["mcp"]
    }
  }
}
```

*If using a dedicated Python virtual environment:*

```json
{
  "mcpServers": {
    "ittools": {
      "command": "/path/to/venv/bin/python3",
      "args": ["-m", "ittools.cli.main", "mcp"]
    }
  }
}
```

#### Cursor

Add `ittools` to your Cursor MCP configuration file (`.cursor/mcp.json`) or in **Cursor Settings > Features > MCP**:

```json
{
  "mcpServers": {
    "ittools": {
      "command": "ittools",
      "args": ["mcp"]
    }
  }
}
```

#### Google Antigravity

Configure `ittools` in your Antigravity project or user MCP configuration (`~/.gemini/antigravity/mcp_servers.json` or `.gemini/settings.json`):

```json
{
  "mcpServers": {
    "ittools": {
      "command": "ittools",
      "args": ["mcp"]
    }
  }
}
```

#### VS Code / Windsurf / Generic Clients

For VS Code extensions supporting MCP (such as **Cline**, **Roo Code**, or **Continue**) or **Windsurf**, add to the respective MCP settings file:

**Standard I/O (stdio):**
```json
{
  "mcpServers": {
    "ittools": {
      "command": "ittools",
      "args": ["mcp"]
    }
  }
}
```

**Remote / SSE Transport:**
If running `ittools mcp --transport sse --port 8000`, configure clients pointing to the SSE endpoint:
```json
{
  "mcpServers": {
    "ittools": {
      "url": "http://localhost:8000/sse"
    }
  }
}
```

### MCP Tools Reference

The `ittools` MCP server registers **15 native tools** covering PKI, cryptographic keypairs, SSL/TLS auditing, server hardening, and Active Directory enrollment:

| Tool Name | Category | Description | Key Parameters | Return Type |
|---|---|---|---|---|
| `csr_generate` | PKI | Generate RSA private key and PKCS#10 CSR | `common_name` *(req)*, `organization`, `organizational_unit`, `city`, `state`, `country`, `email`, `sans`, `key_size` (default: 2048), `output_dir`, `force` | `dict` (`common_name`, `private_key_pem`, `csr_pem`, `saved_files`) |
| `csr_decode` | PKI | Parse and inspect PEM Certificate Signing Request | `csr_pem` *(req)* | `dict` (`common_name`, `organization`, `country`, `sans`, `key_type`, `key_size`, `signature_algorithm`) |
| `pfx_create` | PKI | Bundle private key, certificate, and CA chain into PKCS#12 archive | `private_key_pem` *(req)*, `cert_pem` *(req)*, `ca_certs_pem`, `password`, `friendly_name`, `key_password`, `output_path`, `force` | `dict` (`pfx_base64`, `size_bytes`, `friendly_name`, `saved_to`) |
| `pfx_extract` | PKI | Extract private key (mode 0600), cert, and CA bundle from PFX archive | `pfx_data_or_path` *(req, base64 or file path)*, `password`, `output_dir`, `force` | `dict` (`private_key_pem`, `cert_pem`, `ca_certs_pem`, `friendly_name`, `saved_files`) |
| `ssl_match` | PKI / SSL | Verify whether a private key matches a certificate or CSR via SHA-256 digests | `private_key_pem` *(req)*, `cert_or_csr_pem` *(req)*, `password` | `dict` (`matched`, `key_hash`, `cert_hash`, `message`) |
| `keypair_passphrase` | Keypair | Generate EFF-style multi-word cryptographic passphrase | `words` (default: 4), `separator` (default: "-"), `capitalize`, `include_numbers`, `include_special` | `dict` (`passphrase`) |
| `keypair_rsa` | Keypair | Generate PKCS#8 RSA keypair (private mode 0600, public mode 0644) | `key_size` (default: 2048), `password`, `output_path`, `force` | `dict` (`private_key_pem`, `public_key_pem`, `saved_files`) |
| `keypair_ssh` | Keypair | Generate OpenSSH keypair (`ed25519` or `rsa`) | `key_type` (default: "ed25519"), `key_size`, `comment`, `password`, `output_path`, `force` | `dict` (`private_key`, `public_key`, `saved_files`) |
| `keypair_pgp` | Keypair | Generate ASCII-armored PGP keypair via GnuPG in isolated keyring | `name` *(req)*, `email` *(req)*, `comment`, `expire_years` (default: 1), `password`, `output_dir`, `force` | `dict` (`fingerprint`, `private_key`, `public_key`, `saved_files`) |
| `ssl_check` | SSL/TLS | Inspect remote TLS endpoint validity, cipher, TLS version, and expiration | `host` *(req)*, `port` (default: 443), `timeout` (default: 10.0) | `dict` (`host`, `port`, `subject`, `issuer`, `valid_from`, `valid_to`, `days_remaining`, `is_expired`, `sans`, `tls_version`, `cipher_suite`, `warnings`, `chain_valid`) |
| `ssl_headers` | SSL/TLS | Audit and score HTTP security response headers with actionable recommendations | `url` *(req)*, `timeout` (default: 10.0) | `dict` (`url`, `status_code`, `present_headers`, `missing_headers`, `score`, `recommendations`) |
| `config_generate` | Config | Generate hardened server TLS configuration block (Nginx, Apache, Caddy) | `server` *(req: "nginx"\|"apache"\|"caddy")*, `profile` (default: "intermediate"), `domain`, `cert_path`, `key_path`, `hsts`, `output_path`, `force` | `dict` (`server`, `profile`, `config`, `saved_to`) |
| `adcs_sign` | ADCS | Submit CSR to Microsoft ADCS Web Enrollment and retrieve cert (optional PFX) | `server` *(req)*, `csr_pem` *(req)*, `template` (default: "WebServer"), `username`, `password`, `auth_method` ("ntlm"\|"basic"), `ca_file`, `insecure`, `timeout`, `private_key_pem`, `pfx_password`, `output_cert_path`, `output_pfx_path`, `force` | `dict` (`status`: "issued"\|"pending"\|"error", `req_id`, `cert_pem`, `pfx_base64`, `saved_files`, `message`, `error`) |
| `adcs_retrieve` | ADCS | Download approved certificate by Request ID (optional PFX assembly) | `server` *(req)*, `req_id` *(req)*, `username`, `password`, `auth_method`, `ca_file`, `insecure`, `timeout`, `private_key_pem`, `pfx_password`, `output_cert_path`, `output_pfx_path`, `force` | `dict` (`status`: "retrieved"\|"pending"\|"error", `req_id`, `cert_pem`, `pfx_base64`, `saved_files`, `message`, `error`) |
| `adcs_ca_cert` | ADCS | Download Enterprise CA certificate chain (`.p7b` PKCS#7 format) | `server` *(req)*, `username`, `password`, `auth_method`, `ca_file`, `insecure`, `timeout`, `output_path`, `force` | `dict` (`status`: "success"\|"error", `ca_data`, `ca_cert_p7b_base64`, `saved_to`, `saved_files`, `error`) |

### Security & In-Memory Guarantees

The MCP server subsystem is built with defense-in-depth guarantees specifically designed for AI agents:
1. **In-Memory Operations**: When file paths are omitted, keys, certificates, and archives are returned in memory as PEM strings and base64 payloads without writing temporary files to disk.
2. **Restrictive File Permissions (`0600`)**: When `output_dir` or `output_path` is specified, private keys (`.key`, `private.asc`, OpenSSH private keys) and PKCS#12 archives (`.pfx`) are created using `os.open` with `0o600` flags so only the current user can access them. Public files (CSRs, public keys, certificates, web configs) are created with `0o644`.
3. **Upfront Overwrite Protection**: If destination file paths already exist, tools raise a `FileExistsError` immediately before performing any cryptographic or network operations, preventing accidental data loss unless `force=True` is explicitly passed.
4. **Structured Error Handling**: ADCS approval pending states return `status: "pending"` containing the `req_id` and next-step instructions rather than failing the agent turn, allowing AI assistants to reason about multi-stage workflows naturally.

---

## Development & Testing

### Running Tests

The test suite covers core crypto libraries, parsers, CLI handlers, and edge cases. Run tests using `pytest`:

```bash
# Run all tests verbosely
pytest tests/ -v

# Run a specific test module
pytest tests/test_cli_adcs.py -v
pytest tests/test_cli_pfx.py -v
```

### Project Structure

```
ittools/
├── pyproject.toml               # Package configuration & dependencies
├── README.md                    # Documentation & usage guide
├── src/
│   └── ittools/
│       ├── __init__.py          # Version & package root
│       ├── cli/
│       │   ├── main.py          # Entrypoint & CLI parser dispatch
│       │   ├── prompt.py        # Interactive terminal prompt utility
│       │   └── commands/
│       │       ├── csr.py       # 'ittools csr' commands
│       │       ├── pfx.py       # 'ittools pfx' commands
│       │       ├── adcs.py      # 'ittools adcs' commands
│       │       ├── keypair.py   # 'ittools keypair' commands
│       │       ├── ssl.py       # 'ittools ssl' commands
│       │       ├── config.py    # 'ittools config' commands
│       │       └── mcp_cmd.py   # 'ittools mcp' command
│       ├── mcp/                 # Model Context Protocol (MCP) server & tools
│       │   ├── server.py        # MCPServer instance & transport runner
│       │   └── tools/           # 15 MCP tool definitions (PKI, ADCS, SSL, keys, config)
│       └── core/
│           ├── pki/             # CSR generation, decoding, key matching & PFX bundles
│           ├── adcs/            # Microsoft ADCS Web Enrollment client & exceptions
│           ├── keypair/         # RSA, SSH, PGP & passphrase generation
│           ├── ssl_check/       # Remote SSL cert & security header checks
│           └── config_gen/      # Mozilla TLS config templates & logic
└── tests/                       # Comprehensive pytest suite
```

---

## License

MIT License. See repository for full license details.
