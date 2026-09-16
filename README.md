# ittools

A command-line toolkit of IT, PKI, and SSL/TLS utilities organized as subcommands (similar to `git` or `kubectl`).

`ittools` provides standard, reliable utilities for TLS certificate generation and decoding, cryptographic keypair creation (RSA, OpenSSH, PGP, and secure passphrases), remote SSL/TLS certificate and HTTP security header inspection, certificate/key matching, and hardened server TLS configuration generation adhering to Mozilla recommendations.

---

## Table of Contents

- [Installation](#installation)
  - [Prerequisites](#prerequisites)
  - [Install with pip](#install-with-pip)
  - [Run Without Installing](#run-without-installing)
- [CLI Overview & Exit Codes](#cli-overview--exit-codes)
- [Subcommands Reference](#subcommands-reference)
  - [PKI & CSR (`ittools csr`)](#pki--csr-ittools-csr)
    - [`csr generate`](#csr-generate)
    - [`csr decode`](#csr-decode)
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
- [Development & Testing](#development--testing)

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

## CLI Overview & Exit Codes

```
ittools [--debug] <command> <subcommand> [options]
```

### Global Options

- `--help`, `-h`: Show help and usage for any command or subcommand.
- `--debug`: Print full Python tracebacks when an unhandled error or exception occurs (default: writes clean, user-facing error message to stderr).

### Exit Codes

| Exit Code | Meaning | Context |
|---|---|---|
| `0` | Success | Command completed successfully; checks passed. |
| `1` | Validation / User Error | Invalid arguments, missing required fields, or output file collision without `--force`. |
| `2` | Network / Connection Error | Remote host unreachable, DNS lookup failed, or connection timed out. |
| `3` | Security Warning / Mismatch | Remote SSL certificate expired or expiring within 30 days (`ssl check`), or private key and certificate do not match (`ssl match`). |

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

Connects to a remote host over TLS, extracts the leaf certificate, and reports validity dates, issuer, cipher suite, and expiration warnings.

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
- `0`: Security score is Grade B, A, or A+.
- `1`: Security score is Grade C or F.
- `2`: Network connection or request failure.

**Examples:**
```bash
# Inspect headers
ittools ssl headers https://example.com

# Machine-readable output
ittools ssl headers https://example.com --json
```

#### `ssl match`

Verifies that a private key matches a public certificate or CSR by calculating and comparing their SHA-256 public key digests.

```bash
ittools ssl match --key <private-key.pem> --cert <cert-or-csr.pem>
```

**Options:**
- `--key KEY`: Path to PEM-encoded private key file.
- `--cert CERT`: Path to PEM-encoded certificate or CSR file.

**Exit Codes:**
- `0`: Public key hashes match.
- `3`: Hashes do not match (keypair mismatch).

**Example:**
```bash
ittools ssl match --key output/example.com/example.com.key --cert output/example.com/example.com.csr
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

## Development & Testing

### Running Tests

The test suite covers core crypto libraries, parsers, CLI handlers, and edge cases. Run tests using `pytest`:

```bash
# Run all tests verbosely
pytest tests/ -v

# Run a specific test module
pytest tests/test_cli.py -v
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
│       │       ├── keypair.py   # 'ittools keypair' commands
│       │       ├── ssl.py       # 'ittools ssl' commands
│       │       └── config.py    # 'ittools config' commands
│       └── core/
│           ├── pki/             # CSR generation, decoding & key matching
│           ├── keypair/         # RSA, SSH, PGP & passphrase generation
│           ├── ssl_check/       # Remote SSL cert & security header checks
│           └── config_gen/      # Mozilla TLS config templates & logic
└── tests/                       # Comprehensive pytest suite
```

---

## License

MIT License. See repository for full license details.
