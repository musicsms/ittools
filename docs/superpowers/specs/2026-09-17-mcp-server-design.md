# Design Specification: ittools MCP (Model Context Protocol) Server

**Date:** 2026-09-17  
**Status:** Approved  
**Author:** Antigravity Team  

---

## 1. Overview & Objectives

`ittools` is a modular, high-integrity IT, PKI, and SSL/TLS CLI toolkit. To enable AI assistants and autonomous coding agents (such as Claude Desktop, Cursor, Antigravity, VS Code, and Windsurf) to leverage `ittools` natively, this specification designs a standard **Model Context Protocol (MCP)** server subsystem.

### Key Objectives
1. **Full Protocol Compliance**: Support MCP JSON-RPC 2.0 over standard I/O (`stdio`), compatible with all major MCP clients.
2. **Direct Core Integration**: Expose `ittools.core` services directly into MCP tools without shelling out to subprocesses, ensuring high performance and structured typing.
3. **Complete Toolkit Coverage**: Expose all 6 core functional areas across 14 dedicated tools:
   - PKI & CSR (`csr_generate`, `csr_decode`, `ssl_match`)
   - PKCS#12 Containers (`pfx_create`, `pfx_extract`)
   - Active Directory Certificate Services (`adcs_sign`, `adcs_retrieve`, `adcs_ca_cert`)
   - Cryptographic Keypairs (`keypair_passphrase`, `keypair_rsa`, `keypair_ssh`, `keypair_pgp`)
   - SSL/TLS Inspection (`ssl_check`, `ssl_headers`)
   - Server TLS Configuration (`config_generate`)
4. **Dual Output Mode**: Return structured data (PEM strings, JSON metrics, generated configs) directly to the AI model context, while supporting optional file path parameters to persist files to disk.
5. **Strict Security Model**: Automatically enforce `0600` permissions on all written private keys and PFX archives, with explicit `force=False` overwrite protection.
6. **Graceful Dependency Handling**: Provide `mcp` as an optional package dependency (`ittools[mcp]`) with clear user guidance if invoked when uninstalled.

---

## 2. Architecture & Directory Structure

```
ittools/
├── pyproject.toml                     # Optional dependency: mcp = ["mcp>=1.2.0"]
├── src/ittools/
│   ├── cli/
│   │   ├── main.py                    # Register subcommand `mcp`
│   │   └── commands/
│   │       └── mcp_cmd.py             # CLI handler: runs FastMCP server or shows install hint
│   └── mcp/
│       ├── __init__.py                # Module export and entrypoint
│       ├── server.py                  # FastMCP server instance and tool registration
│       └── tools/
│           ├── __init__.py
│           ├── pki.py                 # Tools: csr_generate, csr_decode, pfx_create, pfx_extract, ssl_match
│           ├── adcs.py                # Tools: adcs_sign, adcs_retrieve, adcs_ca_cert
│           ├── keypair.py             # Tools: keypair_passphrase, keypair_rsa, keypair_ssh, keypair_pgp
│           ├── ssl.py                 # Tools: ssl_check, ssl_headers
│           └── config.py              # Tools: config_generate
└── tests/
    └── test_mcp.py                    # Comprehensive test suite for MCP tools and server
```

---

## 3. CLI Command & Packaging

### 3.1 Subcommand Dispatch (`ittools mcp`)

The top-level parser in `src/ittools/cli/main.py` routes the `mcp` command:

```bash
ittools mcp [--transport {stdio,sse}] [--port PORT]
```

- `--transport`: Default is `stdio`. Optional `sse` transport supported via FastMCP.
- `--port`: Port number when running SSE transport (default: `8000`).

### 3.2 Dependency Handling
If `mcp` is not installed, running `ittools mcp` exits with code `1` and a clean message to stderr:
```
error: The 'mcp' package is required to run the MCP server.
Install it with: pip install "ittools[mcp]"
```

In `pyproject.toml`:
```toml
[project.optional-dependencies]
dev = [
    "pytest>=8.0.0",
    "pytest-cov>=4.1.0",
]
ntlm = [
    "requests-ntlm>=1.2.0",
]
mcp = [
    "mcp>=1.2.0",
]
all = [
    "requests-ntlm>=1.2.0",
    "mcp>=1.2.0",
]
```

---

## 4. MCP Tools Specification

### 4.1 PKI, CSR & PFX Tools (`src/ittools/mcp/tools/pki.py`)

#### `csr_generate`
- **Description**: Generates an RSA private key and a PKCS#10 Certificate Signing Request (CSR) with standard extensions.
- **Parameters**:
  - `common_name` (`str`, required): FQDN or hostname (e.g. `api.example.com`).
  - `organization` (`str`, optional, default `""`): Organization name.
  - `organizational_unit` (`str`, optional, default `""`): OU.
  - `city` (`str`, optional, default `""`): Locality.
  - `state` (`str`, optional, default `""`): State or province.
  - `country` (`str`, optional, default `""`): 2-letter ISO country code.
  - `email` (`str`, optional, default `""`): Contact email.
  - `sans` (`list[str]`, optional): Subject Alternative Names list.
  - `key_size` (`int`, optional, default `2048`): RSA key length (`2048`, `3072`, `4096`).
  - `output_dir` (`str`, optional): If provided, writes `<cn>.key` (mode 0600) and `<cn>.csr` to directory.
  - `force` (`bool`, optional, default `False`): Overwrite files if they already exist.
- **Returns**: `{"common_name": str, "private_key_pem": str, "csr_pem": str, "saved_files": list[str]}`.

#### `csr_decode`
- **Description**: Decodes and inspects a PEM-encoded Certificate Signing Request.
- **Parameters**:
  - `csr_pem` (`str`, required): PEM-encoded CSR content.
- **Returns**: `{"common_name": str, "organization": str, "country": str, "sans": list[str], "key_type": str, "key_size": int, "signature_algorithm": str}`.

#### `pfx_create`
- **Description**: Bundles a private key, leaf certificate, and optional CA chain into a PKCS#12 archive using PBES2 AES-256-CBC encryption.
- **Parameters**:
  - `private_key_pem` (`str`, required): Private key PEM string.
  - `cert_pem` (`str`, required): Certificate PEM string.
  - `ca_certs_pem` (`str`, optional): Optional CA certificate chain PEM string.
  - `password` (`str`, optional): Encryption password for the PFX container.
  - `friendly_name` (`str`, optional): Certificate alias in the PFX.
  - `key_password` (`str`, optional): Passphrase to decrypt private key if encrypted.
  - `output_path` (`str`, optional): Optional file path to save `.pfx` bundle (mode 0600).
  - `force` (`bool`, optional, default `False`): Overwrite existing file.
- **Returns**: `{"pfx_base64": str, "size_bytes": int, "friendly_name": str | None, "saved_to": str | None}`.

#### `pfx_extract`
- **Description**: Extracts the private key, leaf certificate, and CA certificates from a PKCS#12 archive.
- **Parameters**:
  - `pfx_data_or_path` (`str`, required): Base64-encoded PFX bytes or filesystem path to `.pfx` file.
  - `password` (`str`, optional): Archive decryption password.
  - `output_dir` (`str`, optional): Optional directory to write extracted PEM files (private key saved with mode 0600).
  - `force` (`bool`, optional, default `False`): Overwrite existing output files.
- **Returns**: `{"private_key_pem": str | None, "cert_pem": str | None, "ca_certs_pem": list[str], "friendly_name": str | None, "saved_files": list[str]}`.

#### `ssl_match`
- **Description**: Compares SHA-256 public key digests to verify whether a private key matches a certificate or CSR.
- **Parameters**:
  - `private_key_pem` (`str`, required): PEM private key string.
  - `cert_or_csr_pem` (`str`, required): PEM certificate or CSR string.
  - `password` (`str`, optional): Decryption password for encrypted private key.
- **Returns**: `{"matched": bool, "key_hash": str, "cert_hash": str, "message": str}`.

---

### 4.2 Microsoft ADCS Web Enrollment Tools (`src/ittools/mcp/tools/adcs.py`)

#### `adcs_sign`
- **Description**: Submits a CSR to Microsoft Active Directory Certificate Services Web Enrollment and retrieves the issued certificate. If private key is provided, automatically packages a PFX bundle.
- **Parameters**:
  - `server` (`str`, required): ADCS server FQDN or IP.
  - `csr_pem` (`str`, required): CSR PEM string.
  - `template` (`str`, optional, default `"WebServer"`): Certificate template name.
  - `username` (`str`, optional): AD username (e.g. `DOMAIN\user`).
  - `password` (`str`, optional): AD user password.
  - `auth_method` (`str`, optional, default `"ntlm"`): `"ntlm"` or `"basic"`.
  - `ca_file` (`str`, optional): Custom CA certificate path for HTTPS validation.
  - `insecure` (`bool`, optional, default `False`): Disable SSL verification.
  - `timeout` (`float`, optional, default `30.0`): Request timeout in seconds.
  - `private_key_pem` (`str`, optional): Matching private key to assemble PFX.
  - `pfx_password` (`str`, optional): Password for assembled PFX.
  - `output_cert_path` (`str`, optional): Path to save issued certificate.
  - `output_pfx_path` (`str`, optional): Path to save assembled PFX file (mode 0600).
  - `force` (`bool`, optional, default `False`): Overwrite existing files.
- **Returns**:
  - If issued: `{"status": "issued", "req_id": str, "cert_pem": str, "pfx_base64": str | None, "saved_files": list[str]}`.
  - If pending: `{"status": "pending", "req_id": str, "message": str}`.

#### `adcs_retrieve`
- **Description**: Downloads an approved certificate from ADCS by Request ID, with optional PFX assembly.
- **Parameters**: Same authentication, server, and PFX assembly parameters as `adcs_sign`, with `req_id` (`str`, required).
- **Returns**: `{"status": "retrieved", "req_id": str, "cert_pem": str, "pfx_base64": str | None, "saved_files": list[str]}`.

#### `adcs_ca_cert`
- **Description**: Downloads the Enterprise CA certificate chain (.p7b) from Microsoft ADCS.
- **Parameters**: `server`, `username`, `password`, `auth_method`, `ca_file`, `insecure`, `timeout`, `output_path`, `force`.
- **Returns**: `{"ca_data": str, "saved_to": str | None}`.

---

### 4.3 Cryptographic Keypair Tools (`src/ittools/mcp/tools/keypair.py`)

#### `keypair_passphrase`
- **Description**: Generates an EFF-style multi-word cryptographically secure passphrase.
- **Parameters**:
  - `words` (`int`, default `4`): Word count.
  - `separator` (`str`, default `"-"`): Word separator character.
  - `capitalize` (`bool`, default `False`): Capitalize each word.
  - `include_numbers` (`bool`, default `False`): Append random digit.
  - `include_special` (`bool`, default `False`): Append random special character.
- **Returns**: `{"passphrase": str}`.

#### `keypair_rsa`
- **Description**: Generates a standard PKCS#8 RSA keypair.
- **Parameters**: `key_size` (2048/3072/4096), `password` (optional), `output_path` (optional, mode 0600), `force`.
- **Returns**: `{"private_key_pem": str, "public_key_pem": str, "saved_files": list[str]}`.

#### `keypair_ssh`
- **Description**: Generates an OpenSSH-compatible keypair (Ed25519 or RSA).
- **Parameters**: `key_type` ("ed25519" or "rsa"), `key_size`, `comment`, `password`, `output_path` (optional, mode 0600), `force`.
- **Returns**: `{"private_key": str, "public_key": str, "saved_files": list[str]}`.

#### `keypair_pgp`
- **Description**: Generates an ASCII-armored PGP keypair via GnuPG in an isolated environment.
- **Parameters**: `name`, `email`, `comment`, `expire_years`, `password`, `output_dir` (optional, mode 0600), `force`.
- **Returns**: `{"fingerprint": str, "private_key": str, "public_key": str, "saved_files": list[str]}`.

---

### 4.4 SSL/TLS Inspection & Config Tools (`src/ittools/mcp/tools/ssl.py` & `config.py`)

#### `ssl_check`
- **Description**: Connects to a remote host over TLS to inspect the leaf certificate, expiration, protocol, cipher suite, and validity chain. Falls back to unverified connection on untrusted/self-signed certs.
- **Parameters**: `host` (`str`), `port` (`int`, default `443`), `timeout` (`float`, default `10.0`).
- **Returns**: Dictionary representation of `SSLReport`.

#### `ssl_headers`
- **Description**: Inspects and grades HTTP security headers (HSTS, CSP, X-Frame-Options, etc.).
- **Parameters**: `url` (`str`), `timeout` (`float`, default `10.0`).
- **Returns**: Dictionary representation of `SecurityHeadersReport`.

#### `config_generate`
- **Description**: Generates production-ready, hardened server TLS virtual host configurations adhering to Mozilla guidelines.
- **Parameters**: `server` ("nginx", "apache", "caddy"), `profile` ("intermediate", "modern"), `domain`, `cert_path`, `key_path`, `hsts`, `output_path` (optional), `force`.
- **Returns**: `{"server": str, "profile": str, "config": str, "saved_to": str | None}`.

---

## 5. Security & Persistence Guarantees

1. **File Permission Enforcement (`0o600`)**:
   Every function that writes private key data or PKCS#12 bundles creates the file with `os.open` flags `os.O_CREAT | os.O_WRONLY | (os.O_TRUNC if force else os.O_EXCL)` with mode `0o600`, followed by `os.chmod(..., 0o600)` in a `finally` block.
2. **Upfront Overwrite Protection**:
   Before initiating any generation, network calls, or write operations, any target file path specified by the caller is inspected. If it exists and `force=False`, a `FileExistsError` is raised immediately.
3. **In-Memory Default**:
   If no `output_path` or `output_dir` is provided, tools operate completely in-memory without leaving residual artifacts on the filesystem.

---

## 6. Client Configuration Reference

### Claude Desktop (`claude_desktop_config.json`)
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

### Cursor / VS Code / Antigravity
```json
{
  "mcpServers": {
    "ittools": {
      "command": "/path/to/venv/bin/python3",
      "args": ["-m", "ittools.mcp"]
    }
  }
}
```

---

## 7. Testing & Verification

1. **Unit Tests (`tests/test_mcp.py`)**:
   - Verify every tool function in isolation (signatures, return dictionaries, default arguments).
   - Verify base64 and filesystem input handling in PFX tools.
   - Mock ADCS HTTP calls for `adcs_sign`, `adcs_retrieve`, `adcs_ca_cert`, verifying both `issued` and `pending` response structures.
   - Verify file persistence and `0600` permissions on written private keys.
   - Verify error responses do not crash the server process.
2. **CLI Integration**:
   - Test `ittools mcp --help`.
   - Test missing `mcp` dependency error handling.
3. **Full Suite Regression**:
   - All existing 145 tests + new MCP tests must pass 100%.
