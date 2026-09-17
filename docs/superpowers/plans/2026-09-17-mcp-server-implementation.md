# ittools MCP (Model Context Protocol) Server Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a native Model Context Protocol (MCP) server subsystem for `ittools` enabling AI models to directly discover and call 14 PKI, ADCS, Keypair, SSL inspection, and Server TLS configuration tools.

**Architecture:** Create a dedicated `ittools.mcp` package using the official `mcp` SDK (`MCPServer` with `FastMCP` backward compatibility) that directly interfaces with `ittools.core.*`. Provide both in-memory structured returns and optional secure file persistence (`0600` permissions), surfaced through the `ittools mcp` CLI subcommand.

**Tech Stack:** Python 3.10+, `mcp>=1.2.0`, `cryptography`, `requests`, `paramiko`, `python-gnupg`, `pytest`.

**Spec:** [`docs/superpowers/specs/2026-09-17-mcp-server-design.md`](file:///home/bobbab/orca/workspaces/it-tools/fork-to-python/docs/superpowers/specs/2026-09-17-mcp-server-design.md)

## Global Constraints

- Requires Python >= 3.10.
- All private key files and PFX archives written to disk MUST have restrictive permissions `0600` (`-rw-------`).
- Target file overwrite protection: Never overwrite existing files unless `force=True`.
- MCP tools must return structured dictionaries directly in the tool response so models can reason about results immediately.
- Clean error handling: Business and connection errors must be returned as informative status/error dictionaries or tool errors without crashing the MCP server process.
- Active Directory pending state (`ADCSPendingError`) must return status `"pending"` with `req_id`.
- The `mcp` dependency must be optional in `pyproject.toml` (`ittools[mcp]`), with a clean stderr message if `ittools mcp` is executed when `mcp` is not installed.

---

## File Structure

```
src/ittools/
├── cli/
│   ├── main.py                        # Modify: register mcp subcommand
│   └── commands/
│       └── mcp_cmd.py                 # Create: CLI handler for ittools mcp with missing dependency guard
└── mcp/
    ├── __init__.py                    # Create: package export
    ├── server.py                      # Create: MCPServer instance setup and tool registration
    └── tools/
        ├── __init__.py                # Create: package init
        ├── pki.py                     # Create: csr_generate, csr_decode, pfx_create, pfx_extract, ssl_match
        ├── adcs.py                    # Create: adcs_sign, adcs_retrieve, adcs_ca_cert
        ├── keypair.py                 # Create: keypair_passphrase, keypair_rsa, keypair_ssh, keypair_pgp
        ├── ssl.py                     # Create: ssl_check, ssl_headers
        └── config.py                  # Create: config_generate
tests/
└── test_mcp.py                        # Create: comprehensive unit & integration tests for all MCP tools
```

---

### Task 1: Scaffolding, Packaging & PKI MCP Tools

**Files:**
- Modify: `pyproject.toml`
- Create: `src/ittools/mcp/__init__.py`
- Create: `src/ittools/mcp/tools/__init__.py`
- Create: `src/ittools/mcp/tools/pki.py`
- Test: `tests/test_mcp.py`

**Interfaces:**
- Consumes: `ittools.core.pki.csr`, `ittools.core.pki.pfx`, `ittools.core.pki.matcher`
- Produces:
  - `csr_generate(common_name: str, organization: str = "", organizational_unit: str = "", city: str = "", state: str = "", country: str = "", email: str = "", sans: list[str] | None = None, key_size: int = 2048, output_dir: str | None = None, force: bool = False) -> dict`
  - `csr_decode(csr_pem: str) -> dict`
  - `pfx_create(private_key_pem: str, cert_pem: str, ca_certs_pem: str | None = None, password: str | None = None, friendly_name: str | None = None, key_password: str | None = None, output_path: str | None = None, force: bool = False) -> dict`
  - `pfx_extract(pfx_data_or_path: str, password: str | None = None, output_dir: str | None = None, force: bool = False) -> dict`
  - `ssl_match(private_key_pem: str, cert_or_csr_pem: str, password: str | None = None) -> dict`

- [ ] **Step 1: Update `pyproject.toml` with optional dependencies**

Add `mcp = ["mcp>=1.2.0"]` and `all = ["requests-ntlm>=1.2.0", "mcp>=1.2.0"]` under `[project.optional-dependencies]`.

- [ ] **Step 2: Write failing unit tests for PKI MCP tools**

Create `tests/test_mcp.py` with tests for:
1. `test_mcp_csr_generate_in_memory`
2. `test_mcp_csr_generate_with_output_dir` (verifying mode 0600 on private key and force guard)
3. `test_mcp_csr_decode`
4. `test_mcp_pfx_create_and_extract_flow` (verifying base64 and file path extraction)
5. `test_mcp_ssl_match` (both match and mismatch)

- [ ] **Step 3: Run test to verify failure**

Run: `pytest tests/test_mcp.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'ittools.mcp'`

- [ ] **Step 4: Implement `src/ittools/mcp/tools/pki.py`**

Implement helper functions and the 5 PKI tool functions with full type annotations, docstrings, secure 0600 file persistence, and upfront overwrite checks.

- [ ] **Step 5: Run tests to verify they pass**

Run: `pytest tests/test_mcp.py -v`
Expected: PASS (all PKI tool tests pass)

- [ ] **Step 6: Commit**

```bash
git add pyproject.toml src/ittools/mcp/ tests/test_mcp.py
git commit -m "feat(mcp): implement PKI and PFX MCP tools"
```

---

### Task 2: Keypair, SSL Inspection & Server TLS Config MCP Tools

**Files:**
- Create: `src/ittools/mcp/tools/keypair.py`
- Create: `src/ittools/mcp/tools/ssl.py`
- Create: `src/ittools/mcp/tools/config.py`
- Modify: `tests/test_mcp.py`

**Interfaces:**
- Consumes: `ittools.core.keypair.*`, `ittools.core.ssl_check.*`, `ittools.core.config_gen.*`
- Produces:
  - `keypair_passphrase(words: int = 4, separator: str = "-", capitalize: bool = False, include_numbers: bool = False, include_special: bool = False) -> dict`
  - `keypair_rsa(key_size: int = 2048, password: str | None = None, output_path: str | None = None, force: bool = False) -> dict`
  - `keypair_ssh(key_type: str = "ed25519", key_size: int = 2048, comment: str = "", password: str | None = None, output_path: str | None = None, force: bool = False) -> dict`
  - `keypair_pgp(name: str, email: str, comment: str = "", expire_years: int = 1, password: str | None = None, output_dir: str | None = None, force: bool = False) -> dict`
  - `ssl_check(host: str, port: int = 443, timeout: float = 10.0) -> dict`
  - `ssl_headers(url: str, timeout: float = 10.0) -> dict`
  - `config_generate(server: str, profile: str = "intermediate", domain: str = "example.com", cert_path: str = "/etc/ssl/certs/cert.pem", key_path: str = "/etc/ssl/private/key.pem", hsts: bool = True, output_path: str | None = None, force: bool = False) -> dict`

- [ ] **Step 1: Write failing unit tests in `tests/test_mcp.py`**

Add tests for:
1. `test_mcp_keypair_passphrase`
2. `test_mcp_keypair_rsa` (in-memory and with output_path mode 0600)
3. `test_mcp_keypair_ssh` (ed25519 & rsa, output_path mode 0600)
4. `test_mcp_keypair_pgp`
5. `test_mcp_ssl_check` (mocking socket/ssl)
6. `test_mcp_ssl_headers` (mocking requests)
7. `test_mcp_config_generate` (in-memory and output file)

- [ ] **Step 2: Run test to verify failure**

Run: `pytest tests/test_mcp.py -k "keypair or ssl or config" -v`
Expected: FAIL

- [ ] **Step 3: Implement `keypair.py`, `ssl.py`, and `config.py`**

Create `src/ittools/mcp/tools/keypair.py`, `src/ittools/mcp/tools/ssl.py`, and `src/ittools/mcp/tools/config.py` with type annotations, docstrings, error handling, and safe file permissions.

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/test_mcp.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/ittools/mcp/tools/ tests/test_mcp.py
git commit -m "feat(mcp): implement keypair, ssl, and config MCP tools"
```

---

### Task 3: Microsoft ADCS MCP Tools

**Files:**
- Create: `src/ittools/mcp/tools/adcs.py`
- Modify: `tests/test_mcp.py`

**Interfaces:**
- Consumes: `ittools.core.adcs.client.ADCSClient`, `ittools.core.adcs.exceptions.*`, `ittools.core.pki.pfx.create_pfx_bundle`
- Produces:
  - `adcs_sign(server: str, csr_pem: str, template: str = "WebServer", username: str | None = None, password: str | None = None, auth_method: str = "ntlm", ca_file: str | None = None, insecure: bool = False, timeout: float = 30.0, private_key_pem: str | None = None, pfx_password: str | None = None, output_cert_path: str | None = None, output_pfx_path: str | None = None, force: bool = False) -> dict`
  - `adcs_retrieve(server: str, req_id: str, username: str | None = None, password: str | None = None, auth_method: str = "ntlm", ca_file: str | None = None, insecure: bool = False, timeout: float = 30.0, private_key_pem: str | None = None, pfx_password: str | None = None, output_cert_path: str | None = None, output_pfx_path: str | None = None, force: bool = False) -> dict`
  - `adcs_ca_cert(server: str, username: str | None = None, password: str | None = None, auth_method: str = "ntlm", ca_file: str | None = None, insecure: bool = False, timeout: float = 30.0, output_path: str | None = None, force: bool = False) -> dict`

- [ ] **Step 1: Write failing unit tests for ADCS MCP tools**

In `tests/test_mcp.py`, add:
1. `test_mcp_adcs_sign_issued`: mocks `ADCSClient.submit_csr`, verifies `status="issued"`, `cert_pem`, and optional PFX assembly.
2. `test_mcp_adcs_sign_pending`: mocks `ADCSPendingError`, verifies `status="pending"` and `req_id="1042"` returned cleanly without crash.
3. `test_mcp_adcs_sign_connection_error`: mocks `ADCSConnectionError`, verifies error dictionary returned.
4. `test_mcp_adcs_retrieve`: verifies certificate retrieval and optional PFX assembly.
5. `test_mcp_adcs_ca_cert`: verifies CA bundle download and optional file saving.

- [ ] **Step 2: Run test to verify failure**

Run: `pytest tests/test_mcp.py -k "adcs" -v`
Expected: FAIL

- [ ] **Step 3: Implement `src/ittools/mcp/tools/adcs.py`**

Implement `adcs_sign`, `adcs_retrieve`, and `adcs_ca_cert` with clean error catching, pending status handling, and PFX assembly.

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/test_mcp.py -k "adcs" -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/ittools/mcp/tools/adcs.py tests/test_mcp.py
git commit -m "feat(mcp): implement Microsoft ADCS MCP tools"
```

---

### Task 4: MCPServer Assembly, CLI Subcommand & Dependency Guard

**Files:**
- Create: `src/ittools/mcp/server.py`
- Create: `src/ittools/cli/commands/mcp_cmd.py`
- Modify: `src/ittools/cli/main.py`
- Modify: `tests/test_mcp.py`

**Interfaces:**
- Consumes: All MCP tools from Tasks 1-3, `mcp.server.mcpserver.MCPServer`
- Produces:
  - `create_mcp_server() -> MCPServer`: Registers all 14 tools and returns configured server.
  - `run_mcp_server(transport: str = "stdio", port: int = 8000) -> None`: Starts server on specified transport.
  - `register_mcp_commands(subparsers)`: CLI registration for `ittools mcp`.
  - `ittools mcp` CLI subcommand.

- [ ] **Step 1: Write failing CLI integration tests for `ittools mcp`**

In `tests/test_mcp.py`, add:
1. `test_mcp_server_lists_all_14_tools`: verifies `server.list_tools()` contains exactly all 14 tool names.
2. `test_cli_mcp_help`: verifies `ittools mcp --help` displays help without error.
3. `test_cli_mcp_missing_dependency`: mocks `mcp` import failure, verifies error message and exit code 1.

- [ ] **Step 2: Run test to verify failure**

Run: `pytest tests/test_mcp.py -k "server or cli" -v`
Expected: FAIL

- [ ] **Step 3: Implement `src/ittools/mcp/server.py`, `mcp_cmd.py`, and register in `main.py`**

1. Create `src/ittools/mcp/server.py`:
   - Initialize `MCPServer("ittools", instructions="IT, PKI, ADCS, Keypair, and SSL/TLS automation toolkit")`.
   - Register all 14 tools from `src/ittools/mcp/tools/` using `@mcp.tool()`.
   - Implement `run_mcp_server(transport="stdio", port=8000)`.
2. Create `src/ittools/cli/commands/mcp_cmd.py`:
   - Catch missing `mcp` import gracefully.
   - Parse `--transport` (`stdio`/`sse`) and `--port`.
3. Register `register_mcp_commands(subparsers)` in `src/ittools/cli/main.py`.

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/test_mcp.py -v`
Expected: PASS (all tests pass)

- [ ] **Step 5: Commit**

```bash
git add src/ittools/mcp/server.py src/ittools/cli/commands/mcp_cmd.py src/ittools/cli/main.py tests/test_mcp.py
git commit -m "feat(mcp): assemble MCPServer and wire ittools mcp CLI subcommand"
```

---

### Task 5: End-to-End Verification & Documentation Update

**Files:**
- Modify: `README.md`
- Run: Full test suite `pytest -v`
- Run: Live smoke tests

- [ ] **Step 1: Update `README.md`**

Add complete Model Context Protocol (MCP) section to `README.md`:
- Overview of MCP capabilities for AI assistants.
- Running `ittools mcp`.
- Ready-to-copy configuration blocks for Claude Desktop (`claude_desktop_config.json`), Cursor (`.cursor/mcp.json`), Antigravity, and VS Code.
- Table of the 14 available MCP tools with descriptions.

- [ ] **Step 2: Run full regression test suite**

Run: `pytest -v`
Expected: 100% pass rate across all existing tests (145) plus all new MCP tests.

- [ ] **Step 3: Live smoke test**

Run:
```bash
python3 -m ittools.cli.main mcp --help
python3 -c "from ittools.mcp.server import create_mcp_server; s = create_mcp_server(); print('Registered tools:', len(s.list_tools() if hasattr(s, 'list_tools') else []))"
```

- [ ] **Step 4: Commit**

```bash
git add README.md
git commit -m "docs: document ittools MCP server and client configuration"
```
