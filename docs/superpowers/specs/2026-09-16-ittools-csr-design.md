# ittools: CSR generator (first feature) — Design

## Context

The repo is currently empty. The user wants an IT utility toolkit (`ittools`),
a single Go binary organized as subcommands (like `git`/`kubectl`), so more
tools can be added later without restructuring. The first and only feature
being built now is a CSR (Certificate Signing Request) generator, functionally
similar to https://csrgenerator.com/, run as `ittools csr generate`.

Scope for this spec/plan cycle is `csr generate` only. Future tools (base64,
JWT, hashing, etc.) are out of scope but the architecture must not need
rework to add them.

## Goals

- `ittools csr generate` produces an RSA private key and a PKCS#10 CSR,
  covering the same subject fields as csrgenerator.com (CN, O, OU, City,
  State, Country, Email), plus optional SANs.
- Usable both non-interactively (flags, for scripting) and interactively
  (prompts, when no flags are given at all) — matching the web form feel.
- Output written to disk under a per-CN directory, and also printed to
  stdout.
- The overall `ittools` binary is structured so a new subcommand is just a
  new package + one line of registration — no framework dependency.
- Go stdlib only. No external dependencies.

## Non-goals

- No EC/ECDSA keys — RSA only (2048/3072/4096).
- No encrypted/passphrase-protected private keys (csrgenerator.com doesn't
  do this either).
- No other subcommands implemented in this cycle (base64, JWT, etc.) —
  architecture must merely not preclude them later.
- No configurable Key Usage / Extended Key Usage — fixed to the standard TLS
  server profile.

## Architecture

Single Go module, single binary `ittools`.

```
ittools/
  go.mod
  main.go                   # parses os.Args[1] as subcommand name, dispatches
  internal/
    command/
      command.go             # Command interface
    csr/
      cmd.go                 # flag parsing + orchestration for `csr generate`
      csr.go                 # key + CSR generation logic
      prompt.go               # interactive prompt fallback
      csr_test.go
```

### Command interface (`internal/command/command.go`)

```go
type Command interface {
    Name() string
    Run(args []string) error
}
```

`main.go` holds `map[string]command.Command{"csr": csr.New()}` (a literal
map built at startup, not a global registry pattern — nothing here needs
init()-time magic). It looks up `os.Args[1]`, and if not found prints usage
and exits non-zero. Adding a future tool means: write `internal/<tool>/`
implementing `Command`, add one entry to the map in `main.go`.

`csr.New()` returns a value implementing `Command` for the `csr` subcommand
group. Its `Run` further dispatches on the next arg (`generate` is the only
verb for now); an unrecognized or missing verb prints usage and errors.

### CSR generation (`internal/csr/csr.go`)

- `GenerateKey(bits int) (*rsa.PrivateKey, error)` — wraps
  `rsa.GenerateKey(rand.Reader, bits)`.
- `BuildCSR(key *rsa.PrivateKey, subject Subject, sans []string) ([]byte, error)`
  — builds a `x509.CertificateRequest` with the given `pkix.Name` subject and
  DNSNames set to `sans`, adds Key Usage + Extended Key Usage as a requested
  extension (via `ExtraExtensions` with the standard OIDs, DER-encoded),
  signs it with `x509.CreateCertificateRequest`, returns DER bytes.
- `EncodePEM(derBytes []byte, blockType string) []byte` — wraps in
  `pem.Encode` for both the key (PKCS#1, `RSA PRIVATE KEY`) and the CSR
  (`CERTIFICATE REQUEST`).
- `SanitizeName(cn string) string` — replaces `*` with `wildcard`
  (e.g. `*.example.com` → `wildcard.example.com`). Used for both the output
  directory and file basenames.

Key Usage / Extended Key Usage are fixed constants: Digital Signature +
Key Encipherment for Key Usage; Server Auth + Client Auth (OIDs
1.3.6.1.5.5.7.3.1, 1.3.6.1.5.5.7.3.2) for Extended Key Usage. These are
requested extensions on the CSR (a CA may or may not honor them — this
matches how real-world CSR generators like csrgenerator.com annotate
intent).

### Flags / interactive mode (`internal/csr/cmd.go`)

Flags (all via stdlib `flag.FlagSet`, subcommand-scoped so `--help` works
per-subcommand):

| Flag | Required | Notes |
|---|---|---|
| `--cn` | yes (interactive mode still requires non-empty answer) | Common Name |
| `--org` | no | Organization |
| `--ou` | no | Organizational Unit |
| `--city` | no | Locality |
| `--state` | no | State/Province |
| `--country` | no | must be exactly 2 letters if given |
| `--email` | no | Email Address |
| `--san` | no | comma-separated list, split and trimmed |
| `--key-size` | no | one of 2048, 3072, 4096; default 2048 |
| `--force` | no | boolean; overwrite existing output files |

If **no flags at all** are passed (`len(args) == 0`), fall into
`prompt.go`'s interactive flow: prompt for each field in the same order as
the table above, in turn, via stdin. Empty answers are allowed for optional
fields (Enter to skip); CN and key-size are re-prompted until valid.

If **any** flag is passed, no prompting occurs — unset optional fields are
just empty/default, matching normal CLI/scripting expectations.

### Validation

- CN: non-empty (checked whether it came from flag or prompt).
- Country: if non-empty, must be exactly 2 ASCII letters.
- Key size: must be 2048, 3072, or 4096.

Validation failures print a clear error to stderr and exit non-zero before
any key generation happens.

### Output

- Sanitize CN via `SanitizeName` → `name`.
- Output dir: `./output/<name>/`.
- Files: `./output/<name>/<name>.key` (PEM, PKCS#1 RSA private key,
  unencrypted) and `./output/<name>/<name>.csr` (PEM, PKCS#10 CSR).
- If the directory exists and either target file already exists, and
  `--force` was not given: error out without writing, telling the user to
  pass `--force` or remove the existing files.
- Regardless of write outcome, on success both PEM blocks are also printed
  to stdout (key first, then CSR), so the CLI feels like the web tool
  (copy-paste ready) even though files are also saved.

### Error handling

All errors (validation, key generation, CSR building, file I/O) propagate up
through `Run` and are printed via `fmt.Fprintln(os.Stderr, ...)` in `main.go`,
which then exits with status 1. No panics for expected error paths.

## Testing

`internal/csr/csr_test.go`, table-driven, no external deps:

1. `TestBuildCSR` — generate a key, build a CSR with a representative subject
   + SANs, parse it back with `x509.ParseCertificateRequest`, assert Subject
   fields, DNSNames, and that Key Usage / Extended Key Usage extensions are
   present with expected values.
2. `TestSanitizeName` — table of inputs (`"example.com"`, `"*.example.com"`,
   `"*.sub.example.com"`) → expected sanitized outputs.
3. `TestValidate` (or equivalent) — table of (cn, country, keySize) →
   expected valid/invalid, covering empty CN, 1/3-letter country codes, and
   invalid key sizes.

Manual verification: run `ittools csr generate --cn '*.example.com' --org
Acme --country VN`, confirm `output/wildcard.example.com/` is created with
both files, and that `openssl req -in ... -noout -text` (if available)
shows the expected fields — this is a manual check during implementation,
not an automated test.

## Open questions / assumptions

- RSA key encoded as PKCS#1 (`RSA PRIVATE KEY` PEM header), matching
  csrgenerator.com's output format, rather than PKCS#8 (`PRIVATE KEY`).
- `--force` overwrites both files if either exists; it does not selectively
  overwrite just one.
