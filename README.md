# ittools

A small CLI toolkit of IT utilities, organized as subcommands (like `git` or
`kubectl`). Written in Go, standard library only — no third-party
dependencies, no runtime to install beyond the compiled binary.

Currently available:

- [`csr generate`](#csr-generate) — generate an RSA private key and a
  PKCS#10 Certificate Signing Request (CSR), similar to
  [csrgenerator.com](https://csrgenerator.com/) but from the command line.

## Install

### Build from source

Requires Go 1.22 or later.

```bash
git clone https://github.com/musicsms/ittools.git
cd ittools
go build -o ittools .
```

This produces a single static binary, `ittools`. Move it onto your `PATH`
if you want it available everywhere:

```bash
sudo mv ittools /usr/local/bin/
```

### Run without installing

```bash
go run . csr generate --cn example.com
```

## Usage

```
ittools <command> [args]
```

Running `ittools` with no command, or an unknown command, prints the list
of available commands and exits with a non-zero status.

## `csr generate`

Generates an RSA private key and a CSR with the same subject fields as a
typical web-based CSR generator: Common Name, Organization, Organizational
Unit, City, State, Country, Email, plus optional Subject Alternative Names
(SANs).

The CSR always requests:
- **Key Usage:** Digital Signature, Key Encipherment
- **Extended Key Usage:** TLS Web Server Authentication, TLS Web Client
  Authentication

These match a standard TLS server certificate profile and aren't
configurable.

### Flags

| Flag | Default | Description |
|---|---|---|
| `--cn` | *(required)* | Common Name, e.g. `example.com` or `*.example.com` |
| `--org` | *(empty)* | Organization |
| `--ou` | *(empty)* | Organizational Unit |
| `--city` | *(empty)* | City / Locality |
| `--state` | *(empty)* | State / Province |
| `--country` | *(empty)* | Country — must be a 2-letter code if given (e.g. `US`, `VN`); normalized to uppercase |
| `--email` | *(empty)* | Email address |
| `--san` | *(empty)* | Comma-separated Subject Alternative Names, e.g. `example.com,www.example.com` |
| `--key-size` | `2048` | RSA key size: `2048`, `3072`, or `4096` |
| `--force` | `false` | Overwrite existing output files |

Run `ittools csr generate --help` to see this from the CLI itself.

### Non-interactive (flags)

```bash
ittools csr generate \
  --cn example.com \
  --org "Acme Inc" \
  --country US \
  --san example.com,www.example.com \
  --key-size 2048
```

### Interactive

Run with no flags at all (or with only `--force`) to be prompted for each
field in turn:

```bash
ittools csr generate
```

```
Common Name: example.com
Organization: Acme Inc
Organizational Unit: IT
City: Hanoi
State: Hanoi
Country (2-letter code): VN
Email: admin@example.com
Subject Alternative Names (comma-separated, optional): example.com,www.example.com
Key size (2048, 3072, 4096) [2048]:
```

### Output

Both the private key and the CSR are printed to stdout as PEM, and also
saved to disk under `output/<name>/`, where `<name>` is the Common Name
with `*` (and any path-unsafe characters) replaced:

```
output/example.com/example.com.key
output/example.com/example.com.csr
```

A wildcard CN like `*.example.com` becomes `wildcard.example.com`:

```
output/wildcard.example.com/wildcard.example.com.key
output/wildcard.example.com/wildcard.example.com.csr
```

The private key is written with `0600` permissions. By default, `ittools`
refuses to overwrite an existing key or CSR at that path — pass `--force`
to overwrite.

### Inspecting the result

```bash
openssl req -in output/example.com/example.com.csr -noout -text
```

## Development

```bash
go build ./...   # build everything
go vet ./...      # static checks
go test ./...     # run the test suite
```
