# ittools CSR Generator Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build `ittools`, a Go CLI toolkit, with its first subcommand `ittools csr generate` that produces an RSA private key + PKCS#10 CSR (mirroring csrgenerator.com's fields), saved under `output/<sanitized-cn>/`.

**Architecture:** Single Go module, single binary. `main.go` dispatches `os.Args[1]` to a `command.Command` implementation via a literal map. The only implemented command is `internal/csr`, split into pure logic (`csr.go`), file output (`output.go`), interactive prompting (`prompt.go`), and CLI flag orchestration (`cmd.go`). This keeps each file independently testable and lets future tools be added as new `internal/<tool>` packages plus one map entry in `main.go`.

**Tech Stack:** Go 1.22, standard library only (`crypto/rsa`, `crypto/x509`, `crypto/x509/pkix`, `encoding/asn1`, `encoding/pem`, `flag`, `bufio`).

**Spec:** `docs/superpowers/specs/2026-09-16-ittools-csr-design.md`

## Global Constraints

- Go stdlib only — no third-party dependencies (spec: Goals).
- RSA keys only, sizes 2048/3072/4096, default 2048 (spec: Goals/Non-goals).
- No encrypted/passphrase-protected private keys (spec: Non-goals).
- Key Usage = Digital Signature + Key Encipherment; Extended Key Usage = Server Auth + Client Auth, always added, not configurable (spec: Non-goals, Architecture).
- Output directory: `output/<sanitized-cn>/`, files `<sanitized-cn>.key` and `<sanitized-cn>.csr`; sanitization replaces `*` with `wildcard` (spec: Output).
- Adding a future subcommand must require only a new `internal/<tool>` package + one map entry in `main.go` — no framework (spec: Architecture).

---

### Task 1: Module scaffold + Command interface

**Files:**
- Create: `go.mod`
- Create: `internal/command/command.go`

**Interfaces:**
- Produces: `command.Command` interface — `Name() string`, `Run(args []string) error` — used by every subcommand package and by `main.go`'s dispatch map.

- [ ] **Step 1: Initialize the Go module**

Run: `go mod init ittools`
Expected: creates `go.mod` with `module ittools` and a `go` directive.

- [ ] **Step 2: Set the Go version in go.mod**

Open `go.mod` and ensure the `go` directive reads `go 1.22` (edit if `go mod init` picked a different local toolchain version).

- [ ] **Step 3: Write the Command interface**

Create `internal/command/command.go`:

```go
// Package command defines the interface every ittools subcommand implements.
package command

// Command is a subcommand of the ittools binary. Name is the word that
// selects it on the command line (e.g. "csr"); Run receives the remaining
// arguments after that word.
type Command interface {
	Name() string
	Run(args []string) error
}
```

- [ ] **Step 4: Verify the module builds**

Run: `go build ./...`
Expected: succeeds with no output (nothing depends on anything yet, so this just confirms `go.mod` and the package compile).

- [ ] **Step 5: Commit**

```bash
git add go.mod internal/command/command.go
git commit -m "chore: scaffold ittools module and Command interface"
```

---

### Task 2: CSR string helpers — SanitizeName and SplitSANs

**Files:**
- Create: `internal/csr/csr.go`
- Test: `internal/csr/csr_test.go`

**Interfaces:**
- Consumes: nothing yet.
- Produces: `csr.SanitizeName(cn string) string`, `csr.SplitSANs(raw string) []string` — both used by `cmd.go` (Task 7) and `prompt.go` (Task 6).

- [ ] **Step 1: Write the failing tests**

Create `internal/csr/csr_test.go`:

```go
package csr

import (
	"reflect"
	"testing"
)

func TestSanitizeName(t *testing.T) {
	cases := []struct {
		name string
		cn   string
		want string
	}{
		{"plain domain", "example.com", "example.com"},
		{"wildcard", "*.example.com", "wildcard.example.com"},
		{"nested wildcard", "*.sub.example.com", "wildcard.sub.example.com"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := SanitizeName(tc.cn)
			if got != tc.want {
				t.Errorf("SanitizeName(%q) = %q, want %q", tc.cn, got, tc.want)
			}
		})
	}
}

func TestSplitSANs(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		want []string
	}{
		{"empty", "", nil},
		{"whitespace only", "   ", nil},
		{"single", "example.com", []string{"example.com"}},
		{"multiple with spaces", "a.com, b.com ,c.com", []string{"a.com", "b.com", "c.com"}},
		{"trailing comma", "a.com,", []string{"a.com"}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := SplitSANs(tc.raw)
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("SplitSANs(%q) = %#v, want %#v", tc.raw, got, tc.want)
			}
		})
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/csr/... -run 'TestSanitizeName|TestSplitSANs' -v`
Expected: FAIL — `undefined: SanitizeName` / `undefined: SplitSANs` (package `csr` doesn't exist yet).

- [ ] **Step 3: Write the minimal implementation**

Create `internal/csr/csr.go`:

```go
// Package csr generates RSA private keys and PKCS#10 certificate signing
// requests, with the subject fields and output layout of ittools' "csr
// generate" command.
package csr

import "strings"

// SanitizeName converts a Common Name into a filesystem-safe name, replacing
// "*" with "wildcard" (e.g. "*.example.com" -> "wildcard.example.com"). It is
// used for both the output directory and file basenames.
func SanitizeName(cn string) string {
	return strings.ReplaceAll(cn, "*", "wildcard")
}

// SplitSANs parses a comma-separated Subject Alternative Names string into a
// trimmed, non-empty slice. It returns nil if raw contains no usable entries.
func SplitSANs(raw string) []string {
	parts := strings.Split(raw, ",")
	sans := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			sans = append(sans, p)
		}
	}
	if len(sans) == 0 {
		return nil
	}
	return sans
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/csr/... -run 'TestSanitizeName|TestSplitSANs' -v`
Expected: PASS for both `TestSanitizeName` and `TestSplitSANs` (all subtests).

- [ ] **Step 5: Commit**

```bash
git add internal/csr/csr.go internal/csr/csr_test.go
git commit -m "feat(csr): add SanitizeName and SplitSANs helpers"
```

---

### Task 3: CSR field validation

**Files:**
- Modify: `internal/csr/csr.go`
- Modify: `internal/csr/csr_test.go`

**Interfaces:**
- Consumes: nothing new.
- Produces: `csr.ValidateCommonName(cn string) error`, `csr.ValidateCountry(country string) error`, `csr.ValidateKeySize(bits int) error` — used by `cmd.go` (Task 7) and `prompt.go` (Task 6).

- [ ] **Step 1: Write the failing tests**

Append to `internal/csr/csr_test.go`:

```go
func TestValidateCommonName(t *testing.T) {
	if err := ValidateCommonName("example.com"); err != nil {
		t.Errorf("ValidateCommonName(\"example.com\") = %v, want nil", err)
	}
	if err := ValidateCommonName(""); err == nil {
		t.Error("ValidateCommonName(\"\") = nil, want error")
	}
	if err := ValidateCommonName("   "); err == nil {
		t.Error("ValidateCommonName(\"   \") = nil, want error")
	}
}

func TestValidateCountry(t *testing.T) {
	cases := []struct {
		name    string
		country string
		wantErr bool
	}{
		{"empty is valid (optional)", "", false},
		{"two letters upper", "VN", false},
		{"two letters lower", "vn", false},
		{"one letter", "V", true},
		{"three letters", "VNM", true},
		{"digits", "12", true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateCountry(tc.country)
			if (err != nil) != tc.wantErr {
				t.Errorf("ValidateCountry(%q) error = %v, wantErr %v", tc.country, err, tc.wantErr)
			}
		})
	}
}

func TestValidateKeySize(t *testing.T) {
	for _, bits := range []int{2048, 3072, 4096} {
		if err := ValidateKeySize(bits); err != nil {
			t.Errorf("ValidateKeySize(%d) = %v, want nil", bits, err)
		}
	}
	for _, bits := range []int{1024, 2049, 8192, 0} {
		if err := ValidateKeySize(bits); err == nil {
			t.Errorf("ValidateKeySize(%d) = nil, want error", bits)
		}
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/csr/... -run 'TestValidateCommonName|TestValidateCountry|TestValidateKeySize' -v`
Expected: FAIL — `undefined: ValidateCommonName` (and the other two).

- [ ] **Step 3: Write the minimal implementation**

Append to `internal/csr/csr.go` (add `errors` and `fmt` to the import block, changing it to):

```go
import (
	"errors"
	"fmt"
	"strings"
)
```

Then append:

```go
// ValidateCommonName returns an error if cn is empty or whitespace-only.
func ValidateCommonName(cn string) error {
	if strings.TrimSpace(cn) == "" {
		return errors.New("common name is required")
	}
	return nil
}

// ValidateCountry returns an error unless country is empty (it's optional)
// or exactly two ASCII letters, per the X.509 country attribute format.
func ValidateCountry(country string) error {
	if country == "" {
		return nil
	}
	if len(country) != 2 {
		return fmt.Errorf("country must be exactly 2 letters, got %q", country)
	}
	for _, r := range country {
		if (r < 'A' || r > 'Z') && (r < 'a' || r > 'z') {
			return fmt.Errorf("country must contain only letters, got %q", country)
		}
	}
	return nil
}

// ValidateKeySize returns an error unless bits is one of the supported RSA
// key sizes.
func ValidateKeySize(bits int) error {
	switch bits {
	case 2048, 3072, 4096:
		return nil
	default:
		return fmt.Errorf("key size must be 2048, 3072, or 4096, got %d", bits)
	}
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/csr/... -v`
Expected: PASS for all tests in the package so far.

- [ ] **Step 5: Commit**

```bash
git add internal/csr/csr.go internal/csr/csr_test.go
git commit -m "feat(csr): add field validation for CN, country, key size"
```

---

### Task 4: Key generation and CSR building with Key Usage / Extended Key Usage

**Files:**
- Modify: `internal/csr/csr.go`
- Modify: `internal/csr/csr_test.go`

**Interfaces:**
- Consumes: nothing new from this package.
- Produces:
  - `csr.Subject` struct — fields `CommonName, Organization, OrganizationalUnit, City, State, Country, Email string`.
  - `csr.GenerateKey(bits int) (*rsa.PrivateKey, error)`
  - `csr.BuildCSR(key *rsa.PrivateKey, subject Subject, sans []string) ([]byte, error)` — returns DER-encoded CSR bytes.
  - `csr.EncodeKeyPEM(key *rsa.PrivateKey) []byte`
  - `csr.EncodeCSRPEM(der []byte) []byte`
  - All four are used by `cmd.go` (Task 7).

- [ ] **Step 1: Write the failing test**

Change the `import` block at the top of `internal/csr/csr_test.go` to:

```go
import (
	"crypto/x509"
	"reflect"
	"strings"
	"testing"
)
```

Then append:

```go
func TestBuildCSR(t *testing.T) {
	key, err := GenerateKey(2048)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	subject := Subject{
		CommonName:         "*.example.com",
		Organization:       "Acme Inc",
		OrganizationalUnit: "IT",
		City:               "Hanoi",
		State:              "Hanoi",
		Country:            "VN",
		Email:              "admin@example.com",
	}
	sans := []string{"example.com", "www.example.com"}

	der, err := BuildCSR(key, subject, sans)
	if err != nil {
		t.Fatalf("BuildCSR: %v", err)
	}

	parsed, err := x509.ParseCertificateRequest(der)
	if err != nil {
		t.Fatalf("ParseCertificateRequest: %v", err)
	}

	if parsed.Subject.CommonName != subject.CommonName {
		t.Errorf("CommonName = %q, want %q", parsed.Subject.CommonName, subject.CommonName)
	}
	if !reflect.DeepEqual(parsed.Subject.Organization, []string{subject.Organization}) {
		t.Errorf("Organization = %v, want %v", parsed.Subject.Organization, []string{subject.Organization})
	}
	if !reflect.DeepEqual(parsed.Subject.Country, []string{subject.Country}) {
		t.Errorf("Country = %v, want %v", parsed.Subject.Country, []string{subject.Country})
	}
	if !reflect.DeepEqual(parsed.DNSNames, sans) {
		t.Errorf("DNSNames = %v, want %v", parsed.DNSNames, sans)
	}

	if err := parsed.CheckSignature(); err != nil {
		t.Errorf("CheckSignature: %v", err)
	}

	var keyUsageOID = []int{2, 5, 29, 15}
	var extKeyUsageOID = []int{2, 5, 29, 37}
	foundKeyUsage := false
	foundExtKeyUsage := false
	for _, ext := range parsed.Extensions {
		if ext.Id.Equal(keyUsageOID) {
			foundKeyUsage = true
			if len(ext.Value) == 0 {
				t.Error("key usage extension has empty value")
			}
		}
		if ext.Id.Equal(extKeyUsageOID) {
			foundExtKeyUsage = true
			if len(ext.Value) == 0 {
				t.Error("extended key usage extension has empty value")
			}
		}
	}
	if !foundKeyUsage {
		t.Error("CSR missing Key Usage extension")
	}
	if !foundExtKeyUsage {
		t.Error("CSR missing Extended Key Usage extension")
	}
}

func TestEncodePEM(t *testing.T) {
	key, err := GenerateKey(2048)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	der, err := BuildCSR(key, Subject{CommonName: "example.com"}, nil)
	if err != nil {
		t.Fatalf("BuildCSR: %v", err)
	}

	keyPEM := EncodeKeyPEM(key)
	if !containsPEMHeader(keyPEM, "RSA PRIVATE KEY") {
		t.Errorf("EncodeKeyPEM output missing RSA PRIVATE KEY header: %s", keyPEM)
	}

	csrPEM := EncodeCSRPEM(der)
	if !containsPEMHeader(csrPEM, "CERTIFICATE REQUEST") {
		t.Errorf("EncodeCSRPEM output missing CERTIFICATE REQUEST header: %s", csrPEM)
	}
}

func containsPEMHeader(pemBytes []byte, header string) bool {
	return strings.Contains(string(pemBytes), "-----BEGIN "+header+"-----")
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/csr/... -run 'TestBuildCSR|TestEncodePEM' -v`
Expected: FAIL — `undefined: GenerateKey`, `undefined: BuildCSR`, `undefined: Subject`, `undefined: EncodeKeyPEM`, `undefined: EncodeCSRPEM`.

- [ ] **Step 3: Write the minimal implementation**

Update the import block at the top of `internal/csr/csr.go` to:

```go
import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
)
```

Then append to `internal/csr/csr.go`:

```go
// Subject holds the CSR subject fields, matching the form fields of a
// typical web-based CSR generator.
type Subject struct {
	CommonName         string
	Organization       string
	OrganizationalUnit string
	City               string
	State              string
	Country            string
	Email              string
}

var (
	oidExtensionKeyUsage         = asn1.ObjectIdentifier{2, 5, 29, 15}
	oidExtensionExtendedKeyUsage = asn1.ObjectIdentifier{2, 5, 29, 37}
	oidExtKeyUsageServerAuth     = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 1}
	oidExtKeyUsageClientAuth     = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 2}
	oidEmailAddress              = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 1}
)

// GenerateKey creates a new RSA private key of the given bit size.
func GenerateKey(bits int) (*rsa.PrivateKey, error) {
	key, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, fmt.Errorf("generate rsa key: %w", err)
	}
	return key, nil
}

// BuildCSR creates a DER-encoded PKCS#10 certificate request signed by key,
// for the given subject and optional SANs. It always requests a Key Usage
// extension (Digital Signature + Key Encipherment) and an Extended Key Usage
// extension (Server Auth + Client Auth), matching a standard TLS server
// certificate profile.
func BuildCSR(key *rsa.PrivateKey, subject Subject, sans []string) ([]byte, error) {
	name := pkix.Name{
		CommonName: subject.CommonName,
	}
	if subject.Organization != "" {
		name.Organization = []string{subject.Organization}
	}
	if subject.OrganizationalUnit != "" {
		name.OrganizationalUnit = []string{subject.OrganizationalUnit}
	}
	if subject.City != "" {
		name.Locality = []string{subject.City}
	}
	if subject.State != "" {
		name.Province = []string{subject.State}
	}
	if subject.Country != "" {
		name.Country = []string{subject.Country}
	}
	if subject.Email != "" {
		name.ExtraNames = append(name.ExtraNames, pkix.AttributeTypeAndValue{
			Type:  oidEmailAddress,
			Value: subject.Email,
		})
	}

	keyUsageValue, err := marshalKeyUsage()
	if err != nil {
		return nil, fmt.Errorf("marshal key usage: %w", err)
	}
	extKeyUsageValue, err := marshalExtendedKeyUsage()
	if err != nil {
		return nil, fmt.Errorf("marshal extended key usage: %w", err)
	}

	template := &x509.CertificateRequest{
		Subject:            name,
		DNSNames:           sans,
		SignatureAlgorithm: x509.SHA256WithRSA,
		ExtraExtensions: []pkix.Extension{
			{Id: oidExtensionKeyUsage, Critical: true, Value: keyUsageValue},
			{Id: oidExtensionExtendedKeyUsage, Critical: false, Value: extKeyUsageValue},
		},
	}

	der, err := x509.CreateCertificateRequest(rand.Reader, template, key)
	if err != nil {
		return nil, fmt.Errorf("create certificate request: %w", err)
	}
	return der, nil
}

// marshalKeyUsage returns the DER encoding of a KeyUsage BIT STRING with
// digitalSignature (bit 0) and keyEncipherment (bit 2) set, per RFC 5280
// §4.2.1.3. ASN.1 BIT STRINGs are MSB-first, so bit 0 is byte value 0x80 and
// bit 2 is 0x20; BitLength 3 marks bits 0-2 as significant.
func marshalKeyUsage() ([]byte, error) {
	return asn1.Marshal(asn1.BitString{Bytes: []byte{0x80 | 0x20}, BitLength: 3})
}

// marshalExtendedKeyUsage returns the DER encoding of an ExtKeyUsageSyntax
// SEQUENCE containing the Server Auth and Client Auth key purpose OIDs.
func marshalExtendedKeyUsage() ([]byte, error) {
	oids := []asn1.ObjectIdentifier{oidExtKeyUsageServerAuth, oidExtKeyUsageClientAuth}
	return asn1.Marshal(oids)
}

// EncodeKeyPEM encodes key as a PKCS#1 "RSA PRIVATE KEY" PEM block.
func EncodeKeyPEM(key *rsa.PrivateKey) []byte {
	return pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})
}

// EncodeCSRPEM encodes DER-encoded CSR bytes as a "CERTIFICATE REQUEST" PEM
// block.
func EncodeCSRPEM(der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: der,
	})
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `gofmt -w internal/csr/csr.go internal/csr/csr_test.go && go test ./internal/csr/... -v`
Expected: PASS for `TestBuildCSR`, `TestEncodePEM`, and all earlier tests in the package.

- [ ] **Step 5: Commit**

```bash
git add internal/csr/csr.go internal/csr/csr_test.go
git commit -m "feat(csr): generate RSA keys and build CSRs with Key Usage/EKU"
```

---

### Task 5: Output writing

**Files:**
- Create: `internal/csr/output.go`
- Create: `internal/csr/output_test.go`

**Interfaces:**
- Consumes: nothing from other files (takes raw `[]byte` PEM content).
- Produces: `csr.WriteOutput(dir, name string, keyPEM, csrPEM []byte, force bool) (keyPath, csrPath string, err error)` — used by `cmd.go` (Task 7).

- [ ] **Step 1: Write the failing tests**

Create `internal/csr/output_test.go`:

```go
package csr

import (
	"os"
	"path/filepath"
	"testing"
)

func TestWriteOutput(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "example.com")

	keyPath, csrPath, err := WriteOutput(target, "example.com", []byte("KEYDATA"), []byte("CSRDATA"), false)
	if err != nil {
		t.Fatalf("WriteOutput: %v", err)
	}

	if keyPath != filepath.Join(target, "example.com.key") {
		t.Errorf("keyPath = %q, want %q", keyPath, filepath.Join(target, "example.com.key"))
	}
	if csrPath != filepath.Join(target, "example.com.csr") {
		t.Errorf("csrPath = %q, want %q", csrPath, filepath.Join(target, "example.com.csr"))
	}

	gotKey, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatalf("read key file: %v", err)
	}
	if string(gotKey) != "KEYDATA" {
		t.Errorf("key file content = %q, want %q", gotKey, "KEYDATA")
	}

	gotCSR, err := os.ReadFile(csrPath)
	if err != nil {
		t.Fatalf("read csr file: %v", err)
	}
	if string(gotCSR) != "CSRDATA" {
		t.Errorf("csr file content = %q, want %q", gotCSR, "CSRDATA")
	}
}

func TestWriteOutputRefusesOverwriteWithoutForce(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "example.com")

	if _, _, err := WriteOutput(target, "example.com", []byte("KEYDATA"), []byte("CSRDATA"), false); err != nil {
		t.Fatalf("first WriteOutput: %v", err)
	}

	_, _, err := WriteOutput(target, "example.com", []byte("NEWKEY"), []byte("NEWCSR"), false)
	if err == nil {
		t.Fatal("second WriteOutput without force = nil error, want error")
	}

	gotKey, readErr := os.ReadFile(filepath.Join(target, "example.com.key"))
	if readErr != nil {
		t.Fatalf("read key file: %v", readErr)
	}
	if string(gotKey) != "KEYDATA" {
		t.Errorf("key file was overwritten: got %q, want original %q", gotKey, "KEYDATA")
	}
}

func TestWriteOutputForceOverwrites(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "example.com")

	if _, _, err := WriteOutput(target, "example.com", []byte("KEYDATA"), []byte("CSRDATA"), false); err != nil {
		t.Fatalf("first WriteOutput: %v", err)
	}

	if _, _, err := WriteOutput(target, "example.com", []byte("NEWKEY"), []byte("NEWCSR"), true); err != nil {
		t.Fatalf("second WriteOutput with force: %v", err)
	}

	gotKey, err := os.ReadFile(filepath.Join(target, "example.com.key"))
	if err != nil {
		t.Fatalf("read key file: %v", err)
	}
	if string(gotKey) != "NEWKEY" {
		t.Errorf("key file content = %q, want %q", gotKey, "NEWKEY")
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/csr/... -run TestWriteOutput -v`
Expected: FAIL — `undefined: WriteOutput`.

- [ ] **Step 3: Write the minimal implementation**

Create `internal/csr/output.go`:

```go
package csr

import (
	"fmt"
	"os"
	"path/filepath"
)

// WriteOutput writes keyPEM and csrPEM to dir/name.key and dir/name.csr,
// creating dir if needed. If either target file already exists and force is
// false, it returns an error without writing anything.
func WriteOutput(dir, name string, keyPEM, csrPEM []byte, force bool) (keyPath, csrPath string, err error) {
	keyPath = filepath.Join(dir, name+".key")
	csrPath = filepath.Join(dir, name+".csr")

	if !force {
		if _, statErr := os.Stat(keyPath); statErr == nil {
			return "", "", fmt.Errorf("%s already exists (use --force to overwrite)", keyPath)
		}
		if _, statErr := os.Stat(csrPath); statErr == nil {
			return "", "", fmt.Errorf("%s already exists (use --force to overwrite)", csrPath)
		}
	}

	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", "", fmt.Errorf("create output directory: %w", err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		return "", "", fmt.Errorf("write private key: %w", err)
	}
	if err := os.WriteFile(csrPath, csrPEM, 0o644); err != nil {
		return "", "", fmt.Errorf("write csr: %w", err)
	}
	return keyPath, csrPath, nil
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/csr/... -run TestWriteOutput -v`
Expected: PASS for `TestWriteOutput`, `TestWriteOutputRefusesOverwriteWithoutForce`, `TestWriteOutputForceOverwrites`.

- [ ] **Step 5: Commit**

```bash
git add internal/csr/output.go internal/csr/output_test.go
git commit -m "feat(csr): write key/CSR output files with overwrite protection"
```

---

### Task 6: Interactive prompt

**Files:**
- Create: `internal/csr/prompt.go`
- Create: `internal/csr/prompt_test.go`

**Interfaces:**
- Consumes: `csr.Subject` (Task 4), `csr.ValidateCommonName`, `csr.ValidateCountry`, `csr.ValidateKeySize` (Task 3), `csr.SplitSANs` (Task 2).
- Produces: `csr.PromptSubject(r io.Reader, w io.Writer) (subject Subject, sans []string, keySize int, err error)` — used by `cmd.go` (Task 7).

- [ ] **Step 1: Write the failing test**

Create `internal/csr/prompt_test.go`:

```go
package csr

import (
	"reflect"
	"strings"
	"testing"
)

func TestPromptSubjectHappyPath(t *testing.T) {
	input := strings.Join([]string{
		"example.com", // Common Name
		"Acme Inc",    // Organization
		"IT",          // Organizational Unit
		"Hanoi",       // City
		"Hanoi",       // State
		"VN",          // Country
		"admin@example.com", // Email
		"a.com, b.com",      // SANs
		"3072",              // Key size
	}, "\n") + "\n"

	r := strings.NewReader(input)
	var w strings.Builder

	subject, sans, keySize, err := PromptSubject(r, &w)
	if err != nil {
		t.Fatalf("PromptSubject: %v", err)
	}

	want := Subject{
		CommonName:         "example.com",
		Organization:       "Acme Inc",
		OrganizationalUnit: "IT",
		City:               "Hanoi",
		State:              "Hanoi",
		Country:            "VN",
		Email:              "admin@example.com",
	}
	if subject != want {
		t.Errorf("subject = %+v, want %+v", subject, want)
	}
	if !reflect.DeepEqual(sans, []string{"a.com", "b.com"}) {
		t.Errorf("sans = %v, want %v", sans, []string{"a.com", "b.com"})
	}
	if keySize != 3072 {
		t.Errorf("keySize = %d, want 3072", keySize)
	}
}

func TestPromptSubjectDefaultsKeySize(t *testing.T) {
	input := strings.Join([]string{
		"example.com", "", "", "", "", "", "", "", "",
	}, "\n") + "\n"

	subject, _, keySize, err := PromptSubject(strings.NewReader(input), &strings.Builder{})
	if err != nil {
		t.Fatalf("PromptSubject: %v", err)
	}
	if subject.CommonName != "example.com" {
		t.Errorf("CommonName = %q, want %q", subject.CommonName, "example.com")
	}
	if keySize != 2048 {
		t.Errorf("keySize = %d, want default 2048", keySize)
	}
}

func TestPromptSubjectReprompsOnEmptyCommonName(t *testing.T) {
	input := "\nexample.com\n\n\n\n\n\n\n\n\n"

	subject, _, _, err := PromptSubject(strings.NewReader(input), &strings.Builder{})
	if err != nil {
		t.Fatalf("PromptSubject: %v", err)
	}
	if subject.CommonName != "example.com" {
		t.Errorf("CommonName = %q, want %q (should reprompt past blank line)", subject.CommonName, "example.com")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/csr/... -run TestPromptSubject -v`
Expected: FAIL — `undefined: PromptSubject`.

- [ ] **Step 3: Write the minimal implementation**

Create `internal/csr/prompt.go`:

```go
package csr

import (
	"bufio"
	"fmt"
	"io"
	"strconv"
	"strings"
)

// PromptSubject interactively asks for each CSR field on r, writing prompts
// to w. It re-prompts on invalid Common Name, Country, or key size answers.
func PromptSubject(r io.Reader, w io.Writer) (Subject, []string, int, error) {
	scanner := bufio.NewScanner(r)

	ask := func(label string) (string, error) {
		fmt.Fprintf(w, "%s: ", label)
		if !scanner.Scan() {
			if err := scanner.Err(); err != nil {
				return "", err
			}
			return "", io.EOF
		}
		return strings.TrimSpace(scanner.Text()), nil
	}

	var subject Subject

	for {
		cn, err := ask("Common Name")
		if err != nil {
			return Subject{}, nil, 0, err
		}
		if err := ValidateCommonName(cn); err != nil {
			fmt.Fprintln(w, err)
			continue
		}
		subject.CommonName = cn
		break
	}

	var err error
	if subject.Organization, err = ask("Organization"); err != nil {
		return Subject{}, nil, 0, err
	}
	if subject.OrganizationalUnit, err = ask("Organizational Unit"); err != nil {
		return Subject{}, nil, 0, err
	}
	if subject.City, err = ask("City"); err != nil {
		return Subject{}, nil, 0, err
	}
	if subject.State, err = ask("State"); err != nil {
		return Subject{}, nil, 0, err
	}

	for {
		country, err := ask("Country (2-letter code)")
		if err != nil {
			return Subject{}, nil, 0, err
		}
		if err := ValidateCountry(country); err != nil {
			fmt.Fprintln(w, err)
			continue
		}
		subject.Country = country
		break
	}

	if subject.Email, err = ask("Email"); err != nil {
		return Subject{}, nil, 0, err
	}

	sanRaw, err := ask("Subject Alternative Names (comma-separated, optional)")
	if err != nil {
		return Subject{}, nil, 0, err
	}
	sans := SplitSANs(sanRaw)

	var keySize int
	for {
		ksRaw, err := ask("Key size (2048, 3072, 4096) [2048]")
		if err != nil {
			return Subject{}, nil, 0, err
		}
		if ksRaw == "" {
			keySize = 2048
			break
		}
		n, convErr := strconv.Atoi(ksRaw)
		if convErr != nil {
			fmt.Fprintln(w, "key size must be a number")
			continue
		}
		if err := ValidateKeySize(n); err != nil {
			fmt.Fprintln(w, err)
			continue
		}
		keySize = n
		break
	}

	return subject, sans, keySize, nil
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/csr/... -run TestPromptSubject -v`
Expected: PASS for `TestPromptSubjectHappyPath`, `TestPromptSubjectDefaultsKeySize`, `TestPromptSubjectReprompsOnEmptyCommonName`.

- [ ] **Step 5: Run the full package test suite**

Run: `go test ./internal/csr/... -v`
Expected: PASS for every test written in Tasks 2-6.

- [ ] **Step 6: Commit**

```bash
git add internal/csr/prompt.go internal/csr/prompt_test.go
git commit -m "feat(csr): add interactive prompt for CSR fields"
```

---

### Task 7: CLI orchestration (`csr generate` command)

**Files:**
- Create: `internal/csr/cmd.go`
- Create: `internal/csr/cmd_test.go`

**Interfaces:**
- Consumes: `command.Command` (Task 1); `csr.Subject`, `csr.GenerateKey`, `csr.BuildCSR`, `csr.EncodeKeyPEM`, `csr.EncodeCSRPEM` (Task 4); `csr.WriteOutput` (Task 5); `csr.PromptSubject` (Task 6); `csr.SanitizeName`, `csr.SplitSANs` (Task 2); `csr.ValidateCommonName`, `csr.ValidateCountry`, `csr.ValidateKeySize` (Task 3).
- Produces: `csr.New() command.Command` — used by `main.go` (Task 8). `Tool.Name() string` returns `"csr"`. `Tool.Run(args []string) error` dispatches `generate`.

- [ ] **Step 1: Write the failing tests**

Create `internal/csr/cmd_test.go`:

```go
package csr

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func chdirTemp(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("Getwd: %v", err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatalf("Chdir: %v", err)
	}
	t.Cleanup(func() {
		if err := os.Chdir(wd); err != nil {
			t.Fatalf("Chdir back: %v", err)
		}
	})
	return dir
}

func TestRunGenerateWithFlags(t *testing.T) {
	chdirTemp(t)

	var stdout strings.Builder
	err := runGenerate([]string{
		"--cn", "*.example.com",
		"--org", "Acme Inc",
		"--country", "VN",
		"--san", "example.com,www.example.com",
		"--key-size", "2048",
	}, strings.NewReader(""), &stdout)
	if err != nil {
		t.Fatalf("runGenerate: %v", err)
	}

	out := stdout.String()
	if !strings.Contains(out, "-----BEGIN RSA PRIVATE KEY-----") {
		t.Error("stdout missing private key PEM")
	}
	if !strings.Contains(out, "-----BEGIN CERTIFICATE REQUEST-----") {
		t.Error("stdout missing CSR PEM")
	}

	keyPath := filepath.Join("output", "wildcard.example.com", "wildcard.example.com.key")
	csrPath := filepath.Join("output", "wildcard.example.com", "wildcard.example.com.csr")
	if _, err := os.Stat(keyPath); err != nil {
		t.Errorf("expected key file at %s: %v", keyPath, err)
	}
	if _, err := os.Stat(csrPath); err != nil {
		t.Errorf("expected csr file at %s: %v", csrPath, err)
	}
}

func TestRunGenerateMissingCommonNameFails(t *testing.T) {
	chdirTemp(t)

	err := runGenerate([]string{"--org", "Acme"}, strings.NewReader(""), &strings.Builder{})
	if err == nil {
		t.Fatal("runGenerate with no --cn = nil error, want error")
	}
}

func TestRunGenerateRefusesOverwriteWithoutForce(t *testing.T) {
	chdirTemp(t)

	args := []string{"--cn", "example.com"}
	if err := runGenerate(args, strings.NewReader(""), &strings.Builder{}); err != nil {
		t.Fatalf("first runGenerate: %v", err)
	}
	if err := runGenerate(args, strings.NewReader(""), &strings.Builder{}); err == nil {
		t.Fatal("second runGenerate without --force = nil error, want error")
	}
	if err := runGenerate(append(args, "--force"), strings.NewReader(""), &strings.Builder{}); err != nil {
		t.Fatalf("runGenerate with --force: %v", err)
	}
}

func TestRunGenerateInteractiveWhenNoArgs(t *testing.T) {
	chdirTemp(t)

	input := strings.Join([]string{
		"example.com", "", "", "", "", "", "", "", "",
	}, "\n") + "\n"

	if err := runGenerate(nil, strings.NewReader(input), &strings.Builder{}); err != nil {
		t.Fatalf("runGenerate interactive: %v", err)
	}

	if _, err := os.Stat(filepath.Join("output", "example.com", "example.com.key")); err != nil {
		t.Errorf("expected key file: %v", err)
	}
}

func TestToolRunUnknownVerb(t *testing.T) {
	tool := New()
	if err := tool.Run([]string{"bogus"}); err == nil {
		t.Fatal("Run with unknown verb = nil error, want error")
	}
}

func TestToolName(t *testing.T) {
	if got := New().Name(); got != "csr" {
		t.Errorf("Name() = %q, want %q", got, "csr")
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/csr/... -run 'TestRunGenerate|TestTool' -v`
Expected: FAIL — `undefined: runGenerate`, `undefined: New`.

- [ ] **Step 3: Write the minimal implementation**

Create `internal/csr/cmd.go`:

```go
package csr

import (
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"ittools/internal/command"
)

// Tool implements command.Command for the "csr" subcommand group.
type Tool struct{}

// New returns the csr Command, registered in main.go under the name "csr".
func New() command.Command { return Tool{} }

// Name returns "csr".
func (Tool) Name() string { return "csr" }

// Run dispatches to the "generate" verb; any other or missing verb is an
// error.
func (Tool) Run(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: ittools csr generate [flags]")
	}
	switch args[0] {
	case "generate":
		return runGenerate(args[1:], os.Stdin, os.Stdout)
	default:
		return fmt.Errorf("unknown csr subcommand %q (expected: generate)", args[0])
	}
}

// runGenerate implements "csr generate": it parses flags (or, if none are
// given, prompts interactively on stdin/stdout), validates the subject,
// generates a key and CSR, writes them under output/<name>/, and also
// prints both PEM blocks to stdout.
func runGenerate(args []string, stdin io.Reader, stdout io.Writer) error {
	fs := flag.NewFlagSet("csr generate", flag.ContinueOnError)
	cn := fs.String("cn", "", "Common Name")
	org := fs.String("org", "", "Organization")
	ou := fs.String("ou", "", "Organizational Unit")
	city := fs.String("city", "", "City/Locality")
	state := fs.String("state", "", "State/Province")
	country := fs.String("country", "", "Country (2-letter code)")
	email := fs.String("email", "", "Email address")
	san := fs.String("san", "", "Comma-separated Subject Alternative Names")
	keySize := fs.Int("key-size", 2048, "RSA key size (2048, 3072, 4096)")
	force := fs.Bool("force", false, "Overwrite existing output files")

	if err := fs.Parse(args); err != nil {
		return err
	}

	var subject Subject
	var sans []string
	var bits int

	if len(args) == 0 {
		var err error
		subject, sans, bits, err = PromptSubject(stdin, stdout)
		if err != nil {
			return fmt.Errorf("read input: %w", err)
		}
	} else {
		subject = Subject{
			CommonName:         *cn,
			Organization:       *org,
			OrganizationalUnit: *ou,
			City:               *city,
			State:              *state,
			Country:            *country,
			Email:              *email,
		}
		sans = SplitSANs(*san)
		bits = *keySize

		if err := ValidateCommonName(subject.CommonName); err != nil {
			return err
		}
		if err := ValidateCountry(subject.Country); err != nil {
			return err
		}
		if err := ValidateKeySize(bits); err != nil {
			return err
		}
	}

	key, err := GenerateKey(bits)
	if err != nil {
		return err
	}

	der, err := BuildCSR(key, subject, sans)
	if err != nil {
		return err
	}

	keyPEM := EncodeKeyPEM(key)
	csrPEM := EncodeCSRPEM(der)

	name := SanitizeName(subject.CommonName)
	dir := filepath.Join("output", name)

	keyPath, csrPath, err := WriteOutput(dir, name, keyPEM, csrPEM, *force)
	if err != nil {
		return err
	}

	if _, err := stdout.Write(keyPEM); err != nil {
		return err
	}
	if _, err := stdout.Write(csrPEM); err != nil {
		return err
	}
	fmt.Fprintf(stdout, "Saved private key to %s\n", keyPath)
	fmt.Fprintf(stdout, "Saved CSR to %s\n", csrPath)

	return nil
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/csr/... -v`
Expected: PASS for every test in the package, including the new `TestRunGenerate*`, `TestToolRunUnknownVerb`, `TestToolName`.

- [ ] **Step 5: Commit**

```bash
git add internal/csr/cmd.go internal/csr/cmd_test.go
git commit -m "feat(csr): wire up csr generate CLI command"
```

---

### Task 8: main.go entry point and dispatch

**Files:**
- Create: `main.go`
- Create: `main_test.go`

**Interfaces:**
- Consumes: `command.Command` (Task 1), `csr.New() command.Command` (Task 7).
- Produces: `run(args []string, stderr io.Writer) int` (package `main`, unexported, used only by `main()` and its own test).

- [ ] **Step 1: Write the failing tests**

Create `main_test.go`:

```go
package main

import (
	"strings"
	"testing"
)

func TestRunUnknownCommand(t *testing.T) {
	var stderr strings.Builder
	code := run([]string{"ittools", "bogus"}, &stderr)
	if code != 1 {
		t.Errorf("exit code = %d, want 1", code)
	}
	if !strings.Contains(stderr.String(), "unknown command") {
		t.Errorf("stderr = %q, want it to mention unknown command", stderr.String())
	}
}

func TestRunNoArgsPrintsUsage(t *testing.T) {
	var stderr strings.Builder
	code := run([]string{"ittools"}, &stderr)
	if code != 1 {
		t.Errorf("exit code = %d, want 1", code)
	}
	if !strings.Contains(stderr.String(), "usage") {
		t.Errorf("stderr = %q, want it to contain usage", stderr.String())
	}
}

func TestRunKnownCommandPropagatesError(t *testing.T) {
	var stderr strings.Builder
	code := run([]string{"ittools", "csr", "bogus-verb"}, &stderr)
	if code != 1 {
		t.Errorf("exit code = %d, want 1", code)
	}
	if !strings.Contains(stderr.String(), "unknown csr subcommand") {
		t.Errorf("stderr = %q, want it to mention the unknown csr subcommand", stderr.String())
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test . -run TestRun -v`
Expected: FAIL to compile — `undefined: run` (package `main` has no `main.go` yet, only the test file).

- [ ] **Step 3: Write the minimal implementation**

Create `main.go`:

```go
// Command ittools is a toolkit of small IT utilities, organized as
// subcommands (e.g. "ittools csr generate").
package main

import (
	"fmt"
	"io"
	"os"

	"ittools/internal/command"
	"ittools/internal/csr"
)

func main() {
	os.Exit(run(os.Args, os.Stderr))
}

// run dispatches args[1] to a registered command, returning the process
// exit code. It writes errors and usage text to stderr.
func run(args []string, stderr io.Writer) int {
	commands := map[string]command.Command{
		"csr": csr.New(),
	}

	if len(args) < 2 {
		fmt.Fprintln(stderr, usage(commands))
		return 1
	}

	cmd, ok := commands[args[1]]
	if !ok {
		fmt.Fprintf(stderr, "unknown command %q\n%s\n", args[1], usage(commands))
		return 1
	}

	if err := cmd.Run(args[2:]); err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return 1
	}
	return 0
}

func usage(commands map[string]command.Command) string {
	s := "usage: ittools <command> [args]\n\navailable commands:"
	for name := range commands {
		s += "\n  " + name
	}
	return s
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test . -run TestRun -v`
Expected: PASS for `TestRunUnknownCommand`, `TestRunNoArgsPrintsUsage`, `TestRunKnownCommandPropagatesError`.

- [ ] **Step 5: Run the entire test suite**

Run: `go build ./... && go vet ./... && go test ./...`
Expected: build succeeds, vet reports nothing, all tests across `.` and `./internal/csr` PASS.

- [ ] **Step 6: Commit**

```bash
git add main.go main_test.go
git commit -m "feat: add ittools main entry point with csr subcommand dispatch"
```

---

### Task 9: End-to-end manual smoke test

**Files:** none (verification only, no code changes).

**Interfaces:** none — this task exercises the built binary as a user would.

- [ ] **Step 1: Build the binary**

Run: `go build -o /tmp/ittools .`
Expected: succeeds, produces `/tmp/ittools`.

- [ ] **Step 2: Run a non-interactive generate with a wildcard CN**

Run (from a scratch directory, e.g. `cd /tmp && mkdir -p ittools-smoke && cd ittools-smoke`):

```bash
/tmp/ittools csr generate --cn '*.example.com' --org "Acme Inc" --country VN --san 'example.com,www.example.com' --key-size 2048
```

Expected: stdout shows a `-----BEGIN RSA PRIVATE KEY-----` block and a `-----BEGIN CERTIFICATE REQUEST-----` block, followed by two "Saved ..." lines; `output/wildcard.example.com/wildcard.example.com.key` and `.csr` exist in the current directory.

- [ ] **Step 3: Inspect the CSR with OpenSSL, if available**

Run: `openssl req -in output/wildcard.example.com/wildcard.example.com.csr -noout -text 2>&1 || echo "openssl not available, skipping"`
Expected (if openssl is present): shows `Subject: C = VN, O = Acme Inc, CN = *.example.com`, `X509v3 Subject Alternative Name: DNS:example.com, DNS:www.example.com`, and `X509v3 Key Usage: critical / Digital Signature, Key Encipherment` plus `X509v3 Extended Key Usage: TLS Web Server Authentication, TLS Web Client Authentication`. If openssl isn't installed, this step is skipped — the automated `TestBuildCSR` test from Task 4 already verifies these fields programmatically.

- [ ] **Step 4: Confirm overwrite protection**

Run the same generate command again without `--force`.
Expected: exits non-zero with an error mentioning the existing file and `--force`.

Run it again with `--force` appended.
Expected: succeeds and overwrites the files.

- [ ] **Step 5: Try the interactive path**

Run: `/tmp/ittools csr generate` with no flags, and answer the prompts (Common Name required, everything else optional/Enter to accept default).
Expected: prompts appear in order (Common Name, Organization, Organizational Unit, City, State, Country, Email, SANs, Key size), and on completion the same two-PEM-blocks-plus-saved-paths output appears.

- [ ] **Step 6: Report results**

No commit for this task — report back (in chat) that the smoke test passed, noting whether openssl was available for Step 3.

---

## Self-Review Notes

- **Spec coverage:** Command interface/registry (Task 1), SanitizeName/SplitSANs (Task 2), field validation (Task 3), key+CSR generation with fixed Key Usage/EKU (Task 4), output writing with `--force` (Task 5), interactive prompt (Task 6), flag-based + interactive `csr generate` orchestration (Task 7), `main.go` dispatch (Task 8), manual end-to-end verification against the real csrgenerator.com-style fields (Task 9) — every spec section has a task.
- **Type consistency:** `Subject` fields, `PromptSubject` signature `(Subject, []string, int, error)`, `WriteOutput` signature `(keyPath, csrPath string, err error)`, and `command.Command`'s `Run(args []string) error` are used identically across Tasks 4-8.
- **No placeholders:** every step has literal, runnable code and exact shell commands.
