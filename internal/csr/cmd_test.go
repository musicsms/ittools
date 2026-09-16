package csr

import (
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"reflect"
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

func TestRunGenerateNormalizesFlagFields(t *testing.T) {
	chdirTemp(t)

	var stdout strings.Builder
	err := runGenerate([]string{
		"--cn", "  example.com  ",
		"--country", "vn",
	}, strings.NewReader(""), &stdout)
	if err != nil {
		t.Fatalf("runGenerate: %v", err)
	}

	csrPath := filepath.Join("output", "example.com", "example.com.csr")
	csrPEM, err := os.ReadFile(csrPath)
	if err != nil {
		t.Fatalf("read csr file: %v", err)
	}
	block, _ := pem.Decode(csrPEM)
	if block == nil {
		t.Fatal("failed to decode csr PEM")
	}
	parsed, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		t.Fatalf("ParseCertificateRequest: %v", err)
	}
	if parsed.Subject.CommonName != "example.com" {
		t.Errorf("CommonName = %q, want %q (untrimmed input should be trimmed)", parsed.Subject.CommonName, "example.com")
	}
	if !reflect.DeepEqual(parsed.Subject.Country, []string{"VN"}) {
		t.Errorf("Country = %v, want %v (lowercase input should be upper-cased)", parsed.Subject.Country, []string{"VN"})
	}
}

func TestRunGenerateHelpFlag(t *testing.T) {
	chdirTemp(t)

	err := runGenerate([]string{"--help"}, strings.NewReader(""), &strings.Builder{})
	if err != nil {
		t.Errorf("runGenerate([--help]) = %v, want nil", err)
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

func TestRunGenerateInteractiveWithForce(t *testing.T) {
	chdirTemp(t)

	if err := runGenerate([]string{"--cn", "example.com"}, strings.NewReader(""), &strings.Builder{}); err != nil {
		t.Fatalf("first runGenerate: %v", err)
	}

	input := strings.Join([]string{
		"example.com", "", "", "", "", "", "", "", "",
	}, "\n") + "\n"

	// "--force" alone must not fall into the flag path (which would fail on
	// a missing --cn); it should still prompt interactively, and the prompt
	// path should be allowed to overwrite the existing output.
	if err := runGenerate([]string{"--force"}, strings.NewReader(input), &strings.Builder{}); err != nil {
		t.Fatalf("runGenerate with --force (interactive): %v", err)
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
