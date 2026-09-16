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
