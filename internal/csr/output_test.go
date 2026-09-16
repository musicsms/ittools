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
