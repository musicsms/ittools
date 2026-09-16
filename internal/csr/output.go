package csr

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// CheckOverwrite reports whether writing dir/name.key or dir/name.csr would
// silently clobber existing files. It returns nil if force is true or if
// neither file exists; otherwise it returns the same "already exists" error
// WriteOutput would return. Callers can use this to fail fast (e.g. before
// generating an RSA key) without duplicating the stat logic.
func CheckOverwrite(dir, name string, force bool) error {
	if force {
		return nil
	}
	keyPath := filepath.Join(dir, name+".key")
	csrPath := filepath.Join(dir, name+".csr")
	if _, err := os.Stat(keyPath); err == nil {
		return fmt.Errorf("%s already exists (use --force to overwrite)", keyPath)
	}
	if _, err := os.Stat(csrPath); err == nil {
		return fmt.Errorf("%s already exists (use --force to overwrite)", csrPath)
	}
	return nil
}

// WriteOutput writes keyPEM and csrPEM to dir/name.key and dir/name.csr,
// creating dir if needed. If either target file already exists and force is
// false, it returns an error without writing anything (see CheckOverwrite).
//
// As defense in depth against a crafted name that escapes dir (e.g. one
// containing "../", in case a caller bypasses SanitizeName), the resolved
// paths are also verified to stay within dir before anything is written.
func WriteOutput(dir, name string, keyPEM, csrPEM []byte, force bool) (keyPath, csrPath string, err error) {
	keyPath = filepath.Join(dir, name+".key")
	csrPath = filepath.Join(dir, name+".csr")

	if err := checkWithinDir(dir, keyPath); err != nil {
		return "", "", err
	}
	if err := checkWithinDir(dir, csrPath); err != nil {
		return "", "", err
	}

	if err := CheckOverwrite(dir, name, force); err != nil {
		return "", "", err
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

// checkWithinDir returns an error if path, once cleaned, does not resolve to
// a location inside dir.
func checkWithinDir(dir, path string) error {
	cleanDir := filepath.Clean(dir)
	cleanPath := filepath.Clean(path)
	if cleanPath != cleanDir && !strings.HasPrefix(cleanPath, cleanDir+string(filepath.Separator)) {
		return fmt.Errorf("resolved path escapes output directory: %s", path)
	}
	return nil
}
