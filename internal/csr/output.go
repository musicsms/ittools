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
