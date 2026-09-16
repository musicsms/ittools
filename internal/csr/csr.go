// Package csr generates RSA private keys and PKCS#10 certificate signing
// requests, with the subject fields and output layout of ittools' "csr
// generate" command.
package csr

import (
	"errors"
	"fmt"
	"strings"
)

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
