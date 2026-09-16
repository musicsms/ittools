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
