// Package csr generates RSA private keys and PKCS#10 certificate signing
// requests, with the subject fields and output layout of ittools' "csr
// generate" command.
package csr

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
