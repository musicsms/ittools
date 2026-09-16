package csr

import (
	"crypto/x509"
	"reflect"
	"strings"
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
