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
