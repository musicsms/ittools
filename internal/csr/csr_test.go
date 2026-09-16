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
