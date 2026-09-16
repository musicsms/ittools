package csr

import (
	"reflect"
	"strings"
	"testing"
)

func TestPromptSubjectHappyPath(t *testing.T) {
	input := strings.Join([]string{
		"example.com",       // Common Name
		"Acme Inc",          // Organization
		"IT",                // Organizational Unit
		"Hanoi",             // City
		"Hanoi",             // State
		"VN",                // Country
		"admin@example.com", // Email
		"a.com, b.com",      // SANs
		"3072",              // Key size
	}, "\n") + "\n"

	r := strings.NewReader(input)
	var w strings.Builder

	subject, sans, keySize, err := PromptSubject(r, &w)
	if err != nil {
		t.Fatalf("PromptSubject: %v", err)
	}

	want := Subject{
		CommonName:         "example.com",
		Organization:       "Acme Inc",
		OrganizationalUnit: "IT",
		City:               "Hanoi",
		State:              "Hanoi",
		Country:            "VN",
		Email:              "admin@example.com",
	}
	if subject != want {
		t.Errorf("subject = %+v, want %+v", subject, want)
	}
	if !reflect.DeepEqual(sans, []string{"a.com", "b.com"}) {
		t.Errorf("sans = %v, want %v", sans, []string{"a.com", "b.com"})
	}
	if keySize != 3072 {
		t.Errorf("keySize = %d, want 3072", keySize)
	}
}

func TestPromptSubjectDefaultsKeySize(t *testing.T) {
	input := strings.Join([]string{
		"example.com", "", "", "", "", "", "", "", "",
	}, "\n") + "\n"

	subject, _, keySize, err := PromptSubject(strings.NewReader(input), &strings.Builder{})
	if err != nil {
		t.Fatalf("PromptSubject: %v", err)
	}
	if subject.CommonName != "example.com" {
		t.Errorf("CommonName = %q, want %q", subject.CommonName, "example.com")
	}
	if keySize != 2048 {
		t.Errorf("keySize = %d, want default 2048", keySize)
	}
}

func TestPromptSubjectReprompsOnEmptyCommonName(t *testing.T) {
	input := "\nexample.com\n\n\n\n\n\n\n\n\n"

	subject, _, _, err := PromptSubject(strings.NewReader(input), &strings.Builder{})
	if err != nil {
		t.Fatalf("PromptSubject: %v", err)
	}
	if subject.CommonName != "example.com" {
		t.Errorf("CommonName = %q, want %q (should reprompt past blank line)", subject.CommonName, "example.com")
	}
}
