package csr

import (
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"ittools/internal/command"
)

// Tool implements command.Command for the "csr" subcommand group.
type Tool struct{}

// New returns the csr Command, registered in main.go under the name "csr".
func New() command.Command { return Tool{} }

// Name returns "csr".
func (Tool) Name() string { return "csr" }

// Run dispatches to the "generate" verb; any other or missing verb is an
// error.
func (Tool) Run(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: ittools csr generate [flags]")
	}
	switch args[0] {
	case "generate":
		return runGenerate(args[1:], os.Stdin, os.Stdout)
	default:
		return fmt.Errorf("unknown csr subcommand %q (expected: generate)", args[0])
	}
}

// runGenerate implements "csr generate": it parses flags (or, if none are
// given, prompts interactively on stdin/stdout), validates the subject,
// generates a key and CSR, writes them under output/<name>/, and also
// prints both PEM blocks to stdout.
func runGenerate(args []string, stdin io.Reader, stdout io.Writer) error {
	fs := flag.NewFlagSet("csr generate", flag.ContinueOnError)
	cn := fs.String("cn", "", "Common Name")
	org := fs.String("org", "", "Organization")
	ou := fs.String("ou", "", "Organizational Unit")
	city := fs.String("city", "", "City/Locality")
	state := fs.String("state", "", "State/Province")
	country := fs.String("country", "", "Country (2-letter code)")
	email := fs.String("email", "", "Email address")
	san := fs.String("san", "", "Comma-separated Subject Alternative Names")
	keySize := fs.Int("key-size", 2048, "RSA key size (2048, 3072, 4096)")
	force := fs.Bool("force", false, "Overwrite existing output files")

	if err := fs.Parse(args); err != nil {
		return err
	}

	var subject Subject
	var sans []string
	var bits int

	if len(args) == 0 {
		var err error
		subject, sans, bits, err = PromptSubject(stdin, stdout)
		if err != nil {
			return fmt.Errorf("read input: %w", err)
		}
	} else {
		subject = Subject{
			CommonName:         *cn,
			Organization:       *org,
			OrganizationalUnit: *ou,
			City:               *city,
			State:              *state,
			Country:            *country,
			Email:              *email,
		}
		sans = SplitSANs(*san)
		bits = *keySize

		if err := ValidateCommonName(subject.CommonName); err != nil {
			return err
		}
		if err := ValidateCountry(subject.Country); err != nil {
			return err
		}
		if err := ValidateKeySize(bits); err != nil {
			return err
		}
	}

	key, err := GenerateKey(bits)
	if err != nil {
		return err
	}

	der, err := BuildCSR(key, subject, sans)
	if err != nil {
		return err
	}

	keyPEM := EncodeKeyPEM(key)
	csrPEM := EncodeCSRPEM(der)

	name := SanitizeName(subject.CommonName)
	dir := filepath.Join("output", name)

	keyPath, csrPath, err := WriteOutput(dir, name, keyPEM, csrPEM, *force)
	if err != nil {
		return err
	}

	if _, err := stdout.Write(keyPEM); err != nil {
		return err
	}
	if _, err := stdout.Write(csrPEM); err != nil {
		return err
	}
	fmt.Fprintf(stdout, "Saved private key to %s\n", keyPath)
	fmt.Fprintf(stdout, "Saved CSR to %s\n", csrPath)

	return nil
}
