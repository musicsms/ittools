package csr

import (
	"bufio"
	"fmt"
	"io"
	"strconv"
	"strings"
)

// PromptSubject interactively asks for each CSR field on r, writing prompts
// to w. It re-prompts on invalid Common Name, Country, or key size answers.
func PromptSubject(r io.Reader, w io.Writer) (Subject, []string, int, error) {
	scanner := bufio.NewScanner(r)

	ask := func(label string) (string, error) {
		fmt.Fprintf(w, "%s: ", label)
		if !scanner.Scan() {
			if err := scanner.Err(); err != nil {
				return "", err
			}
			return "", io.EOF
		}
		return strings.TrimSpace(scanner.Text()), nil
	}

	var subject Subject

	for {
		cn, err := ask("Common Name")
		if err != nil {
			return Subject{}, nil, 0, err
		}
		if err := ValidateCommonName(cn); err != nil {
			fmt.Fprintln(w, err)
			continue
		}
		subject.CommonName = cn
		break
	}

	var err error
	if subject.Organization, err = ask("Organization"); err != nil {
		return Subject{}, nil, 0, err
	}
	if subject.OrganizationalUnit, err = ask("Organizational Unit"); err != nil {
		return Subject{}, nil, 0, err
	}
	if subject.City, err = ask("City"); err != nil {
		return Subject{}, nil, 0, err
	}
	if subject.State, err = ask("State"); err != nil {
		return Subject{}, nil, 0, err
	}

	for {
		country, err := ask("Country (2-letter code)")
		if err != nil {
			return Subject{}, nil, 0, err
		}
		if err := ValidateCountry(country); err != nil {
			fmt.Fprintln(w, err)
			continue
		}
		subject.Country = country
		break
	}

	if subject.Email, err = ask("Email"); err != nil {
		return Subject{}, nil, 0, err
	}

	sanRaw, err := ask("Subject Alternative Names (comma-separated, optional)")
	if err != nil {
		return Subject{}, nil, 0, err
	}
	sans := SplitSANs(sanRaw)

	var keySize int
	for {
		ksRaw, err := ask("Key size (2048, 3072, 4096) [2048]")
		if err != nil {
			return Subject{}, nil, 0, err
		}
		if ksRaw == "" {
			keySize = 2048
			break
		}
		n, convErr := strconv.Atoi(ksRaw)
		if convErr != nil {
			fmt.Fprintln(w, "key size must be a number")
			continue
		}
		if err := ValidateKeySize(n); err != nil {
			fmt.Fprintln(w, err)
			continue
		}
		keySize = n
		break
	}

	return subject, sans, keySize, nil
}
