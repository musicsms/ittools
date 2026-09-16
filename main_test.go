package main

import (
	"strings"
	"testing"
)

func TestRunUnknownCommand(t *testing.T) {
	var stderr strings.Builder
	code := run([]string{"ittools", "bogus"}, &stderr)
	if code != 1 {
		t.Errorf("exit code = %d, want 1", code)
	}
	if !strings.Contains(stderr.String(), "unknown command") {
		t.Errorf("stderr = %q, want it to mention unknown command", stderr.String())
	}
}

func TestRunNoArgsPrintsUsage(t *testing.T) {
	var stderr strings.Builder
	code := run([]string{"ittools"}, &stderr)
	if code != 1 {
		t.Errorf("exit code = %d, want 1", code)
	}
	if !strings.Contains(stderr.String(), "usage") {
		t.Errorf("stderr = %q, want it to contain usage", stderr.String())
	}
}

func TestRunKnownCommandPropagatesError(t *testing.T) {
	var stderr strings.Builder
	code := run([]string{"ittools", "csr", "bogus-verb"}, &stderr)
	if code != 1 {
		t.Errorf("exit code = %d, want 1", code)
	}
	if !strings.Contains(stderr.String(), "unknown csr subcommand") {
		t.Errorf("stderr = %q, want it to mention the unknown csr subcommand", stderr.String())
	}
}
