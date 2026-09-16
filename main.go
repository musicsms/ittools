// Command ittools is a toolkit of small IT utilities, organized as
// subcommands (e.g. "ittools csr generate").
package main

import (
	"fmt"
	"io"
	"os"

	"ittools/internal/command"
	"ittools/internal/csr"
)

func main() {
	os.Exit(run(os.Args, os.Stderr))
}

// run dispatches args[1] to a registered command, returning the process
// exit code. It writes errors and usage text to stderr.
func run(args []string, stderr io.Writer) int {
	commands := map[string]command.Command{
		"csr": csr.New(),
	}

	if len(args) < 2 {
		fmt.Fprintln(stderr, usage(commands))
		return 1
	}

	cmd, ok := commands[args[1]]
	if !ok {
		fmt.Fprintf(stderr, "unknown command %q\n%s\n", args[1], usage(commands))
		return 1
	}

	if err := cmd.Run(args[2:]); err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return 1
	}
	return 0
}

func usage(commands map[string]command.Command) string {
	s := "usage: ittools <command> [args]\n\navailable commands:"
	for name := range commands {
		s += "\n  " + name
	}
	return s
}
