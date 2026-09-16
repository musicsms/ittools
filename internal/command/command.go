// Package command defines the interface every ittools subcommand implements.
package command

// Command is a subcommand of the ittools binary. Name is the word that
// selects it on the command line (e.g. "csr"); Run receives the remaining
// arguments after that word.
type Command interface {
	Name() string
	Run(args []string) error
}
