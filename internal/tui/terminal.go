package tui

import (
	"os"

	"golang.org/x/term"
)

// IsStdoutTerminal returns true if stdout is a terminal (not piped)
func IsStdoutTerminal() bool {
	return term.IsTerminal(int(os.Stdout.Fd()))
}
