package tui

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"strings"

	"golang.org/x/term"
)

// stdinReader is a shared reader for non-terminal stdin to avoid buffering issues
var stdinReader *bufio.Reader

// ReadPassword reads a password from the terminal without echoing
func ReadPassword(prompt string) ([]byte, error) {
	fmt.Fprint(os.Stderr, prompt)

	fd := int(os.Stdin.Fd())
	if !term.IsTerminal(fd) {
		// Not a terminal, read from stdin directly
		// Use shared reader to avoid buffering issues with multiple reads
		if stdinReader == nil {
			stdinReader = bufio.NewReader(os.Stdin)
		}
		line, err := stdinReader.ReadString('\n')
		if err != nil {
			return nil, err
		}
		// Handle both \n and \r\n line endings
		line = strings.TrimSuffix(line, "\n")
		line = strings.TrimSuffix(line, "\r")
		return []byte(line), nil
	}

	password, err := term.ReadPassword(fd)
	fmt.Fprintln(os.Stderr) // New line after password input

	if err != nil {
		return nil, fmt.Errorf("read password: %w", err)
	}

	return password, nil
}

// ReadPasswordConfirm reads a password with confirmation
func ReadPasswordConfirm(prompt, confirmPrompt string) ([]byte, error) {
	password, err := ReadPassword(prompt)
	if err != nil {
		return nil, err
	}

	confirm, err := ReadPassword(confirmPrompt)
	if err != nil {
		return nil, err
	}

	if string(password) != string(confirm) {
		return nil, errors.New("passwords do not match")
	}

	return password, nil
}

// Confirm prompts for a yes/no confirmation
func Confirm(prompt string, defaultYes bool) (bool, error) {
	hint := "[y/N]"
	if defaultYes {
		hint = "[Y/n]"
	}

	fmt.Fprintf(os.Stderr, "%s %s ", prompt, hint)

	reader := bufio.NewReader(os.Stdin)
	response, err := reader.ReadString('\n')
	if err != nil {
		return false, err
	}

	response = strings.TrimSpace(strings.ToLower(response))

	if response == "" {
		return defaultYes, nil
	}

	switch response {
	case "y", "yes":
		return true, nil
	case "n", "no":
		return false, nil
	default:
		return defaultYes, nil
	}
}

// ReadLine reads a line of input
func ReadLine(prompt string) (string, error) {
	fmt.Fprint(os.Stderr, prompt)

	reader := bufio.NewReader(os.Stdin)
	line, err := reader.ReadString('\n')
	if err != nil {
		return "", err
	}

	return strings.TrimSpace(line), nil
}

// ReadLineDefault reads a line with a default value
func ReadLineDefault(prompt, defaultValue string) (string, error) {
	if defaultValue != "" {
		prompt = fmt.Sprintf("%s [%s]: ", strings.TrimSuffix(prompt, ": "), defaultValue)
	}

	line, err := ReadLine(prompt)
	if err != nil {
		return "", err
	}

	if line == "" {
		return defaultValue, nil
	}

	return line, nil
}
