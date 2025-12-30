package tui

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"

	"golang.org/x/term"
)

// Select presents options to the user and returns the selected index
func Select(prompt string, options []string) (int, error) {
	if len(options) == 0 {
		return -1, fmt.Errorf("no options provided")
	}

	fmt.Fprintln(os.Stderr, prompt)
	for i, opt := range options {
		fmt.Fprintf(os.Stderr, "  %d) %s\n", i+1, opt)
	}
	fmt.Fprint(os.Stderr, "Choice [1]: ")

	reader := bufio.NewReader(os.Stdin)
	input, err := reader.ReadString('\n')
	if err != nil {
		return -1, fmt.Errorf("read input: %w", err)
	}

	input = strings.TrimSpace(input)

	// Default to first option
	if input == "" {
		return 0, nil
	}

	// Parse selection
	choice, err := strconv.Atoi(input)
	if err != nil {
		return -1, fmt.Errorf("invalid selection: %s", input)
	}

	if choice < 1 || choice > len(options) {
		return -1, fmt.Errorf("selection out of range: %d", choice)
	}

	return choice - 1, nil
}

// SelectMulti presents options and allows multiple selections
func SelectMulti(prompt string, options []string, defaults []bool) ([]int, error) {
	if len(options) == 0 {
		return nil, fmt.Errorf("no options provided")
	}

	// Initialize defaults
	selected := make([]bool, len(options))
	if len(defaults) == len(options) {
		copy(selected, defaults)
	}

	fmt.Fprintln(os.Stderr, prompt)
	fmt.Fprintln(os.Stderr, "(Enter numbers separated by commas, or 'a' for all, 'n' for none)")
	fmt.Fprintln(os.Stderr)

	for i, opt := range options {
		marker := "[ ]"
		if selected[i] {
			marker = "[x]"
		}
		fmt.Fprintf(os.Stderr, "  %d) %s %s\n", i+1, marker, opt)
	}

	fmt.Fprint(os.Stderr, "Selection: ")

	reader := bufio.NewReader(os.Stdin)
	input, err := reader.ReadString('\n')
	if err != nil {
		return nil, fmt.Errorf("read input: %w", err)
	}

	input = strings.TrimSpace(strings.ToLower(input))

	// Handle special cases
	if input == "" {
		// Return current selection
		result := make([]int, 0)
		for i, s := range selected {
			if s {
				result = append(result, i)
			}
		}
		return result, nil
	}

	if input == "a" || input == "all" {
		result := make([]int, len(options))
		for i := range options {
			result[i] = i
		}
		return result, nil
	}

	if input == "n" || input == "none" {
		return []int{}, nil
	}

	// Parse comma-separated list
	parts := strings.Split(input, ",")
	result := make([]int, 0, len(parts))

	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}

		num, err := strconv.Atoi(part)
		if err != nil {
			continue
		}

		if num >= 1 && num <= len(options) {
			result = append(result, num-1)
		}
	}

	return result, nil
}

// PasswordPrompt prompts for a password without echoing
// This is an alias for ReadPassword for compatibility
func PasswordPrompt(prompt string) ([]byte, error) {
	return ReadPassword(prompt)
}

// IsTerminal returns true if stdin is a terminal
func IsTerminal() bool {
	return term.IsTerminal(int(os.Stdin.Fd()))
}

// TerminalWidth returns the terminal width, or 80 if not a terminal
func TerminalWidth() int {
	if !IsTerminal() {
		return 80
	}

	width, _, err := term.GetSize(int(os.Stdout.Fd()))
	if err != nil {
		return 80
	}
	return width
}

// ClearLine clears the current line in the terminal
func ClearLine() {
	if IsTerminal() {
		fmt.Fprint(os.Stderr, "\r\033[K")
	}
}

// Spinner shows a simple text spinner
type Spinner struct {
	message string
	done    chan struct{}
}

// NewSpinner creates a new spinner with a message
func NewSpinner(message string) *Spinner {
	return &Spinner{
		message: message,
		done:    make(chan struct{}),
	}
}

// Start starts the spinner animation
func (s *Spinner) Start() {
	if !IsTerminal() {
		fmt.Fprintf(os.Stderr, "%s...\n", s.message)
		return
	}

	frames := []string{"|", "/", "-", "\\"}
	go func() {
		i := 0
		for {
			select {
			case <-s.done:
				return
			default:
				fmt.Fprintf(os.Stderr, "\r%s %s", s.message, frames[i%len(frames)])
				i++
				// Sleep handled by caller
			}
		}
	}()
}

// Stop stops the spinner
func (s *Spinner) Stop() {
	close(s.done)
	ClearLine()
}

// StopWithMessage stops the spinner and shows a final message
func (s *Spinner) StopWithMessage(message string) {
	close(s.done)
	ClearLine()
	fmt.Fprintf(os.Stderr, "%s\n", message)
}

// ProgressBar shows a simple progress bar
func ProgressBar(current, total int, width int) string {
	if total <= 0 {
		return ""
	}

	percent := float64(current) / float64(total)
	filled := int(percent * float64(width))
	if filled > width {
		filled = width
	}

	bar := strings.Repeat("=", filled)
	if filled < width {
		bar += ">"
		bar += strings.Repeat(" ", width-filled-1)
	}

	return fmt.Sprintf("[%s] %d%%", bar, int(percent*100))
}
