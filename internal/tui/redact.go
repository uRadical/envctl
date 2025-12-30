package tui

import (
	"fmt"
	"os"
	"strings"

	"golang.org/x/term"
	"uradical.io/go/envctl/internal/env"
)

// RedactResult contains the result of the redaction screen
type RedactResult struct {
	Selected  []string // Names of selected variables
	Cancelled bool
}

// ANSI escape codes
const (
	clearScreen = "\033[2J"
	moveCursor  = "\033[%d;%dH"
	hideCursor  = "\033[?25l"
	showCursor  = "\033[?25h"
	bold        = "\033[1m"
	dim         = "\033[2m"
	reset       = "\033[0m"
	yellow      = "\033[33m"
	green       = "\033[32m"
	red         = "\033[31m"
	cyan        = "\033[36m"
)

// RedactScreen displays the variable selection TUI
func RedactScreen(title string, analysis *env.AnalysisResult) (*RedactResult, error) {
	// Check if we're in a terminal
	fd := int(os.Stdin.Fd())
	if !term.IsTerminal(fd) {
		// Non-interactive mode - select all recommended
		result := &RedactResult{
			Selected: make([]string, 0),
		}
		for _, v := range analysis.FilterRecommended() {
			result.Selected = append(result.Selected, v.Name)
		}
		return result, nil
	}

	// Enter raw mode
	oldState, err := term.MakeRaw(fd)
	if err != nil {
		return nil, fmt.Errorf("enter raw mode: %w", err)
	}
	defer term.Restore(fd, oldState)

	// Hide cursor
	fmt.Print(hideCursor)
	defer fmt.Print(showCursor)

	// Initialize selection state
	selected := make(map[string]bool)
	for _, v := range analysis.Variables {
		selected[v.Name] = v.Recommended
	}

	cursor := 0
	maxVisible := 15
	offset := 0

	// Input buffer
	buf := make([]byte, 3)

	for {
		// Clear and draw
		fmt.Print(clearScreen)
		fmt.Printf(moveCursor, 1, 1)

		// Title
		fmt.Printf("%s%s%s\n\n", bold, title, reset)

		// Instructions
		fmt.Printf("%s[Space] toggle  [a] all  [n] none  [s] safe only%s\n", dim, reset)
		fmt.Printf("%s[Enter] confirm  [q] cancel%s\n\n", dim, reset)

		// Variables list
		visible := analysis.Variables
		if len(visible) > maxVisible {
			if cursor < offset {
				offset = cursor
			} else if cursor >= offset+maxVisible {
				offset = cursor - maxVisible + 1
			}
			visible = analysis.Variables[offset : offset+maxVisible]
			if offset > 0 {
				fmt.Printf("%s↑ more above%s\n", dim, reset)
			}
		}

		for i, v := range visible {
			idx := i + offset
			prefix := "  "
			if idx == cursor {
				prefix = "> "
			}

			checkbox := "[ ]"
			if selected[v.Name] {
				checkbox = "[x]"
			}

			// Format value (truncate and mask if needed)
			value := v.Value
			if len(value) > 40 {
				value = value[:37] + "..."
			}

			// Sensitivity indicator
			sensitiveMarker := ""
			if v.Sensitive {
				sensitiveMarker = fmt.Sprintf(" %s⚠ %s%s", yellow, v.Level.String(), reset)
				value = env.MaskValue(v.Value)
			}

			line := fmt.Sprintf("%s%s %s=%s%s", prefix, checkbox, v.Name, value, sensitiveMarker)

			// Highlight current line
			if idx == cursor {
				fmt.Printf("%s%s%s\n", cyan, line, reset)
			} else if v.Sensitive {
				fmt.Printf("%s%s%s\n", dim, line, reset)
			} else {
				fmt.Println(line)
			}
		}

		if len(analysis.Variables) > maxVisible && offset+maxVisible < len(analysis.Variables) {
			fmt.Printf("%s↓ more below%s\n", dim, reset)
		}

		// Status line
		fmt.Println()
		selectedCount := countSelected(selected)
		fmt.Printf("Selected: %d / %d\n", selectedCount, len(analysis.Variables))

		// Read input
		n, err := os.Stdin.Read(buf)
		if err != nil {
			return nil, fmt.Errorf("read input: %w", err)
		}

		input := buf[:n]

		// Handle input
		switch {
		case input[0] == 'q', input[0] == 3: // q or Ctrl+C
			return &RedactResult{Cancelled: true}, nil

		case input[0] == 13: // Enter
			result := &RedactResult{
				Selected: make([]string, 0),
			}
			for name, sel := range selected {
				if sel {
					result.Selected = append(result.Selected, name)
				}
			}
			return result, nil

		case input[0] == ' ': // Space - toggle
			name := analysis.Variables[cursor].Name
			selected[name] = !selected[name]

		case input[0] == 'a': // Select all
			for _, v := range analysis.Variables {
				selected[v.Name] = true
			}

		case input[0] == 'n': // Select none
			for _, v := range analysis.Variables {
				selected[v.Name] = false
			}

		case input[0] == 's': // Select safe only
			for _, v := range analysis.Variables {
				selected[v.Name] = !v.Sensitive
			}

		case len(input) == 3 && input[0] == 27 && input[1] == 91: // Arrow keys
			switch input[2] {
			case 65: // Up
				if cursor > 0 {
					cursor--
				}
			case 66: // Down
				if cursor < len(analysis.Variables)-1 {
					cursor++
				}
			}

		case input[0] == 'j': // Vim down
			if cursor < len(analysis.Variables)-1 {
				cursor++
			}

		case input[0] == 'k': // Vim up
			if cursor > 0 {
				cursor--
			}
		}
	}
}

func countSelected(selected map[string]bool) int {
	count := 0
	for _, sel := range selected {
		if sel {
			count++
		}
	}
	return count
}

// SimpleRedactScreen is a non-interactive fallback
func SimpleRedactScreen(analysis *env.AnalysisResult) (*RedactResult, error) {
	fmt.Println("Variables to share:")
	fmt.Println()

	for _, v := range analysis.Variables {
		marker := "[x]"
		if v.Sensitive {
			marker = "[ ]"
			fmt.Printf("%s %s=%s (sensitive: %s)\n", marker, v.Name, env.MaskValue(v.Value), v.Level)
		} else {
			fmt.Printf("%s %s=%s\n", marker, v.Name, truncate(v.Value, 40))
		}
	}

	fmt.Println()
	fmt.Print("Share non-sensitive variables? [Y/n] ")

	confirmed, err := Confirm("", true)
	if err != nil || !confirmed {
		return &RedactResult{Cancelled: true}, nil
	}

	result := &RedactResult{
		Selected: make([]string, 0),
	}
	for _, v := range analysis.FilterRecommended() {
		result.Selected = append(result.Selected, v.Name)
	}

	return result, nil
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}

// PromptSelect allows selecting from a list of options
func PromptSelect(title string, options []string) (int, error) {
	fmt.Println(title)
	for i, opt := range options {
		fmt.Printf("  %d. %s\n", i+1, opt)
	}

	fmt.Print("Select [1]: ")

	line, err := ReadLine("")
	if err != nil {
		return 0, err
	}

	if line == "" {
		return 0, nil
	}

	var idx int
	_, err = fmt.Sscanf(line, "%d", &idx)
	if err != nil || idx < 1 || idx > len(options) {
		return 0, nil
	}

	return idx - 1, nil
}

// Box draws a box around text
func Box(title, content string) string {
	lines := strings.Split(content, "\n")
	maxWidth := len(title)
	for _, line := range lines {
		if len(line) > maxWidth {
			maxWidth = len(line)
		}
	}

	width := maxWidth + 4
	var sb strings.Builder

	// Top border
	sb.WriteString("┌─ ")
	sb.WriteString(title)
	sb.WriteString(" ")
	sb.WriteString(strings.Repeat("─", width-len(title)-4))
	sb.WriteString("┐\n")

	// Content
	for _, line := range lines {
		sb.WriteString("│ ")
		sb.WriteString(line)
		sb.WriteString(strings.Repeat(" ", width-len(line)-2))
		sb.WriteString("│\n")
	}

	// Bottom border
	sb.WriteString("└")
	sb.WriteString(strings.Repeat("─", width))
	sb.WriteString("┘\n")

	return sb.String()
}
