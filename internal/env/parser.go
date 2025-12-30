package env

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strings"
)

// Variable represents a single environment variable
type Variable struct {
	Name      string `json:"name"`
	Value     string `json:"value"`
	Line      int    `json:"line"`
	Comment   string `json:"comment,omitempty"`
	Exported  bool   `json:"exported"`
}

// EnvFile represents a parsed .env file
type EnvFile struct {
	Path      string      `json:"path"`
	Variables []*Variable `json:"variables"`
}

// Parser errors
var (
	ErrEmptyFile       = errors.New("empty file")
	ErrInvalidLine     = errors.New("invalid line format")
	ErrUnterminatedQuote = errors.New("unterminated quote")
)

// Parse parses an .env file and returns its variables
func Parse(path string) (*EnvFile, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open file: %w", err)
	}
	defer f.Close()

	envFile := &EnvFile{
		Path:      path,
		Variables: make([]*Variable, 0),
	}

	scanner := bufio.NewScanner(f)
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		line := scanner.Text()

		// Parse the line
		v, err := parseLine(line, lineNum)
		if err != nil {
			return nil, fmt.Errorf("line %d: %w", lineNum, err)
		}

		if v != nil {
			envFile.Variables = append(envFile.Variables, v)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read file: %w", err)
	}

	return envFile, nil
}

// ParseString parses env content from a string
func ParseString(content string) (*EnvFile, error) {
	envFile := &EnvFile{
		Variables: make([]*Variable, 0),
	}

	lines := strings.Split(content, "\n")
	for lineNum, line := range lines {
		v, err := parseLine(line, lineNum+1)
		if err != nil {
			return nil, fmt.Errorf("line %d: %w", lineNum+1, err)
		}

		if v != nil {
			envFile.Variables = append(envFile.Variables, v)
		}
	}

	return envFile, nil
}

// parseLine parses a single line of an env file
func parseLine(line string, lineNum int) (*Variable, error) {
	// Trim whitespace
	line = strings.TrimSpace(line)

	// Skip empty lines
	if line == "" {
		return nil, nil
	}

	// Skip comments
	if strings.HasPrefix(line, "#") {
		return nil, nil
	}

	// Handle export prefix
	exported := false
	if strings.HasPrefix(line, "export ") {
		exported = true
		line = strings.TrimPrefix(line, "export ")
		line = strings.TrimSpace(line)
	}

	// Find the equals sign
	idx := strings.Index(line, "=")
	if idx == -1 {
		return nil, fmt.Errorf("%w: no '=' found", ErrInvalidLine)
	}

	name := strings.TrimSpace(line[:idx])
	valueStr := line[idx+1:]

	// Validate name
	if !isValidVarName(name) {
		return nil, fmt.Errorf("%w: invalid variable name '%s'", ErrInvalidLine, name)
	}

	// Parse value (handle quotes)
	value, err := parseValue(valueStr)
	if err != nil {
		return nil, err
	}

	return &Variable{
		Name:     name,
		Value:    value,
		Line:     lineNum,
		Exported: exported,
	}, nil
}

// parseValue parses the value part of a line
func parseValue(s string) (string, error) {
	s = strings.TrimSpace(s)

	if len(s) == 0 {
		return "", nil
	}

	// Check for quoted values
	if s[0] == '"' || s[0] == '\'' {
		quote := s[0]
		// Find matching end quote
		end := -1
		for i := 1; i < len(s); i++ {
			if s[i] == byte(quote) && (i == 1 || s[i-1] != '\\') {
				end = i
				break
			}
		}

		if end == -1 {
			return "", ErrUnterminatedQuote
		}

		value := s[1:end]

		// Handle escape sequences in double quotes
		if quote == '"' {
			value = strings.ReplaceAll(value, "\\n", "\n")
			value = strings.ReplaceAll(value, "\\t", "\t")
			value = strings.ReplaceAll(value, "\\\"", "\"")
			value = strings.ReplaceAll(value, "\\\\", "\\")
		}

		return value, nil
	}

	// Unquoted value - take until comment or end of line
	// Remove inline comments
	if idx := strings.Index(s, " #"); idx != -1 {
		s = s[:idx]
	}

	return strings.TrimSpace(s), nil
}

// isValidVarName checks if a name is a valid environment variable name
func isValidVarName(name string) bool {
	if len(name) == 0 {
		return false
	}

	// Must start with letter or underscore
	if !((name[0] >= 'A' && name[0] <= 'Z') ||
		(name[0] >= 'a' && name[0] <= 'z') ||
		name[0] == '_') {
		return false
	}

	// Rest must be alphanumeric or underscore
	for i := 1; i < len(name); i++ {
		c := name[i]
		if !((c >= 'A' && c <= 'Z') ||
			(c >= 'a' && c <= 'z') ||
			(c >= '0' && c <= '9') ||
			c == '_') {
			return false
		}
	}

	return true
}

// Serialize serializes the env file back to string format
func (e *EnvFile) Serialize() string {
	var sb strings.Builder

	for _, v := range e.Variables {
		if v.Exported {
			sb.WriteString("export ")
		}

		sb.WriteString(v.Name)
		sb.WriteString("=")

		// Quote value if needed
		if needsQuoting(v.Value) {
			sb.WriteString("\"")
			sb.WriteString(escapeValue(v.Value))
			sb.WriteString("\"")
		} else {
			sb.WriteString(v.Value)
		}

		sb.WriteString("\n")
	}

	return sb.String()
}

// needsQuoting checks if a value needs to be quoted
func needsQuoting(s string) bool {
	if s == "" {
		return true
	}

	// Needs quoting if contains special characters
	for _, c := range s {
		if c == ' ' || c == '"' || c == '\'' || c == '\\' ||
			c == '\n' || c == '\t' || c == '#' || c == '$' {
			return true
		}
	}

	return false
}

// escapeValue escapes special characters in a value
func escapeValue(s string) string {
	s = strings.ReplaceAll(s, "\\", "\\\\")
	s = strings.ReplaceAll(s, "\"", "\\\"")
	s = strings.ReplaceAll(s, "\n", "\\n")
	s = strings.ReplaceAll(s, "\t", "\\t")
	return s
}

// Get returns a variable by name
func (e *EnvFile) Get(name string) *Variable {
	for _, v := range e.Variables {
		if v.Name == name {
			return v
		}
	}
	return nil
}

// Names returns all variable names
func (e *EnvFile) Names() []string {
	names := make([]string, len(e.Variables))
	for i, v := range e.Variables {
		names[i] = v.Name
	}
	return names
}

// Filter returns variables matching a filter function
func (e *EnvFile) Filter(fn func(*Variable) bool) []*Variable {
	result := make([]*Variable, 0)
	for _, v := range e.Variables {
		if fn(v) {
			result = append(result, v)
		}
	}
	return result
}

// Select returns only the specified variables
func (e *EnvFile) Select(names []string) *EnvFile {
	nameSet := make(map[string]bool)
	for _, n := range names {
		nameSet[n] = true
	}

	result := &EnvFile{
		Path:      e.Path,
		Variables: make([]*Variable, 0),
	}

	for _, v := range e.Variables {
		if nameSet[v.Name] {
			result.Variables = append(result.Variables, v)
		}
	}

	return result
}

// Exclude returns variables excluding the specified names
func (e *EnvFile) Exclude(names []string) *EnvFile {
	nameSet := make(map[string]bool)
	for _, n := range names {
		nameSet[n] = true
	}

	result := &EnvFile{
		Path:      e.Path,
		Variables: make([]*Variable, 0),
	}

	for _, v := range e.Variables {
		if !nameSet[v.Name] {
			result.Variables = append(result.Variables, v)
		}
	}

	return result
}

// Merge merges another env file into this one
// Variables from other override existing ones
func (e *EnvFile) Merge(other *EnvFile) {
	for _, v := range other.Variables {
		existing := e.Get(v.Name)
		if existing != nil {
			existing.Value = v.Value
		} else {
			e.Variables = append(e.Variables, v)
		}
	}
}

// ToMap converts variables to a map
func (e *EnvFile) ToMap() map[string]string {
	m := make(map[string]string)
	for _, v := range e.Variables {
		m[v.Name] = v.Value
	}
	return m
}

// sensitivePattern matches variable names that typically contain secrets
var sensitivePattern = regexp.MustCompile(`(?i)(secret|token|password|passwd|pwd|credential|private|api_key|apikey|auth)`)

// publicPattern matches variable names that are typically public despite matching sensitive pattern
var publicPattern = regexp.MustCompile(`(?i)(public|pubkey)`)

// IsSensitiveName checks if a variable name suggests sensitive content
func IsSensitiveName(name string) bool {
	if publicPattern.MatchString(name) {
		return false
	}
	return sensitivePattern.MatchString(name)
}
