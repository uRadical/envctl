// Package secrets handles encrypted environment variable storage
package secrets

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"

	"envctl.dev/go/envctl/internal/crypto"
)

// EncryptedEnv represents the structure of an encrypted environment file
type EncryptedEnv struct {
	Version   int               `json:"version"`
	Variables map[string]string `json:"variables"`
}

// SaveEncrypted encrypts and saves environment variables to a file
// The variables are encrypted to the identity's own public key (self-encryption)
func SaveEncrypted(path string, variables map[string]string, identity *crypto.Identity) error {
	env := EncryptedEnv{
		Version:   1,
		Variables: variables,
	}

	plaintext, err := json.Marshal(env)
	if err != nil {
		return fmt.Errorf("marshaling env: %w", err)
	}

	// Encrypt to self (using own public key)
	ciphertext, err := crypto.EncryptForIdentity(plaintext, identity.Public())
	if err != nil {
		return fmt.Errorf("encrypting: %w", err)
	}

	if err := os.WriteFile(path, ciphertext, 0600); err != nil {
		return fmt.Errorf("writing file: %w", err)
	}

	return nil
}

// LoadEncrypted decrypts and loads environment variables from a file
func LoadEncrypted(path string, identity *crypto.Identity) (map[string]string, error) {
	ciphertext, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading file: %w", err)
	}

	plaintext, err := crypto.DecryptWithIdentity(ciphertext, identity)
	if err != nil {
		return nil, fmt.Errorf("decrypting: %w", err)
	}

	var env EncryptedEnv
	if err := json.Unmarshal(plaintext, &env); err != nil {
		return nil, fmt.Errorf("unmarshaling env: %w", err)
	}

	return env.Variables, nil
}

// WriteDotEnv writes variables to a .env file in standard format
func WriteDotEnv(path string, variables map[string]string) error {
	// Sort keys for consistent output
	keys := make([]string, 0, len(variables))
	for k := range variables {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var lines []string
	for _, k := range keys {
		v := variables[k]
		// Quote values that contain special characters
		if needsQuoting(v) {
			v = fmt.Sprintf("\"%s\"", escapeValue(v))
		}
		lines = append(lines, fmt.Sprintf("%s=%s", k, v))
	}

	content := strings.Join(lines, "\n") + "\n"
	return os.WriteFile(path, []byte(content), 0600)
}

// needsQuoting returns true if a value needs to be quoted in a .env file
func needsQuoting(v string) bool {
	if len(v) == 0 {
		return false
	}
	// Quote if contains spaces, tabs, newlines, quotes, or shell special chars
	return strings.ContainsAny(v, " \t\n\"'$`\\#")
}

// escapeValue escapes special characters for quoted .env values
func escapeValue(v string) string {
	v = strings.ReplaceAll(v, "\\", "\\\\")
	v = strings.ReplaceAll(v, "\"", "\\\"")
	v = strings.ReplaceAll(v, "\n", "\\n")
	v = strings.ReplaceAll(v, "\r", "\\r")
	v = strings.ReplaceAll(v, "\t", "\\t")
	return v
}

// RemoveDotEnv securely removes the .env file
func RemoveDotEnv(path string) error {
	// Check if exists
	info, err := os.Stat(path)
	if os.IsNotExist(err) {
		return nil // Already gone
	}
	if err != nil {
		return err
	}

	// Overwrite with zeros before deleting (basic secure delete)
	if info.Size() > 0 {
		zeros := make([]byte, info.Size())
		if err := os.WriteFile(path, zeros, 0600); err != nil {
			// Continue even if overwrite fails
		}
	}

	return os.Remove(path)
}

// ParseEnvFile parses a .env file into a map of variables
func ParseEnvFile(path string) (map[string]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	return ParseEnvContent(string(data))
}

// ParseEnvContent parses .env file content into a map of variables
func ParseEnvContent(content string) (map[string]string, error) {
	variables := make(map[string]string)

	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)

		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Parse KEY=value
		idx := strings.Index(line, "=")
		if idx == -1 {
			continue
		}

		key := strings.TrimSpace(line[:idx])
		value := strings.TrimSpace(line[idx+1:])

		// Remove surrounding quotes if present
		value = unquoteValue(value)

		variables[key] = value
	}

	return variables, nil
}

// unquoteValue removes surrounding quotes and handles escape sequences
func unquoteValue(v string) string {
	if len(v) < 2 {
		return v
	}

	// Check for double quotes
	if v[0] == '"' && v[len(v)-1] == '"' {
		v = v[1 : len(v)-1]
		// Handle escape sequences
		v = strings.ReplaceAll(v, "\\n", "\n")
		v = strings.ReplaceAll(v, "\\r", "\r")
		v = strings.ReplaceAll(v, "\\t", "\t")
		v = strings.ReplaceAll(v, "\\\"", "\"")
		v = strings.ReplaceAll(v, "\\\\", "\\")
		return v
	}

	// Check for single quotes (no escape processing)
	if v[0] == '\'' && v[len(v)-1] == '\'' {
		return v[1 : len(v)-1]
	}

	return v
}

// CountVariables counts the number of variables in a .env file
func CountVariables(path string) (int, error) {
	vars, err := ParseEnvFile(path)
	if err != nil {
		return 0, err
	}
	return len(vars), nil
}

// ListEncryptedEnvs lists available encrypted environments in a project
func ListEncryptedEnvs(envctlDir string) ([]string, error) {
	entries, err := os.ReadDir(envctlDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}

	var envs []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if strings.HasSuffix(name, ".enc") {
			envs = append(envs, strings.TrimSuffix(name, ".enc"))
		}
	}

	sort.Strings(envs)
	return envs, nil
}
