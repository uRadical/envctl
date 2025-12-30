package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// ProjectConfig represents the project configuration stored in .envctl/config
type ProjectConfig struct {
	Project         string    // project name
	Env             string    // environment name (dev, stage, prod)
	Locked          bool      // whether .env is currently locked (removed)
	LastUnlocked    time.Time // when .env was last written
	AutoLockMinutes int       // auto-lock timeout (0 = disabled)
}

// LoadProjectConfig loads the project config from a directory
func LoadProjectConfig(dir string) (*ProjectConfig, error) {
	configPath := EnvctlConfigPath(dir)
	data, err := os.ReadFile(configPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("not an envctl project (no .envctl/config)")
		}
		return nil, err
	}

	config := &ProjectConfig{
		AutoLockMinutes: 480, // Default 8 hours
		Locked:          true,
	}

	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}

		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])

		switch key {
		case "project":
			config.Project = value
		case "env":
			config.Env = value
		case "locked":
			config.Locked = value == "true"
		case "last_unlocked":
			config.LastUnlocked, _ = time.Parse(time.RFC3339, value)
		case "auto_lock_minutes":
			config.AutoLockMinutes, _ = strconv.Atoi(value)
		}
	}

	return config, nil
}

// Save saves the project config to .envctl/config
func (c *ProjectConfig) Save(projectDir string) error {
	// Ensure .envctl directory exists
	envctlDir := EnvctlDir(projectDir)
	if err := os.MkdirAll(envctlDir, 0700); err != nil {
		return fmt.Errorf("create .envctl directory: %w", err)
	}

	configPath := EnvctlConfigPath(projectDir)

	lines := []string{
		fmt.Sprintf("project=%s", c.Project),
	}

	if c.Env != "" {
		lines = append(lines, fmt.Sprintf("env=%s", c.Env))
	}

	lines = append(lines, fmt.Sprintf("locked=%t", c.Locked))

	if !c.LastUnlocked.IsZero() {
		lines = append(lines, fmt.Sprintf("last_unlocked=%s", c.LastUnlocked.Format(time.RFC3339)))
	}

	if c.AutoLockMinutes > 0 {
		lines = append(lines, fmt.Sprintf("auto_lock_minutes=%d", c.AutoLockMinutes))
	}

	content := strings.Join(lines, "\n") + "\n"
	return os.WriteFile(configPath, []byte(content), 0600)
}

// SaveProjectConfig saves the project config (wrapper for backward compat)
func SaveProjectConfig(dir string, config *ProjectConfig) error {
	return config.Save(dir)
}

// FindProjectConfig walks up directories to find project config
// Returns config, project directory, and error
func FindProjectConfig(startDir string) (*ProjectConfig, string, error) {
	dir := startDir

	for {
		config, err := LoadProjectConfig(dir)
		if err == nil {
			return config, dir, nil
		}

		// Move to parent directory
		parent := dir[:strings.LastIndex(dir, string(os.PathSeparator))]
		if parent == "" || parent == dir {
			// Reached root
			return nil, "", fmt.Errorf("not in an envctl project (no .envctl/config found)")
		}
		dir = parent
	}
}

// ProjectConfigExists checks if project config exists in a directory
func ProjectConfigExists(dir string) bool {
	configPath := EnvctlConfigPath(dir)
	_, err := os.Stat(configPath)
	return err == nil
}
