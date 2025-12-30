package env

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// EnvInfo represents information about an environment file
type EnvInfo struct {
	Name     string `json:"name"`     // "dev", "stage", "prod"
	Path     string `json:"path"`     // ".env.dev"
	VarCount int    `json:"var_count"`
	Current  bool   `json:"current"`
}

// List returns all .env files in a directory
func List(dir string) ([]EnvInfo, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("read directory: %w", err)
	}

	// Check current symlink target
	currentEnv := ""
	envPath := filepath.Join(dir, ".env")
	if target, err := os.Readlink(envPath); err == nil {
		// Extract env name from target (e.g., ".env.dev" -> "dev")
		if strings.HasPrefix(target, ".env.") {
			currentEnv = strings.TrimPrefix(target, ".env.")
		}
	}

	var envs []EnvInfo

	for _, entry := range entries {
		name := entry.Name()

		// Skip directories
		if entry.IsDir() {
			continue
		}

		// Match .env.* files (but not .env itself)
		if !strings.HasPrefix(name, ".env.") {
			continue
		}

		// Skip backup files
		if strings.HasSuffix(name, ".bak") || strings.HasSuffix(name, "~") {
			continue
		}

		envName := strings.TrimPrefix(name, ".env.")
		envFilePath := filepath.Join(dir, name)

		// Count variables
		varCount := 0
		if parsed, err := Parse(envFilePath); err == nil {
			varCount = len(parsed.Variables)
		}

		envs = append(envs, EnvInfo{
			Name:     envName,
			Path:     name,
			VarCount: varCount,
			Current:  envName == currentEnv,
		})
	}

	// Sort by name
	sort.Slice(envs, func(i, j int) bool {
		return envs[i].Name < envs[j].Name
	})

	return envs, nil
}

// Current returns the current environment name, or empty if none is set
func Current(dir string) (string, error) {
	envPath := filepath.Join(dir, ".env")

	// Check if .env exists and is a symlink
	info, err := os.Lstat(envPath)
	if err != nil {
		if os.IsNotExist(err) {
			return "", nil
		}
		return "", fmt.Errorf("stat .env: %w", err)
	}

	// Check if it's a symlink
	if info.Mode()&os.ModeSymlink == 0 {
		// It's a regular file, not managed by us
		return "", nil
	}

	// Read symlink target
	target, err := os.Readlink(envPath)
	if err != nil {
		return "", fmt.Errorf("read symlink: %w", err)
	}

	// Extract env name from target
	if strings.HasPrefix(target, ".env.") {
		return strings.TrimPrefix(target, ".env."), nil
	}

	return "", nil
}

// Use switches to a different environment by updating the .env symlink
func Use(dir, name string) error {
	envPath := filepath.Join(dir, ".env")
	targetPath := fmt.Sprintf(".env.%s", name)
	fullTargetPath := filepath.Join(dir, targetPath)

	// Check that target exists
	if _, err := os.Stat(fullTargetPath); err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("environment not found: %s", name)
		}
		return fmt.Errorf("stat target: %w", err)
	}

	// Check if .env exists
	info, err := os.Lstat(envPath)
	if err == nil {
		// File exists
		if info.Mode()&os.ModeSymlink != 0 {
			// It's a symlink, remove it
			if err := os.Remove(envPath); err != nil {
				return fmt.Errorf("remove old symlink: %w", err)
			}
		} else {
			// It's a regular file, backup first
			backupPath := envPath + ".original"
			if err := os.Rename(envPath, backupPath); err != nil {
				return fmt.Errorf("backup original .env: %w", err)
			}
		}
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("check .env: %w", err)
	}

	// Create symlink
	if err := os.Symlink(targetPath, envPath); err != nil {
		return fmt.Errorf("create symlink: %w", err)
	}

	return nil
}

// Create creates a new environment file
func Create(dir, name string) error {
	path := filepath.Join(dir, fmt.Sprintf(".env.%s", name))

	// Check if already exists
	if _, err := os.Stat(path); err == nil {
		return fmt.Errorf("environment already exists: %s", name)
	}

	// Create empty file
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("create file: %w", err)
	}
	defer f.Close()

	// Write header comment
	_, err = f.WriteString(fmt.Sprintf("# %s environment\n", name))
	if err != nil {
		return fmt.Errorf("write header: %w", err)
	}

	return nil
}

// Delete deletes an environment file
func Delete(dir, name string) error {
	path := filepath.Join(dir, fmt.Sprintf(".env.%s", name))

	// Check if it's the current environment
	current, err := Current(dir)
	if err != nil {
		return fmt.Errorf("check current: %w", err)
	}

	if current == name {
		return fmt.Errorf("cannot delete current environment")
	}

	// Delete the file
	if err := os.Remove(path); err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("environment not found: %s", name)
		}
		return fmt.Errorf("delete file: %w", err)
	}

	return nil
}

// Copy copies an environment to a new name
func Copy(dir, source, dest string) error {
	sourcePath := filepath.Join(dir, fmt.Sprintf(".env.%s", source))
	destPath := filepath.Join(dir, fmt.Sprintf(".env.%s", dest))

	// Check source exists
	data, err := os.ReadFile(sourcePath)
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("source environment not found: %s", source)
		}
		return fmt.Errorf("read source: %w", err)
	}

	// Check dest doesn't exist
	if _, err := os.Stat(destPath); err == nil {
		return fmt.Errorf("destination already exists: %s", dest)
	}

	// Write dest
	if err := os.WriteFile(destPath, data, 0600); err != nil {
		return fmt.Errorf("write destination: %w", err)
	}

	return nil
}
