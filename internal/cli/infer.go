package cli

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// InferredName contains the inferred project name and its source
type InferredName struct {
	Name   string
	Source string // ".envctl/config", "git remote origin", or "directory name"
}

// inferProjectName attempts to infer project name from .envctl/config, git remote, or directory
func inferProjectName() (*InferredName, error) {
	// First, check .envctl/config in current directory
	if name := readProjectFromConfig(".envctl/config"); name != "" {
		return &InferredName{Name: name, Source: ".envctl/config"}, nil
	}

	// Try git remote origin
	cmd := exec.Command("git", "remote", "get-url", "origin")
	output, err := cmd.Output()
	if err == nil {
		name := parseRepoNameFromURL(strings.TrimSpace(string(output)))
		if name != "" {
			return &InferredName{Name: name, Source: "git remote origin"}, nil
		}
	}

	// Fall back to directory name
	cwd, err := os.Getwd()
	if err != nil {
		return nil, fmt.Errorf("get working directory: %w", err)
	}

	name := filepath.Base(cwd)
	if name == "" || name == "." || name == "/" {
		return nil, fmt.Errorf("could not determine directory name")
	}

	return &InferredName{Name: name, Source: "directory name"}, nil
}

// readProjectFromConfig reads the project name from .envctl/config file
func readProjectFromConfig(configPath string) string {
	file, err := os.Open(configPath)
	if err != nil {
		return ""
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "project=") {
			return strings.TrimPrefix(line, "project=")
		}
	}
	return ""
}

// parseRepoNameFromURL extracts repo name from git URL
// Handles: git@github.com:user/repo.git, https://github.com/user/repo.git
func parseRepoNameFromURL(url string) string {
	if url == "" {
		return ""
	}

	// Remove .git suffix
	url = strings.TrimSuffix(url, ".git")

	// SSH format: git@github.com:user/repo
	if strings.Contains(url, ":") && strings.Contains(url, "@") {
		parts := strings.Split(url, ":")
		if len(parts) == 2 {
			pathParts := strings.Split(parts[1], "/")
			if len(pathParts) > 0 {
				return pathParts[len(pathParts)-1]
			}
		}
	}

	// HTTPS format: https://github.com/user/repo
	parts := strings.Split(url, "/")
	if len(parts) > 0 {
		return parts[len(parts)-1]
	}

	return ""
}
