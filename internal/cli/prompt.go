package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
	"uradical.io/go/envctl/internal/config"
)

func init() {
	rootCmd.AddCommand(promptCmd)
}

// PromptCache is the cached prompt data
type PromptCache struct {
	Team       string `json:"team"`
	Env        string `json:"env"`
	Stale      bool   `json:"stale"`
	LastShared string `json:"last_shared,omitempty"`
	UpdatedBy  string `json:"updated_by,omitempty"`
	UpdatedAt  string `json:"updated_at,omitempty"`
}

var promptCmd = &cobra.Command{
	Use:   "prompt",
	Short: "Output for shell prompt integration",
	Long: `Output environment status for shell prompt integration.

This command is designed to be fast (<10ms) and reads from a cache file
rather than connecting to the daemon. Use it in your shell prompt.

Examples for shell integration are in the README.`,
	RunE: runPrompt,
}

func runPrompt(cmd *cobra.Command, args []string) error {
	// First try the cache file for fastest response
	paths, err := config.GetPaths()
	if err == nil {
		cache, err := loadPromptCache(paths.CacheFile)
		if err == nil && cache.Team != "" {
			outputPrompt(cache)
			return nil
		}
	}

	// Fall back to .envctl file
	cwd, err := os.Getwd()
	if err != nil {
		return nil // Silent fail
	}

	projectConfig, err := config.LoadProjectConfig(cwd)
	if err != nil {
		// Try walking up
		projectConfig, _, err = config.FindProjectConfig(cwd)
		if err != nil {
			return nil // Silent - no project context
		}
	}

	cache := &PromptCache{
		Team: projectConfig.Project,
		Env:  projectConfig.Env,
	}

	if cache.Env == "" {
		// Try to detect from symlink
		envPath := filepath.Join(cwd, ".env")
		if info, err := os.Lstat(envPath); err == nil {
			if info.Mode()&os.ModeSymlink != 0 {
				target, err := os.Readlink(envPath)
				if err == nil && strings.HasPrefix(target, ".env.") {
					cache.Env = strings.TrimPrefix(target, ".env.")
				}
			}
		}
	}

	if cache.Env != "" || cache.Team != "" {
		outputPrompt(cache)
	}

	return nil
}

func loadPromptCache(path string) (*PromptCache, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var cache PromptCache
	if err := json.Unmarshal(data, &cache); err != nil {
		return nil, err
	}

	return &cache, nil
}

func outputPrompt(cache *PromptCache) {
	if cache.Env == "" && cache.Team == "" {
		return
	}

	// Color based on environment
	var color string
	switch cache.Env {
	case "prod", "production":
		color = "\033[31m" // Red
	case "stage", "staging":
		color = "\033[33m" // Yellow
	default:
		color = "\033[32m" // Green
	}

	// Build prompt string
	var parts []string
	if cache.Team != "" {
		parts = append(parts, cache.Team)
	}
	if cache.Env != "" {
		parts = append(parts, cache.Env)
	}

	output := strings.Join(parts, ":")

	// Add stale indicator
	if cache.Stale {
		output += " ↓"
	}

	fmt.Printf("%s%s\033[0m", color, output)
}
