package cli

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"uradical.io/go/envctl/internal/config"
	"uradical.io/go/envctl/internal/secrets"
)

func init() {
	rootCmd.AddCommand(statusCmd)
}

var statusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show current project and environment status",
	Long: `Display the current project, active environment, and lock status.

Examples:
  envctl status`,
	RunE: runStatus,
}

func runStatus(cmd *cobra.Command, args []string) error {
	cwd, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("getting current directory: %w", err)
	}

	// Find project config (walks up directories)
	cfg, projectDir, err := config.FindProjectConfig(cwd)
	if err != nil {
		fmt.Println("Not in an envctl project")
		return nil
	}

	// Check if .env exists
	dotEnvPath := config.DotEnvPath(projectDir)
	dotEnvExists := false
	varCount := 0
	if info, err := os.Stat(dotEnvPath); err == nil && info.Size() > 0 {
		dotEnvExists = true
		varCount, _ = secrets.CountVariables(dotEnvPath)
	}

	// List available environments
	envctlDir := config.EnvctlDir(projectDir)
	availableEnvs, _ := secrets.ListEncryptedEnvs(envctlDir)
	availableStr := strings.Join(availableEnvs, ", ")
	if availableStr == "" {
		availableStr = "(none)"
	}

	// Display status
	fmt.Printf("Project:      %s\n", cfg.Project)

	if cfg.Env != "" {
		fmt.Printf("Environment:  %s\n", cfg.Env)
	} else {
		fmt.Printf("Environment:  (not set)\n")
	}

	fmt.Printf("Available:    %s\n", availableStr)

	if dotEnvExists {
		fmt.Printf("Status:       unlocked (%d variables)\n", varCount)
		if !cfg.LastUnlocked.IsZero() {
			duration := time.Since(cfg.LastUnlocked)
			fmt.Printf("Unlocked:     %s ago\n", formatDuration(duration))

			if cfg.AutoLockMinutes > 0 {
				remaining := time.Duration(cfg.AutoLockMinutes)*time.Minute - duration
				if remaining > 0 {
					fmt.Printf("Auto-lock in: %s\n", formatDuration(remaining))
				} else {
					fmt.Printf("Auto-lock:    overdue\n")
				}
			}
		}
	} else {
		fmt.Printf("Status:       locked\n")
	}

	return nil
}

func formatDuration(d time.Duration) string {
	if d < 0 {
		return "0s"
	}
	if d < time.Minute {
		return fmt.Sprintf("%ds", int(d.Seconds()))
	}
	if d < time.Hour {
		return fmt.Sprintf("%dm", int(d.Minutes()))
	}
	if d < 24*time.Hour {
		hours := int(d.Hours())
		mins := int(d.Minutes()) % 60
		if mins > 0 {
			return fmt.Sprintf("%dh %dm", hours, mins)
		}
		return fmt.Sprintf("%dh", hours)
	}
	return fmt.Sprintf("%dd", int(d.Hours()/24))
}
