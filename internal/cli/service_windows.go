//go:build windows

package cli

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

const taskName = "EnvctlDaemon"

func installService() error {
	// Get current executable
	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("get executable: %w", err)
	}

	// Resolve to absolute path
	exe, err = filepath.Abs(exe)
	if err != nil {
		return fmt.Errorf("resolve executable path: %w", err)
	}

	// Check if already installed
	checkCmd := exec.Command("schtasks", "/Query", "/TN", taskName)
	if err := checkCmd.Run(); err == nil {
		fmt.Println("Service is already installed.")
		fmt.Println("To reinstall, first run: envctl daemon uninstall")
		return nil
	}

	// Create scheduled task
	// Note: We use /SC ONLOGON but /DELAY to give time for network
	// The task runs interactively so the user can enter passphrase
	args := []string{
		"/Create",
		"/TN", taskName,
		"/TR", fmt.Sprintf(`"%s" daemon run`, exe),
		"/SC", "ONLOGON",
		"/DELAY", "0000:30", // 30 second delay after login
		"/RL", "LIMITED",   // Run with limited privileges
		"/IT",              // Interactive (allows passphrase input)
		"/F",               // Force create (overwrite if exists)
	}

	cmd := exec.Command("schtasks", args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("create scheduled task: %w", err)
	}

	fmt.Println("Service installed successfully.")
	fmt.Println()
	fmt.Printf("Task name: %s\n", taskName)
	fmt.Println()
	fmt.Println("Note: The task is set to run at logon with a 30-second delay.")
	fmt.Println("It runs interactively so you can enter your passphrase.")
	fmt.Println()
	fmt.Println("To start the daemon now, run:")
	fmt.Println("  envctl daemon start")
	fmt.Println()
	fmt.Println("To manage the scheduled task:")
	fmt.Printf("  schtasks /Query /TN %s /V\n", taskName)
	fmt.Printf("  schtasks /Run /TN %s\n", taskName)
	fmt.Printf("  schtasks /End /TN %s\n", taskName)

	return nil
}

func uninstallService() error {
	// Check if installed
	checkCmd := exec.Command("schtasks", "/Query", "/TN", taskName)
	if err := checkCmd.Run(); err != nil {
		// Check if error is because task doesn't exist
		output, _ := checkCmd.CombinedOutput()
		if strings.Contains(string(output), "does not exist") || err != nil {
			fmt.Println("Service is not installed.")
			return nil
		}
	}

	// Stop the task if running (ignore errors)
	exec.Command("schtasks", "/End", "/TN", taskName).Run()

	// Delete the scheduled task
	cmd := exec.Command("schtasks", "/Delete", "/TN", taskName, "/F")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("delete scheduled task: %w", err)
	}

	fmt.Println("Service uninstalled successfully.")
	return nil
}
