//go:build linux

package cli

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"text/template"

	"uradical.io/go/envctl/internal/config"
)

const systemdUnitTemplate = `[Unit]
Description=envctl daemon
Documentation=https://uradical.io/envctl
After=network.target

[Service]
Type=simple
ExecStart={{.Executable}} daemon run
Restart=on-failure
RestartSec=5
StandardOutput=append:{{.LogDir}}/daemon.log
StandardError=append:{{.LogDir}}/daemon.err
Environment="HOME={{.Home}}"

[Install]
WantedBy=default.target
`

type systemdConfig struct {
	Executable string
	LogDir     string
	Home       string
}

func installService() error {
	paths, err := config.GetPaths()
	if err != nil {
		return fmt.Errorf("get paths: %w", err)
	}

	// Get current executable
	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("get executable: %w", err)
	}

	// Resolve symlinks
	exe, err = filepath.EvalSymlinks(exe)
	if err != nil {
		return fmt.Errorf("resolve executable path: %w", err)
	}

	home, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("get home directory: %w", err)
	}

	// Prepare systemd user directory
	systemdUserDir := filepath.Join(home, ".config", "systemd", "user")
	if err := os.MkdirAll(systemdUserDir, 0755); err != nil {
		return fmt.Errorf("create systemd user directory: %w", err)
	}

	unitPath := filepath.Join(systemdUserDir, "envctl.service")

	// Check if already installed
	if _, err := os.Stat(unitPath); err == nil {
		fmt.Println("Service is already installed.")
		fmt.Println("To reinstall, first run: envctl daemon uninstall")
		return nil
	}

	// Use config directory for logs
	logDir := paths.ConfigDir
	if err := os.MkdirAll(logDir, 0755); err != nil {
		return fmt.Errorf("create log directory: %w", err)
	}

	// Generate unit file
	tmpl, err := template.New("unit").Parse(systemdUnitTemplate)
	if err != nil {
		return fmt.Errorf("parse template: %w", err)
	}

	f, err := os.Create(unitPath)
	if err != nil {
		return fmt.Errorf("create unit file: %w", err)
	}
	defer f.Close()

	cfg := systemdConfig{
		Executable: exe,
		LogDir:     logDir,
		Home:       home,
	}

	if err := tmpl.Execute(f, cfg); err != nil {
		os.Remove(unitPath)
		return fmt.Errorf("write unit file: %w", err)
	}

	// Reload systemd
	if err := exec.Command("systemctl", "--user", "daemon-reload").Run(); err != nil {
		fmt.Println("Warning: could not reload systemd. Run manually:")
		fmt.Println("  systemctl --user daemon-reload")
	}

	fmt.Println("Service installed successfully.")
	fmt.Println()
	fmt.Printf("Unit file: %s\n", unitPath)
	fmt.Println()
	fmt.Println("Note: The service is NOT enabled to start at login automatically.")
	fmt.Println("This is because it requires passphrase input.")
	fmt.Println()
	fmt.Println("To start the daemon now, run:")
	fmt.Println("  envctl daemon start")
	fmt.Println()
	fmt.Println("To manage with systemctl:")
	fmt.Println("  systemctl --user start envctl")
	fmt.Println("  systemctl --user status envctl")
	fmt.Println("  systemctl --user stop envctl")

	return nil
}

func uninstallService() error {
	home, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("get home directory: %w", err)
	}

	unitPath := filepath.Join(home, ".config", "systemd", "user", "envctl.service")

	// Check if installed
	if _, err := os.Stat(unitPath); os.IsNotExist(err) {
		fmt.Println("Service is not installed.")
		return nil
	}

	// Stop and disable service (ignore errors)
	exec.Command("systemctl", "--user", "stop", "envctl").Run()
	exec.Command("systemctl", "--user", "disable", "envctl").Run()

	// Remove unit file
	if err := os.Remove(unitPath); err != nil {
		return fmt.Errorf("remove unit file: %w", err)
	}

	// Reload systemd
	exec.Command("systemctl", "--user", "daemon-reload").Run()

	fmt.Println("Service uninstalled successfully.")
	return nil
}
