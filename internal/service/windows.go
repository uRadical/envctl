//go:build windows

package service

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

type windowsInstaller struct {
	taskName string
	execPath string
	logPath  string
}

// NewInstaller returns a Windows-specific service installer
func NewInstaller() Installer {
	execPath, _ := os.Executable()
	if execPath == "" {
		execPath = filepath.Join(os.Getenv("PROGRAMFILES"), "envctl", "envctl.exe")
	}

	appData := os.Getenv("APPDATA")
	logPath := filepath.Join(appData, "envctl", "daemon.log")

	return &windowsInstaller{
		taskName: "envctl",
		execPath: execPath,
		logPath:  logPath,
	}
}

func (i *windowsInstaller) Install() error {
	if i.IsInstalled() {
		return ErrAlreadyInstalled{}
	}

	// Ensure log directory exists
	if err := os.MkdirAll(filepath.Dir(i.logPath), 0755); err != nil {
		return fmt.Errorf("create log dir: %w", err)
	}

	// Create scheduled task that runs at logon
	// Using schtasks.exe for compatibility
	cmd := exec.Command("schtasks", "/Create",
		"/TN", i.taskName,
		"/TR", fmt.Sprintf(`"%s" daemon run`, i.execPath),
		"/SC", "ONLOGON",
		"/RL", "LIMITED",
		"/F",
	)

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("create scheduled task: %w", err)
	}

	return nil
}

func (i *windowsInstaller) Uninstall() error {
	if !i.IsInstalled() {
		return ErrNotInstalled{}
	}

	// Stop if running
	i.Stop()

	// Delete scheduled task
	cmd := exec.Command("schtasks", "/Delete", "/TN", i.taskName, "/F")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("delete scheduled task: %w", err)
	}

	return nil
}

func (i *windowsInstaller) IsInstalled() bool {
	cmd := exec.Command("schtasks", "/Query", "/TN", i.taskName)
	return cmd.Run() == nil
}

func (i *windowsInstaller) Start() error {
	if !i.IsInstalled() {
		return ErrNotInstalled{}
	}

	cmd := exec.Command("schtasks", "/Run", "/TN", i.taskName)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("run scheduled task: %w", err)
	}

	return nil
}

func (i *windowsInstaller) Stop() error {
	if !i.IsInstalled() {
		return ErrNotInstalled{}
	}

	// Find and kill the envctl process
	cmd := exec.Command("taskkill", "/IM", "envctl.exe", "/F")
	_ = cmd.Run() // Ignore error if not running

	return nil
}

func (i *windowsInstaller) Status() (ServiceStatus, error) {
	status := ServiceStatus{}

	if !i.IsInstalled() {
		return status, nil
	}
	status.Installed = true

	// Check if process is running
	cmd := exec.Command("tasklist", "/FI", "IMAGENAME eq envctl.exe", "/FO", "CSV", "/NH")
	output, err := cmd.Output()
	if err != nil {
		return status, nil
	}

	outputStr := string(output)
	if strings.Contains(outputStr, "envctl.exe") {
		status.Running = true

		// Try to get PID from output
		// Format: "envctl.exe","1234","Console","1","5,000 K"
		parts := strings.Split(outputStr, ",")
		if len(parts) >= 2 {
			pidStr := strings.Trim(parts[1], "\"")
			var pid int
			fmt.Sscanf(pidStr, "%d", &pid)
			status.PID = pid
		}
	}

	return status, nil
}

func (i *windowsInstaller) Enable() error {
	if !i.IsInstalled() {
		return ErrNotInstalled{}
	}

	cmd := exec.Command("schtasks", "/Change", "/TN", i.taskName, "/Enable")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("enable scheduled task: %w", err)
	}

	return nil
}

func (i *windowsInstaller) Disable() error {
	if !i.IsInstalled() {
		return ErrNotInstalled{}
	}

	cmd := exec.Command("schtasks", "/Change", "/TN", i.taskName, "/Disable")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("disable scheduled task: %w", err)
	}

	return nil
}

func (i *windowsInstaller) Logs(lines int) (string, error) {
	// Read last N lines from log file
	data, err := os.ReadFile(i.logPath)
	if err != nil {
		return "", fmt.Errorf("read log file: %w", err)
	}

	logLines := strings.Split(string(data), "\n")
	if len(logLines) > lines {
		logLines = logLines[len(logLines)-lines:]
	}

	return strings.Join(logLines, "\n"), nil
}
