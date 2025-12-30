//go:build darwin

package service

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const launchAgentPlist = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>io.uradical.envctl</string>
    <key>ProgramArguments</key>
    <array>
        <string>%s</string>
        <string>daemon</string>
        <string>run</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <dict>
        <key>SuccessfulExit</key>
        <false/>
    </dict>
    <key>StandardOutPath</key>
    <string>%s/daemon.log</string>
    <key>StandardErrorPath</key>
    <string>%s/daemon.log</string>
</dict>
</plist>
`

type darwinInstaller struct {
	plistPath string
	logDir    string
	execPath  string
}

// NewInstaller returns a macOS-specific service installer
func NewInstaller() Installer {
	home, _ := os.UserHomeDir()
	plistPath := filepath.Join(home, "Library", "LaunchAgents", "io.uradical.envctl.plist")
	logDir := filepath.Join(home, "Library", "Logs", "envctl")

	execPath, _ := os.Executable()
	if execPath == "" {
		execPath = "/usr/local/bin/envctl"
	}

	return &darwinInstaller{
		plistPath: plistPath,
		logDir:    logDir,
		execPath:  execPath,
	}
}

func (i *darwinInstaller) Install() error {
	if i.IsInstalled() {
		return ErrAlreadyInstalled{}
	}

	// Ensure directories exist
	if err := os.MkdirAll(filepath.Dir(i.plistPath), 0755); err != nil {
		return fmt.Errorf("create LaunchAgents dir: %w", err)
	}

	if err := os.MkdirAll(i.logDir, 0755); err != nil {
		return fmt.Errorf("create log dir: %w", err)
	}

	// Write plist
	content := fmt.Sprintf(launchAgentPlist, i.execPath, i.logDir, i.logDir)
	if err := os.WriteFile(i.plistPath, []byte(content), 0644); err != nil {
		return fmt.Errorf("write plist: %w", err)
	}

	return nil
}

func (i *darwinInstaller) Uninstall() error {
	if !i.IsInstalled() {
		return ErrNotInstalled{}
	}

	// Unload if loaded
	i.Stop()

	// Remove plist
	if err := os.Remove(i.plistPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove plist: %w", err)
	}

	return nil
}

func (i *darwinInstaller) IsInstalled() bool {
	_, err := os.Stat(i.plistPath)
	return err == nil
}

func (i *darwinInstaller) Start() error {
	if !i.IsInstalled() {
		return ErrNotInstalled{}
	}

	cmd := exec.Command("launchctl", "load", i.plistPath)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("launchctl load: %w", err)
	}

	return nil
}

func (i *darwinInstaller) Stop() error {
	if !i.IsInstalled() {
		return ErrNotInstalled{}
	}

	cmd := exec.Command("launchctl", "unload", i.plistPath)
	if err := cmd.Run(); err != nil {
		// Ignore error if not loaded
		return nil
	}

	return nil
}

func (i *darwinInstaller) Status() (ServiceStatus, error) {
	status := ServiceStatus{}

	if !i.IsInstalled() {
		return status, nil
	}
	status.Installed = true

	// Check if running using launchctl list
	cmd := exec.Command("launchctl", "list", "io.uradical.envctl")
	output, err := cmd.Output()
	if err != nil {
		// Not running
		return status, nil
	}

	// Parse output to get PID
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		if strings.Contains(line, "PID") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				if parts[1] != "-" {
					if pid, err := strconv.Atoi(parts[1]); err == nil {
						status.PID = pid
						status.Running = true
					}
				}
			}
		}
	}

	// If we have a PID, get uptime from process start time
	if status.PID > 0 {
		status.Running = true
		// Use ps to get start time
		psCmd := exec.Command("ps", "-o", "lstart=", "-p", strconv.Itoa(status.PID))
		psOutput, err := psCmd.Output()
		if err == nil {
			// Parse date
			startStr := strings.TrimSpace(string(psOutput))
			if t, err := time.Parse("Mon Jan 2 15:04:05 2006", startStr); err == nil {
				status.Uptime = time.Since(t)
			}
		}
	}

	return status, nil
}

func (i *darwinInstaller) Enable() error {
	// On macOS, services are enabled by loading them
	return i.Start()
}

func (i *darwinInstaller) Disable() error {
	return i.Stop()
}

func (i *darwinInstaller) Logs(lines int) (string, error) {
	logFile := filepath.Join(i.logDir, "daemon.log")
	cmd := exec.Command("tail", "-n", strconv.Itoa(lines), logFile)
	output, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("tail logs: %w", err)
	}
	return string(output), nil
}
