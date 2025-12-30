//go:build linux

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

const systemdUserUnit = `[Unit]
Description=envctl daemon
Documentation=https://github.com/uradical/envctl
After=network.target

[Service]
Type=simple
ExecStart=%s daemon run
Restart=on-failure
RestartSec=5

[Install]
WantedBy=default.target
`

type linuxInstaller struct {
	unitPath string
	execPath string
}

// NewInstaller returns a Linux-specific service installer
func NewInstaller() Installer {
	home, _ := os.UserHomeDir()
	configDir := filepath.Join(home, ".config", "systemd", "user")
	unitPath := filepath.Join(configDir, "envctl.service")

	execPath, _ := os.Executable()
	if execPath == "" {
		execPath = "/usr/local/bin/envctl"
	}

	return &linuxInstaller{
		unitPath: unitPath,
		execPath: execPath,
	}
}

func (i *linuxInstaller) Install() error {
	if i.IsInstalled() {
		return ErrAlreadyInstalled{}
	}

	// Ensure directory exists
	dir := filepath.Dir(i.unitPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("create systemd user dir: %w", err)
	}

	// Write unit file
	content := fmt.Sprintf(systemdUserUnit, i.execPath)
	if err := os.WriteFile(i.unitPath, []byte(content), 0644); err != nil {
		return fmt.Errorf("write unit file: %w", err)
	}

	// Reload systemd
	if err := exec.Command("systemctl", "--user", "daemon-reload").Run(); err != nil {
		return fmt.Errorf("systemctl daemon-reload: %w", err)
	}

	return nil
}

func (i *linuxInstaller) Uninstall() error {
	if !i.IsInstalled() {
		return ErrNotInstalled{}
	}

	// Stop if running
	i.Stop()

	// Disable
	exec.Command("systemctl", "--user", "disable", "envctl").Run()

	// Remove unit file
	if err := os.Remove(i.unitPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove unit file: %w", err)
	}

	// Reload systemd
	exec.Command("systemctl", "--user", "daemon-reload").Run()

	return nil
}

func (i *linuxInstaller) IsInstalled() bool {
	_, err := os.Stat(i.unitPath)
	return err == nil
}

func (i *linuxInstaller) Start() error {
	if !i.IsInstalled() {
		return ErrNotInstalled{}
	}

	cmd := exec.Command("systemctl", "--user", "start", "envctl")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("systemctl start: %w", err)
	}

	return nil
}

func (i *linuxInstaller) Stop() error {
	if !i.IsInstalled() {
		return ErrNotInstalled{}
	}

	cmd := exec.Command("systemctl", "--user", "stop", "envctl")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("systemctl stop: %w", err)
	}

	return nil
}

func (i *linuxInstaller) Status() (ServiceStatus, error) {
	status := ServiceStatus{}

	if !i.IsInstalled() {
		return status, nil
	}
	status.Installed = true

	// Check if running
	cmd := exec.Command("systemctl", "--user", "is-active", "envctl")
	output, _ := cmd.Output()
	status.Running = strings.TrimSpace(string(output)) == "active"

	if status.Running {
		// Get PID
		pidCmd := exec.Command("systemctl", "--user", "show", "envctl", "--property=MainPID", "--value")
		pidOutput, _ := pidCmd.Output()
		if pid, err := strconv.Atoi(strings.TrimSpace(string(pidOutput))); err == nil {
			status.PID = pid
		}

		// Get uptime
		uptimeCmd := exec.Command("systemctl", "--user", "show", "envctl", "--property=ActiveEnterTimestamp", "--value")
		uptimeOutput, _ := uptimeCmd.Output()
		if t, err := time.Parse("Mon 2006-01-02 15:04:05 MST", strings.TrimSpace(string(uptimeOutput))); err == nil {
			status.Uptime = time.Since(t)
		}
	}

	return status, nil
}

func (i *linuxInstaller) Enable() error {
	if !i.IsInstalled() {
		return ErrNotInstalled{}
	}

	cmd := exec.Command("systemctl", "--user", "enable", "envctl")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("systemctl enable: %w", err)
	}

	return nil
}

func (i *linuxInstaller) Disable() error {
	if !i.IsInstalled() {
		return ErrNotInstalled{}
	}

	cmd := exec.Command("systemctl", "--user", "disable", "envctl")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("systemctl disable: %w", err)
	}

	return nil
}

func (i *linuxInstaller) Logs(lines int) (string, error) {
	cmd := exec.Command("journalctl", "--user", "-u", "envctl", "-n", strconv.Itoa(lines), "--no-pager")
	output, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("journalctl: %w", err)
	}
	return string(output), nil
}
