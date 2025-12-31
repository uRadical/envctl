//go:build darwin

package cli

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"text/template"

	"envctl.dev/go/envctl/internal/config"
)

const launchdPlistTemplate = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>io.uradical.envctl</string>
    <key>ProgramArguments</key>
    <array>
        <string>{{.Executable}}</string>
        <string>daemon</string>
        <string>run</string>
    </array>
    <key>RunAtLoad</key>
    <false/>
    <key>KeepAlive</key>
    <dict>
        <key>SuccessfulExit</key>
        <false/>
    </dict>
    <key>StandardOutPath</key>
    <string>{{.LogDir}}/daemon.log</string>
    <key>StandardErrorPath</key>
    <string>{{.LogDir}}/daemon.err</string>
    <key>EnvironmentVariables</key>
    <dict>
        <key>HOME</key>
        <string>{{.Home}}</string>
        <key>PATH</key>
        <string>/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin</string>
    </dict>
</dict>
</plist>
`

type launchdConfig struct {
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

	// Prepare plist path
	launchAgentsDir := filepath.Join(home, "Library", "LaunchAgents")
	if err := os.MkdirAll(launchAgentsDir, 0755); err != nil {
		return fmt.Errorf("create LaunchAgents directory: %w", err)
	}

	plistPath := filepath.Join(launchAgentsDir, "io.uradical.envctl.plist")

	// Check if already installed
	if _, err := os.Stat(plistPath); err == nil {
		fmt.Println("Service is already installed.")
		fmt.Println("To reinstall, first run: envctl daemon uninstall")
		return nil
	}

	// Use config directory for logs
	logDir := paths.ConfigDir
	if err := os.MkdirAll(logDir, 0755); err != nil {
		return fmt.Errorf("create log directory: %w", err)
	}

	// Generate plist
	tmpl, err := template.New("plist").Parse(launchdPlistTemplate)
	if err != nil {
		return fmt.Errorf("parse template: %w", err)
	}

	f, err := os.Create(plistPath)
	if err != nil {
		return fmt.Errorf("create plist file: %w", err)
	}
	defer f.Close()

	cfg := launchdConfig{
		Executable: exe,
		LogDir:     logDir,
		Home:       home,
	}

	if err := tmpl.Execute(f, cfg); err != nil {
		os.Remove(plistPath)
		return fmt.Errorf("write plist: %w", err)
	}

	fmt.Println("Service installed successfully.")
	fmt.Println()
	fmt.Printf("Plist: %s\n", plistPath)
	fmt.Println()
	fmt.Println("Note: The service is NOT set to start at login automatically.")
	fmt.Println("This is because it requires passphrase input.")
	fmt.Println()
	fmt.Println("To start the daemon now, run:")
	fmt.Println("  envctl daemon start")
	fmt.Println()
	fmt.Println("To load the service (for launchctl management):")
	fmt.Printf("  launchctl load %s\n", plistPath)

	return nil
}

func uninstallService() error {
	home, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("get home directory: %w", err)
	}

	plistPath := filepath.Join(home, "Library", "LaunchAgents", "io.uradical.envctl.plist")

	// Check if installed
	if _, err := os.Stat(plistPath); os.IsNotExist(err) {
		fmt.Println("Service is not installed.")
		return nil
	}

	// Unload from launchd (ignore errors if not loaded)
	exec.Command("launchctl", "unload", plistPath).Run()

	// Remove plist file
	if err := os.Remove(plistPath); err != nil {
		return fmt.Errorf("remove plist: %w", err)
	}

	fmt.Println("Service uninstalled successfully.")
	return nil
}
