package cli

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"envctl.dev/go/envctl/internal/chain"
	"envctl.dev/go/envctl/internal/client"
	"envctl.dev/go/envctl/internal/config"
	"envctl.dev/go/envctl/internal/crypto"
)

var doctorFix bool

func init() {
	rootCmd.AddCommand(doctorCmd)
	doctorCmd.Flags().BoolVar(&doctorFix, "fix", false, "automatically fix issues (e.g., remove stale socket)")
}

var doctorCmd = &cobra.Command{
	Use:   "doctor",
	Short: "Check envctl health",
	Long: `Run health checks on your envctl installation.

Checks identity, daemon status, network configuration, and project chains.

Use --fix to automatically resolve common issues like stale sockets.`,
	RunE: runDoctor,
}

func runDoctor(cmd *cobra.Command, args []string) error {
	fmt.Printf("envctl v%s\n\n", version)

	paths, err := config.GetPaths()
	if err != nil {
		fmt.Printf("❌ Failed to get paths: %v\n", err)
		return nil
	}

	// Identity checks
	fmt.Println("Identity")
	if paths.IdentityExists() {
		fmt.Println("  ✓ Identity exists")

		// Try to load public identity
		pub, err := crypto.LoadPublic(paths.IdentityPubFile)
		if err != nil {
			fmt.Printf("  ⚠ Could not load public key: %v\n", err)
		} else {
			fmt.Printf("  ✓ Name: %s\n", pub.Name)
			fmt.Printf("  ✓ Fingerprint: %s\n", pub.Fingerprint())
		}
	} else {
		fmt.Println("  ❌ No identity found")
		fmt.Println("     Run 'envctl init' to create one")
	}
	fmt.Println()

	// Daemon checks
	fmt.Println("Daemon")
	if client.IsRunning() {
		c, err := client.Connect()
		if err != nil {
			fmt.Printf("  ⚠ Running but could not connect: %v\n", err)
		} else {
			status, err := c.Status()
			c.Close()
			if err != nil {
				fmt.Printf("  ⚠ Running but could not get status: %v\n", err)
			} else {
				fmt.Printf("  ✓ Running (PID %d, uptime %s)\n", status.PID, status.Uptime)
				fmt.Printf("  ✓ Identity: %s\n", status.Identity)
				fmt.Printf("  ✓ Peers: %d connected\n", status.PeerCount)
				fmt.Printf("  ✓ Projects: %d loaded\n", status.TeamCount)
			}
		}
	} else {
		// Check for stale socket
		if runtime.GOOS != "windows" {
			if _, err := os.Stat(paths.SocketPath); err == nil {
				// Socket file exists but daemon is not responding - stale socket
				fmt.Println("  ❌ Stale socket detected")
				fmt.Printf("    Socket file exists at %s but daemon is not responding\n", paths.SocketPath)
				if doctorFix {
					if err := os.Remove(paths.SocketPath); err != nil {
						fmt.Printf("    ❌ Failed to remove stale socket: %v\n", err)
					} else {
						fmt.Println("    ✓ Removed stale socket")
						fmt.Println("    Start daemon with: envctl daemon start")
					}
				} else {
					fmt.Println("    Run 'envctl doctor --fix' to remove it")
				}
			} else {
				fmt.Println("  ⚠ Not running")
				fmt.Println("    Start with: envctl daemon start")
			}
		} else {
			fmt.Println("  ⚠ Not running")
			fmt.Println("    Start with: envctl daemon start")
		}
	}
	fmt.Println()

	// Network checks
	fmt.Println("Network")
	fmt.Printf("  P2P port: 7834\n")
	fmt.Printf("  Web UI port: 7835\n")

	switch runtime.GOOS {
	case "darwin":
		fmt.Printf("  Socket: %s\n", paths.SocketPath)
	case "linux":
		fmt.Printf("  Socket: %s\n", paths.SocketPath)
	case "windows":
		fmt.Println("  Socket: named pipe (\\\\.\\pipe\\envctl)")
	}

	// Check if ports are available or in use by us
	checkPort("P2P", 7834)
	checkPort("Web UI", 7835)

	// Check mDNS
	checkMDNS()
	fmt.Println()

	// Project checks
	fmt.Println("Projects")
	entries, err := os.ReadDir(paths.ChainsDir)
	if err != nil {
		if os.IsNotExist(err) {
			fmt.Println("  No projects yet")
		} else {
			fmt.Printf("  ⚠ Could not read chains directory: %v\n", err)
		}
	} else {
		projectCount := 0
		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}
			name := entry.Name()
			if len(name) < 6 || name[len(name)-6:] != ".chain" {
				continue
			}
			if len(name) > 8 && name[len(name)-8:] == ".chain.1" {
				continue
			}

			projectName := name[:len(name)-6]
			chainPath := paths.ChainFile(projectName)

			c, err := chain.Load(chainPath)
			if err != nil {
				fmt.Printf("  ⚠ %s: failed to load (%v)\n", projectName, err)
				continue
			}

			// Verify chain
			if err := c.Verify(); err != nil {
				fmt.Printf("  ⚠ %s: %d members, %d blocks, INVALID (%v)\n",
					projectName, c.MemberCount(), c.Len(), err)
			} else {
				fmt.Printf("  ✓ %s: %d members, %d blocks, valid\n",
					projectName, c.MemberCount(), c.Len())
			}
			projectCount++
		}

		if projectCount == 0 {
			fmt.Println("  No projects yet")
			fmt.Println("  Create one with: envctl project create <name>")
		}
	}
	fmt.Println()

	// Configuration
	fmt.Println("Configuration")
	fmt.Printf("  Config file: %s\n", paths.ConfigFile)
	if _, err := os.Stat(paths.ConfigFile); os.IsNotExist(err) {
		fmt.Println("    (not created yet, using defaults)")
	}
	fmt.Println()

	// Current project context
	fmt.Println("Project Context")
	cwd, _ := os.Getwd()
	projectConfig, err := config.LoadProjectConfig(cwd)
	if err != nil {
		fmt.Println("  No .envctl file in current directory")
	} else {
		if projectConfig.Project != "" {
			fmt.Printf("  ✓ Project: %s\n", projectConfig.Project)
		}
		if projectConfig.Env != "" {
			fmt.Printf("  ✓ Environment: %s\n", projectConfig.Env)
		}
	}

	return nil
}

// checkPort checks if a port is available or in use
func checkPort(name string, port int) {
	addr := fmt.Sprintf("127.0.0.1:%d", port)
	conn, err := net.DialTimeout("tcp", addr, 500*time.Millisecond)
	if err != nil {
		// Port appears to be available (nothing listening)
		fmt.Printf("  ⚠ %s port %d: not listening\n", name, port)
	} else {
		conn.Close()
		fmt.Printf("  ✓ %s port %d: listening\n", name, port)
	}
}

// checkMDNS checks if mDNS is functional
func checkMDNS() {
	switch runtime.GOOS {
	case "darwin":
		// Check if mDNSResponder is running
		output, err := exec.Command("pgrep", "-x", "mDNSResponder").Output()
		if err == nil && len(output) > 0 {
			fmt.Println("  ✓ mDNS: mDNSResponder running")
		} else {
			fmt.Println("  ⚠ mDNS: mDNSResponder not detected")
		}
		// Check firewall status
		output, err = exec.Command("/usr/libexec/ApplicationFirewall/socketfilterfw", "--getglobalstate").Output()
		if err == nil {
			if strings.Contains(string(output), "enabled") {
				fmt.Println("  ⚠ Firewall: enabled (may block P2P)")
			} else {
				fmt.Println("  ✓ Firewall: disabled")
			}
		}
	case "linux":
		// Check for avahi-daemon or systemd-resolved
		output, err := exec.Command("systemctl", "is-active", "avahi-daemon").Output()
		if err == nil && strings.TrimSpace(string(output)) == "active" {
			fmt.Println("  ✓ mDNS: avahi-daemon running")
		} else {
			output, err = exec.Command("systemctl", "is-active", "systemd-resolved").Output()
			if err == nil && strings.TrimSpace(string(output)) == "active" {
				fmt.Println("  ✓ mDNS: systemd-resolved running")
			} else {
				fmt.Println("  ⚠ mDNS: no mDNS service detected")
			}
		}
	case "windows":
		// Windows has built-in mDNS support via DNS Client service
		output, err := exec.Command("sc", "query", "Dnscache").Output()
		if err == nil && strings.Contains(string(output), "RUNNING") {
			fmt.Println("  ✓ mDNS: DNS Client running")
		} else {
			fmt.Println("  ⚠ mDNS: DNS Client not running")
		}
		// Check Windows Firewall
		output, err = exec.Command("netsh", "advfirewall", "show", "currentprofile").Output()
		if err == nil && strings.Contains(string(output), "ON") {
			fmt.Println("  ⚠ Firewall: enabled (may block P2P)")
		}
	}
}
