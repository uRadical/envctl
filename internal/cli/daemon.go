package cli

import (
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"syscall"
	"time"

	"github.com/spf13/cobra"
	"envctl.dev/go/envctl/internal/client"
	"envctl.dev/go/envctl/internal/config"
	"envctl.dev/go/envctl/internal/crypto"
	"envctl.dev/go/envctl/internal/daemon"
	"envctl.dev/go/envctl/internal/keychain"
	"envctl.dev/go/envctl/internal/tui"
)

var (
	daemonP2PPort  int
	daemonWebPort  int
	daemonLogFile  string
)

func init() {
	rootCmd.AddCommand(daemonCmd)

	// Subcommands
	daemonCmd.AddCommand(daemonRunCmd)
	daemonCmd.AddCommand(daemonStartCmd)
	daemonCmd.AddCommand(daemonStopCmd)
	daemonCmd.AddCommand(daemonStatusCmd)
	daemonCmd.AddCommand(daemonEnvCmd)
	daemonCmd.AddCommand(daemonInstallCmd)
	daemonCmd.AddCommand(daemonUninstallCmd)

	// Flags
	daemonRunCmd.Flags().IntVar(&daemonP2PPort, "p2p-port", 7834, "P2P port")
	daemonRunCmd.Flags().IntVar(&daemonWebPort, "web-port", 7835, "Web UI port")
	daemonRunCmd.Flags().StringVar(&daemonLogFile, "log-file", "", "Log file path")
}

var daemonCmd = &cobra.Command{
	Use:   "daemon",
	Short: "Daemon management commands",
	Long: `Control the envctl background daemon.

The daemon handles peer-to-peer connections, chain synchronization,
and serves the web UI.`,
}

var daemonRunCmd = &cobra.Command{
	Use:   "run",
	Short: "Run daemon in foreground",
	Long: `Run the daemon in the foreground.

This is typically used by service managers (systemd, launchd).
For manual use, prefer 'envctl daemon start'.`,
	RunE: runDaemonRun,
}

func runDaemonRun(cmd *cobra.Command, args []string) error {
	paths, err := config.GetPaths()
	if err != nil {
		return fmt.Errorf("get paths: %w", err)
	}

	// Check identity exists
	if !paths.IdentityExists() {
		return fmt.Errorf("no identity found. Run 'envctl init' first")
	}

	// Try to get passphrase from keychain first
	var passphrase []byte
	keychainPass, err := keychain.Get()
	if err == nil {
		passphrase = []byte(keychainPass)
	} else {
		// Prompt for passphrase
		passphrase, err = tui.ReadPassword("Passphrase: ")
		if err != nil {
			return fmt.Errorf("read passphrase: %w", err)
		}
	}

	// Load identity with retries
	var identity *crypto.Identity
	for retries := 0; retries < 3; retries++ {
		identity, err = crypto.LoadEncrypted(paths.IdentityFile, passphrase)
		if err == nil {
			break
		}

		if retries < 2 {
			fmt.Println("Invalid passphrase. Try again.")
			passphrase, err = tui.ReadPassword("Passphrase: ")
			if err != nil {
				return fmt.Errorf("read passphrase: %w", err)
			}
		}
	}
	crypto.ZeroBytes(passphrase)

	if identity == nil {
		return fmt.Errorf("failed to load identity after 3 attempts")
	}

	// Ensure directories
	if err := paths.EnsureDirectories(); err != nil {
		return fmt.Errorf("create directories: %w", err)
	}

	// Check for existing daemon
	if client.IsRunning() {
		return fmt.Errorf("daemon is already running")
	}

	// Create and run daemon
	d, err := daemon.New(&daemon.Options{
		Paths:      paths,
		Identity:   identity,
		P2PPort:    daemonP2PPort,
		WebPort:    daemonWebPort,
		WebEnabled: true,
	})
	if err != nil {
		return fmt.Errorf("create daemon: %w", err)
	}

	fmt.Println("Daemon starting...")
	return d.Run()
}

var daemonStartCmd = &cobra.Command{
	Use:   "start",
	Short: "Start daemon in background",
	Long: `Start the daemon in the background.

The daemon will continue running after this command exits.
Use 'envctl daemon status' to check if it's running.`,
	RunE: runDaemonStart,
}

func runDaemonStart(cmd *cobra.Command, args []string) error {
	paths, err := config.GetPaths()
	if err != nil {
		return fmt.Errorf("get paths: %w", err)
	}

	// Check if already running
	if client.IsRunning() {
		fmt.Println("Daemon is already running.")
		return nil
	}

	// Check identity exists
	if !paths.IdentityExists() {
		return fmt.Errorf("no identity found. Run 'envctl init' first")
	}

	// Get current executable
	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("get executable: %w", err)
	}

	// Load config to get port settings
	cfg, _ := config.LoadFrom(paths.ConfigFile)
	p2pPort := 7834
	webPort := 7835
	if cfg != nil && cfg.Daemon.P2PPort > 0 {
		p2pPort = cfg.Daemon.P2PPort
	}
	if cfg != nil && cfg.Daemon.WebPort > 0 {
		webPort = cfg.Daemon.WebPort
	}

	// Start daemon process with port flags from config
	daemonCmd := exec.Command(exe, "daemon", "run",
		fmt.Sprintf("--p2p-port=%d", p2pPort),
		fmt.Sprintf("--web-port=%d", webPort))
	daemonCmd.Stdin = os.Stdin // For passphrase input
	daemonCmd.Stdout = os.Stdout
	daemonCmd.Stderr = os.Stderr

	// Start the daemon process - this will prompt for passphrase if needed
	if err := daemonCmd.Start(); err != nil {
		return fmt.Errorf("start daemon: %w", err)
	}

	// Create a channel to signal when daemon exits
	done := make(chan error, 1)
	go func() {
		done <- daemonCmd.Wait()
	}()

	// Wait for daemon to start (poll for IPC socket) or exit
	// Give plenty of time for passphrase entry
	timeout := time.After(60 * time.Second)
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case err := <-done:
			// Daemon exited - this means it failed (passphrase wrong, etc.)
			if err != nil {
				return fmt.Errorf("daemon failed to start: %w", err)
			}
			return fmt.Errorf("daemon exited unexpectedly")

		case <-ticker.C:
			// Check if daemon is now running
			if client.IsRunning() {
				fmt.Printf("Daemon started (PID %d).\n", daemonCmd.Process.Pid)
				fmt.Println("Use 'envctl daemon status' for details.")
				return nil
			}

		case <-timeout:
			// Timeout waiting for daemon
			fmt.Println("Timeout waiting for daemon to start.")
			fmt.Println("The daemon process may still be running in the background.")
			return nil
		}
	}
}

var daemonStopCmd = &cobra.Command{
	Use:   "stop",
	Short: "Stop the daemon",
	RunE:  runDaemonStop,
}

func runDaemonStop(cmd *cobra.Command, args []string) error {
	paths, err := config.GetPaths()
	if err != nil {
		return fmt.Errorf("get paths: %w", err)
	}

	// Read PID file
	if paths.PIDFile == "" {
		return fmt.Errorf("no PID file path configured")
	}

	data, err := os.ReadFile(paths.PIDFile)
	if err != nil {
		if os.IsNotExist(err) {
			fmt.Println("Daemon is not running (no PID file).")
			return nil
		}
		return fmt.Errorf("read PID file: %w", err)
	}

	pid, err := strconv.Atoi(string(data))
	if err != nil {
		return fmt.Errorf("parse PID: %w", err)
	}

	// Find process
	process, err := os.FindProcess(pid)
	if err != nil {
		return fmt.Errorf("find process: %w", err)
	}

	// Send SIGTERM
	fmt.Printf("Sending SIGTERM to daemon (PID %d)...\n", pid)
	if err := process.Signal(syscall.SIGTERM); err != nil {
		return fmt.Errorf("send signal: %w", err)
	}

	// Wait for process to exit
	for i := 0; i < 30; i++ {
		if !client.IsRunning() {
			fmt.Println("Daemon stopped.")
			return nil
		}
		time.Sleep(100 * time.Millisecond)
	}

	fmt.Println("Daemon did not stop gracefully. Consider 'kill -9'.")
	return nil
}

var daemonStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show daemon status",
	RunE:  runDaemonStatus,
}

func runDaemonStatus(cmd *cobra.Command, args []string) error {
	c, err := client.Connect()
	if err != nil {
		fmt.Println("Daemon is not running.")
		return nil
	}
	defer c.Close()

	status, err := c.Status()
	if err != nil {
		return fmt.Errorf("get status: %w", err)
	}

	fmt.Println("Daemon Status")
	fmt.Println()
	fmt.Printf("  Running:     yes\n")
	fmt.Printf("  PID:         %d\n", status.PID)
	fmt.Printf("  Uptime:      %s\n", status.Uptime)
	fmt.Printf("  Identity:    %s\n", status.Identity)
	fmt.Printf("  Fingerprint: %s\n", status.Fingerprint)
	fmt.Printf("  P2P Address: %s\n", status.P2PAddr)
	fmt.Printf("  Peers:       %d connected\n", status.PeerCount)
	fmt.Printf("  Teams:       %d loaded\n", status.TeamCount)

	// Agent status
	if status.AgentUnlocked {
		fmt.Printf("  Agent:       unlocked\n")
	} else {
		fmt.Printf("  Agent:       locked\n")
	}
	if status.PendingCount > 0 {
		fmt.Printf("  Pending:     %d secrets\n", status.PendingCount)
	}

	return nil
}

var daemonEnvCmd = &cobra.Command{
	Use:   "env",
	Short: "Print shell environment for daemon integration",
	Long: `Print environment variables for shell integration.

This command outputs shell commands to set up environment variables
for integrating with the daemon. Add it to your shell profile:

  # bash/zsh
  eval "$(envctl daemon env)"

  # fish
  envctl daemon env | source

The following variables are set:
  ENVCTL_SOCKET  - Path to the daemon socket
  ENVCTL_RUNNING - Set to 1 if daemon is running`,
	RunE: runDaemonEnv,
}

func runDaemonEnv(cmd *cobra.Command, args []string) error {
	paths, err := config.GetPaths()
	if err != nil {
		return fmt.Errorf("get paths: %w", err)
	}

	// Always output socket path
	fmt.Printf("export ENVCTL_SOCKET=%q\n", paths.SocketPath)

	// Check if daemon is running
	c, err := client.Connect()
	if err != nil {
		fmt.Println("export ENVCTL_RUNNING=0")
		return nil
	}
	defer c.Close()

	fmt.Println("export ENVCTL_RUNNING=1")
	return nil
}

var daemonInstallCmd = &cobra.Command{
	Use:   "install",
	Short: "Install daemon as user service",
	Long: `Install the daemon as a user service.

On Linux, this creates a systemd user service.
On macOS, this creates a launchd agent.
On Windows, this creates a scheduled task.

The service will start the daemon automatically when you log in.`,
	RunE: runDaemonInstall,
}

func runDaemonInstall(cmd *cobra.Command, args []string) error {
	return installService()
}

var daemonUninstallCmd = &cobra.Command{
	Use:   "uninstall",
	Short: "Remove daemon user service",
	RunE:  runDaemonUninstall,
}

func runDaemonUninstall(cmd *cobra.Command, args []string) error {
	return uninstallService()
}
