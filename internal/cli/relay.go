package cli

import (
	"encoding/json"
	"fmt"

	"github.com/spf13/cobra"
	"envctl.dev/go/envctl/internal/client"
)

func init() {
	rootCmd.AddCommand(relayCmd)

	relayCmd.AddCommand(relayStatusCmd)
	relayCmd.AddCommand(relayConnectCmd)
	relayCmd.AddCommand(relayDisconnectCmd)

	// Add --project flag to relay commands
	relayStatusCmd.Flags().StringP("project", "p", "", "project name")

	// Add project relay subcommand
	projectCmd.AddCommand(projectRelayCmd)
	projectRelayCmd.AddCommand(projectRelayStatusCmd)
	projectRelayCmd.AddCommand(projectRelaySetCmd)
	projectRelaySetCmd.Flags().Bool("disable", false, "disable relay for this project")
}

var relayCmd = &cobra.Command{
	Use:   "relay",
	Short: "Relay server management",
	Long: `Manage relay server connections for async sync with offline peers.

The relay acts as a store-and-forward mailbox - when peers are offline,
messages go to the relay; when they come online, they fetch pending messages.

Relay is configured per-project in the project chain using:
  envctl project relay set <url>

All messages sent via relay are end-to-end encrypted.`,
}

var relayStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show relay status",
	Long: `Show the status of relay connections.

Without --project, shows status for all projects.
With --project, shows detailed status for that project.`,
	RunE: runRelayStatus,
}

func runRelayStatus(cmd *cobra.Command, args []string) error {
	if err := client.RequireDaemon(); err != nil {
		return fmt.Errorf("daemon not running. Start with: envctl daemon start")
	}

	c, err := client.Connect()
	if err != nil {
		return fmt.Errorf("connect to daemon: %w", err)
	}
	defer c.Close()

	project, _ := cmd.Flags().GetString("project")

	if project != "" {
		// Get status for specific project
		result, err := c.Call("relay.project_status", project)
		if err != nil {
			return fmt.Errorf("get relay status: %w", err)
		}

		var status struct {
			Project    string `json:"project"`
			RelayURL   string `json:"relay_url"`
			AllowRelay bool   `json:"allow_relay"`
			Status     struct {
				Project   string `json:"project"`
				URL       string `json:"url"`
				Connected bool   `json:"connected"`
				LastError string `json:"last_error,omitempty"`
			} `json:"status"`
		}

		if err := json.Unmarshal(result, &status); err != nil {
			return fmt.Errorf("parse response: %w", err)
		}

		fmt.Printf("Relay Status for %s\n\n", status.Project)

		if !status.AllowRelay {
			fmt.Println("  Relay: disabled")
			fmt.Println()
			fmt.Println("Enable relay with: envctl project relay set <url>")
			return nil
		}

		if status.RelayURL == "" {
			fmt.Println("  Relay: enabled but not configured")
			fmt.Println()
			fmt.Println("Configure relay with: envctl project relay set <url>")
			return nil
		}

		fmt.Printf("  URL: %s\n", status.RelayURL)
		if status.Status.Connected {
			fmt.Println("  Status: connected")
		} else {
			fmt.Println("  Status: disconnected")
			if status.Status.LastError != "" {
				fmt.Printf("  Last Error: %s\n", status.Status.LastError)
			}
		}
		fmt.Println()

		return nil
	}

	// Get status for all projects
	result, err := c.Call("relay.status", nil)
	if err != nil {
		return fmt.Errorf("get relay status: %w", err)
	}

	var status struct {
		Enabled  bool `json:"enabled"`
		Projects map[string]struct {
			Project   string `json:"project"`
			URL       string `json:"url"`
			Connected bool   `json:"connected"`
			LastError string `json:"last_error,omitempty"`
		} `json:"projects"`
	}

	if err := json.Unmarshal(result, &status); err != nil {
		return fmt.Errorf("parse response: %w", err)
	}

	if !status.Enabled {
		fmt.Println("Relay is not enabled.")
		fmt.Println()
		fmt.Println("Relay is enabled automatically when a project has a relay URL configured.")
		return nil
	}

	if len(status.Projects) == 0 {
		fmt.Println("No projects have relay configured.")
		fmt.Println()
		fmt.Println("Configure relay for a project with: envctl project relay set <url>")
		return nil
	}

	fmt.Printf("Relay Connections (%d)\n\n", len(status.Projects))

	for project, ps := range status.Projects {
		statusStr := "connected"
		if !ps.Connected {
			statusStr = "disconnected"
		}

		fmt.Printf("  %s [%s]\n", project, statusStr)
		fmt.Printf("    URL: %s\n", ps.URL)
		if ps.LastError != "" {
			fmt.Printf("    Last Error: %s\n", ps.LastError)
		}
		fmt.Println()
	}

	return nil
}

var relayConnectCmd = &cobra.Command{
	Use:   "connect <project>",
	Short: "Connect to relay for a project",
	Long: `Manually connect to the relay for a project.

The daemon automatically connects to relays for projects that have
relay configured. Use this command if you need to manually reconnect.`,
	Args: cobra.ExactArgs(1),
	RunE: runRelayConnect,
}

func runRelayConnect(cmd *cobra.Command, args []string) error {
	project := args[0]

	if err := client.RequireDaemon(); err != nil {
		return fmt.Errorf("daemon not running. Start with: envctl daemon start")
	}

	c, err := client.Connect()
	if err != nil {
		return fmt.Errorf("connect to daemon: %w", err)
	}
	defer c.Close()

	result, err := c.Call("relay.connect", project)
	if err != nil {
		return fmt.Errorf("connect to relay: %w", err)
	}

	var resp struct {
		Connected bool   `json:"connected"`
		Project   string `json:"project"`
	}

	if err := json.Unmarshal(result, &resp); err != nil {
		return fmt.Errorf("parse response: %w", err)
	}

	fmt.Printf("Connected to relay for project %s\n", resp.Project)
	return nil
}

var relayDisconnectCmd = &cobra.Command{
	Use:   "disconnect <project>",
	Short: "Disconnect from relay for a project",
	Long:  `Manually disconnect from the relay for a project.`,
	Args:  cobra.ExactArgs(1),
	RunE:  runRelayDisconnect,
}

func runRelayDisconnect(cmd *cobra.Command, args []string) error {
	project := args[0]

	if err := client.RequireDaemon(); err != nil {
		return fmt.Errorf("daemon not running. Start with: envctl daemon start")
	}

	c, err := client.Connect()
	if err != nil {
		return fmt.Errorf("connect to daemon: %w", err)
	}
	defer c.Close()

	result, err := c.Call("relay.disconnect", project)
	if err != nil {
		return fmt.Errorf("disconnect from relay: %w", err)
	}

	var resp struct {
		Disconnected bool   `json:"disconnected"`
		Project      string `json:"project"`
	}

	if err := json.Unmarshal(result, &resp); err != nil {
		return fmt.Errorf("parse response: %w", err)
	}

	fmt.Printf("Disconnected from relay for project %s\n", resp.Project)
	return nil
}

// Project relay commands

var projectRelayCmd = &cobra.Command{
	Use:   "relay",
	Short: "Manage project relay settings",
	Long: `Manage the relay server configuration for this project.

The relay enables async sync with offline peers. When a peer is offline,
messages are stored on the relay and delivered when they come online.

All messages are end-to-end encrypted - the relay only sees encrypted blobs.`,
	PersistentPreRun: projectPreRun, // Copy --project to teamNameFlag
}

var projectRelayStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show relay status for this project",
	RunE:  runProjectRelayStatus,
}

func runProjectRelayStatus(cmd *cobra.Command, args []string) error {
	project := teamNameFlag
	if project == "" {
		// Try to infer from git or directory
		inferred, err := inferProjectName()
		if err != nil {
			return fmt.Errorf("no project specified. Use --project or run from a linked directory")
		}
		project = inferred.Name
	}

	if err := client.RequireDaemon(); err != nil {
		return fmt.Errorf("daemon not running. Start with: envctl daemon start")
	}

	c, err := client.Connect()
	if err != nil {
		return fmt.Errorf("connect to daemon: %w", err)
	}
	defer c.Close()

	result, err := c.Call("relay.project_status", project)
	if err != nil {
		return fmt.Errorf("get relay status: %w", err)
	}

	var status struct {
		Project    string `json:"project"`
		RelayURL   string `json:"relay_url"`
		AllowRelay bool   `json:"allow_relay"`
		Status     struct {
			Project   string `json:"project"`
			URL       string `json:"url"`
			Connected bool   `json:"connected"`
			LastError string `json:"last_error,omitempty"`
		} `json:"status"`
	}

	if err := json.Unmarshal(result, &status); err != nil {
		return fmt.Errorf("parse response: %w", err)
	}

	fmt.Printf("Relay Status for %s\n\n", status.Project)

	if !status.AllowRelay {
		fmt.Println("  Relay: disabled")
		fmt.Println()
		fmt.Println("Enable relay with: envctl project relay set <url>")
		return nil
	}

	if status.RelayURL == "" {
		fmt.Println("  Relay: enabled but not configured")
		fmt.Println()
		fmt.Println("Configure relay with: envctl project relay set <url>")
		return nil
	}

	fmt.Printf("  URL: %s\n", status.RelayURL)
	if status.Status.Connected {
		fmt.Println("  Status: connected")
	} else {
		fmt.Println("  Status: disconnected")
		if status.Status.LastError != "" {
			fmt.Printf("  Last Error: %s\n", status.Status.LastError)
		}
	}
	fmt.Println()

	return nil
}

var projectRelaySetCmd = &cobra.Command{
	Use:   "set [url]",
	Short: "Set relay URL for this project (requires admin consensus)",
	Long: `Set the relay server URL for this project.

This creates a proposal to update the project policy with the relay URL.
The proposal must be approved by enough admins according to project policy.

Use --disable to disable relay for this project.

Examples:
  envctl project relay set wss://relay.envctl.dev/ws
  envctl project relay set --disable`,
	Args: cobra.MaximumNArgs(1),
	RunE: runProjectRelaySet,
}

func runProjectRelaySet(cmd *cobra.Command, args []string) error {
	disable, _ := cmd.Flags().GetBool("disable")

	var url string
	if len(args) > 0 {
		url = args[0]
	}

	if !disable && url == "" {
		return fmt.Errorf("relay URL required (or use --disable)")
	}

	project := teamNameFlag
	if project == "" {
		inferred, err := inferProjectName()
		if err != nil {
			return fmt.Errorf("no project specified. Use --project or run from a linked directory")
		}
		project = inferred.Name
	}

	if err := client.RequireDaemon(); err != nil {
		return fmt.Errorf("daemon not running. Start with: envctl daemon start")
	}

	c, err := client.Connect()
	if err != nil {
		return fmt.Errorf("connect to daemon: %w", err)
	}
	defer c.Close()

	req := map[string]interface{}{
		"project": project,
		"url":     url,
		"disable": disable,
	}

	result, err := c.Call("relay.set", req)
	if err != nil {
		return fmt.Errorf("set relay: %w", err)
	}

	var resp struct {
		Success bool   `json:"success"`
		Pending bool   `json:"pending"`
		Project string `json:"project"`
		Action  string `json:"action"`
		URL     string `json:"url"`
		Message string `json:"message"`
	}

	if err := json.Unmarshal(result, &resp); err != nil {
		return fmt.Errorf("parse response: %w", err)
	}

	if resp.Success {
		if resp.Action == "disabled" {
			fmt.Printf("Relay disabled for project %s\n", resp.Project)
		} else {
			fmt.Printf("Relay enabled for project %s\n", resp.Project)
			fmt.Printf("  URL: %s\n", resp.URL)
		}
	} else if resp.Pending {
		fmt.Println(resp.Message)
	}

	return nil
}
