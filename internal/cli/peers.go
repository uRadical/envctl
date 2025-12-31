package cli

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/spf13/cobra"
	"envctl.dev/go/envctl/internal/client"
)

func init() {
	rootCmd.AddCommand(peersCmd)

	peersCmd.AddCommand(peersListCmd)
	peersCmd.AddCommand(peersAddCmd)
	peersCmd.AddCommand(peersForgetCmd)
	peersCmd.AddCommand(peersSavedCmd)
}

var peersCmd = &cobra.Command{
	Use:   "peers",
	Short: "Peer management commands",
	Long: `Manage peer connections.

Peers are discovered automatically via mDNS on the local network.
You can also add peers manually using their address.`,
}

var peersListCmd = &cobra.Command{
	Use:   "list",
	Short: "List connected peers",
	RunE:  runPeersList,
}

func runPeersList(cmd *cobra.Command, args []string) error {
	if err := client.RequireDaemon(); err != nil {
		return fmt.Errorf("daemon not running. Start with: envctl daemon start")
	}

	c, err := client.Connect()
	if err != nil {
		return fmt.Errorf("connect to daemon: %w", err)
	}
	defer c.Close()

	result, err := c.Call("peers.list", nil)
	if err != nil {
		return fmt.Errorf("list peers: %w", err)
	}

	var peers []struct {
		Name      string   `json:"name"`
		Addr      string   `json:"addr"`
		Connected bool     `json:"connected"`
		LastSeen  string   `json:"last_seen"`
		Teams     []string `json:"teams"`
	}

	if err := json.Unmarshal(result, &peers); err != nil {
		return fmt.Errorf("parse response: %w", err)
	}

	if len(peers) == 0 {
		fmt.Println("No peers connected.")
		fmt.Println()
		fmt.Println("Peers are discovered automatically via mDNS on the local network.")
		fmt.Println("To add a peer manually: envctl peers add <host:port>")
		return nil
	}

	fmt.Printf("Connected Peers (%d)\n\n", len(peers))

	for _, p := range peers {
		status := "connected"
		if !p.Connected {
			status = "disconnected"
		}

		teamsStr := "(no shared teams)"
		if len(p.Teams) > 0 {
			teamsStr = strings.Join(p.Teams, ", ")
		}

		name := p.Name
		if name == "" {
			name = p.Addr
		}

		fmt.Printf("  %s [%s]\n", name, status)
		fmt.Printf("    Address: %s\n", p.Addr)
		fmt.Printf("    Teams: %s\n", teamsStr)
		fmt.Println()
	}

	return nil
}

var peersAddCmd = &cobra.Command{
	Use:   "add <address>",
	Short: "Add a peer manually",
	Long: `Add a peer by address.

Use this when mDNS discovery isn't available (e.g., across subnets
or when connecting via VPN/Tailscale).

Example:
  envctl peers add 192.168.1.50:7834
  envctl peers add alice-laptop.local:7834`,
	Args: cobra.ExactArgs(1),
	RunE: runPeersAdd,
}

func runPeersAdd(cmd *cobra.Command, args []string) error {
	addr := args[0]

	if err := client.RequireDaemon(); err != nil {
		return fmt.Errorf("daemon not running. Start with: envctl daemon start")
	}

	c, err := client.Connect()
	if err != nil {
		return fmt.Errorf("connect to daemon: %w", err)
	}
	defer c.Close()

	_, err = c.Call("peers.add", addr)
	if err != nil {
		return fmt.Errorf("add peer: %w", err)
	}

	fmt.Printf("Connecting to peer at %s...\n", addr)
	fmt.Println("Use 'envctl peers list' to see connection status.")

	return nil
}

var peersForgetCmd = &cobra.Command{
	Use:   "forget <name>",
	Short: "Forget a saved peer",
	Long: `Remove a peer from the saved peers list.

Saved peers are automatically reconnected when the daemon restarts.
Use this command to stop auto-reconnecting to a specific peer.

Example:
  envctl peers forget bob
  envctl peers forget alice`,
	Args: cobra.ExactArgs(1),
	RunE: runPeersForget,
}

func runPeersForget(cmd *cobra.Command, args []string) error {
	name := args[0]

	if err := client.RequireDaemon(); err != nil {
		return fmt.Errorf("daemon not running. Start with: envctl daemon start")
	}

	c, err := client.Connect()
	if err != nil {
		return fmt.Errorf("connect to daemon: %w", err)
	}
	defer c.Close()

	params := map[string]string{"name": name}
	_, err = c.Call("peers.forget", params)
	if err != nil {
		return fmt.Errorf("forget peer: %w", err)
	}

	fmt.Printf("Forgot peer '%s'. It will no longer auto-reconnect on restart.\n", name)

	return nil
}

var peersSavedCmd = &cobra.Command{
	Use:   "saved",
	Short: "List saved peers",
	Long: `List peers that are saved for auto-reconnection.

These peers will be automatically reconnected when the daemon restarts.
Use 'envctl peers forget <name>' to remove a peer from auto-reconnect.`,
	RunE: runPeersSaved,
}

func runPeersSaved(cmd *cobra.Command, args []string) error {
	if err := client.RequireDaemon(); err != nil {
		return fmt.Errorf("daemon not running. Start with: envctl daemon start")
	}

	c, err := client.Connect()
	if err != nil {
		return fmt.Errorf("connect to daemon: %w", err)
	}
	defer c.Close()

	result, err := c.Call("peers.saved", nil)
	if err != nil {
		return fmt.Errorf("list saved peers: %w", err)
	}

	var peers []struct {
		Name        string `json:"name"`
		Fingerprint string `json:"fingerprint"`
		Addr        string `json:"addr"`
		AddedAt     string `json:"added_at"`
		LastSeen    string `json:"last_seen"`
	}

	if err := json.Unmarshal(result, &peers); err != nil {
		return fmt.Errorf("parse response: %w", err)
	}

	if len(peers) == 0 {
		fmt.Println("No saved peers.")
		fmt.Println()
		fmt.Println("Peers are saved automatically when they connect successfully.")
		fmt.Println("Saved peers will be auto-reconnected when the daemon restarts.")
		return nil
	}

	fmt.Printf("Saved Peers (%d)\n\n", len(peers))

	for _, p := range peers {
		fmt.Printf("  %s\n", p.Name)
		fmt.Printf("    Address: %s\n", p.Addr)
		fmt.Printf("    Fingerprint: %s\n", p.Fingerprint[:min(16, len(p.Fingerprint))])
		fmt.Println()
	}

	fmt.Println("These peers will auto-reconnect on daemon restart.")
	fmt.Println("Use 'envctl peers forget <name>' to remove a peer.")

	return nil
}
