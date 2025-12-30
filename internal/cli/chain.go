package cli

import (
	"fmt"

	"github.com/spf13/cobra"
	"uradical.io/go/envctl/internal/client"
)

func init() {
	rootCmd.AddCommand(chainCmd)
	chainCmd.AddCommand(chainVerifyCmd)
	chainCmd.AddCommand(chainRepairCmd)
}

var chainCmd = &cobra.Command{
	Use:   "chain",
	Short: "Chain management commands",
	Long: `Commands for managing the project membership blockchain.

The chain stores cryptographically verified project membership,
role assignments, and environment access permissions.`,
}

var chainVerifyCmd = &cobra.Command{
	Use:   "verify [project]",
	Short: "Verify chain integrity",
	Long: `Verify the integrity of a project's membership chain.

Checks that all blocks are properly signed, linked, and
that approval requirements are met.`,
	Args: cobra.MaximumNArgs(1),
	RunE: runChainVerify,
}

func runChainVerify(cmd *cobra.Command, args []string) error {
	c, err := client.Connect()
	if err != nil {
		return fmt.Errorf("connect to daemon: %w", err)
	}
	defer c.Close()

	var params map[string]string
	if len(args) > 0 {
		params = map[string]string{"project": args[0]}
	}

	var result struct {
		Team       string `json:"team"`
		Valid      bool   `json:"valid"`
		BlockCount int    `json:"block_count"`
		Error      string `json:"error,omitempty"`
	}

	if err := c.CallResult("chain.verify", params, &result); err != nil {
		return fmt.Errorf("verify chain: %w", err)
	}

	if result.Valid {
		fmt.Printf("Chain valid (%d blocks)\n", result.BlockCount)
	} else {
		fmt.Printf("Chain invalid: %s\n", result.Error)
		return fmt.Errorf("chain verification failed")
	}

	return nil
}

var chainRepairCmd = &cobra.Command{
	Use:   "repair [project]",
	Short: "Repair chain from peers",
	Long: `Attempt to repair a corrupted chain by re-syncing from peers.

This will attempt to:
1. Restore from local backup if available
2. Sync missing blocks from connected peers
3. Verify the repaired chain`,
	Args: cobra.MaximumNArgs(1),
	RunE: runChainRepair,
}

func runChainRepair(cmd *cobra.Command, args []string) error {
	c, err := client.Connect()
	if err != nil {
		return fmt.Errorf("connect to daemon: %w", err)
	}
	defer c.Close()

	var params map[string]string
	if len(args) > 0 {
		params = map[string]string{"project": args[0]}
	}

	var result struct {
		Team         string `json:"team"`
		Repaired     bool   `json:"repaired"`
		BlocksAdded  int    `json:"blocks_added"`
		Source       string `json:"source"` // "backup" or "peer"
		Error        string `json:"error,omitempty"`
	}

	fmt.Println("Attempting chain repair...")

	if err := c.CallResult("chain.repair", params, &result); err != nil {
		return fmt.Errorf("repair chain: %w", err)
	}

	if result.Repaired {
		fmt.Printf("Chain repaired from %s (%d blocks added)\n", result.Source, result.BlocksAdded)
	} else if result.Error != "" {
		fmt.Printf("Repair failed: %s\n", result.Error)
		return fmt.Errorf("chain repair failed")
	} else {
		fmt.Println("Chain is already valid, no repair needed.")
	}

	return nil
}
