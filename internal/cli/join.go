package cli

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"uradical.io/go/envctl/internal/chain"
	"uradical.io/go/envctl/internal/client"
	"uradical.io/go/envctl/internal/config"
	"uradical.io/go/envctl/internal/crypto"
	"uradical.io/go/envctl/internal/tui"
)

var (
	joinCodeFlag string
)

func init() {
	projectCmd.AddCommand(joinCmd)

	joinCmd.Flags().StringVar(&joinCodeFlag, "code", "", "invite code (e.g., ABC-DEF-GHI)")
	joinCmd.MarkFlagRequired("code")
}

var joinCmd = &cobra.Command{
	Use:   "join",
	Short: "Join an existing project using an invite code",
	Long: `Join an existing project that you've been invited to.

You need an invite code from a project admin. The admin creates the invite
using your public key (from 'envctl whoami --verbose').

This command will:
1. Connect to a peer who has the project chain
2. Download and verify the chain
3. Verify your invite code is valid
4. Create a member-add block (signed by you)
5. Broadcast the block to peers for inclusion

The project directory (.envctl/) will be created in the current directory.

Examples:
  envctl project join --code ABC-DEF-GHI`,
	RunE: runJoin,
}

func runJoin(cmd *cobra.Command, args []string) error {
	code := chain.NormalizeInviteCode(joinCodeFlag)

	if !chain.ValidateInviteCodeFormat(code) {
		return fmt.Errorf("invalid invite code format: expected XXX-XXX-XXX")
	}

	paths, err := config.GetPaths()
	if err != nil {
		return fmt.Errorf("get paths: %w", err)
	}

	// Check identity exists
	if !paths.IdentityExists() {
		return fmt.Errorf("no identity found. Run 'envctl init' first")
	}

	// Check we're not already in a project
	cwd, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("get working directory: %w", err)
	}

	_, err = config.LoadProjectConfig(cwd)
	if err == nil {
		return fmt.Errorf("this directory is already linked to a project. Use 'envctl project sync' instead")
	}

	// Load identity
	passphrase, err := tui.ReadPassword("Passphrase: ")
	if err != nil {
		return fmt.Errorf("read passphrase: %w", err)
	}

	identity, err := crypto.LoadEncrypted(paths.IdentityFile, passphrase)
	crypto.ZeroBytes(passphrase)
	if err != nil {
		return fmt.Errorf("load identity: %w", err)
	}

	fmt.Println("Connecting to daemon...")

	// Connect to daemon
	c, err := client.Connect()
	if err != nil {
		return fmt.Errorf("connect to daemon: %w\nEnsure daemon is running: envctl daemon start", err)
	}
	defer c.Close()

	// Request to join project via daemon
	// The daemon will:
	// 1. Broadcast a chain request to peers
	// 2. Find a peer with a chain containing our invite code
	// 3. Download the chain
	// 4. Validate the invite
	// 5. Create and sign the member-add block
	// 6. Broadcast to peers

	var result struct {
		Success     bool   `json:"success"`
		ProjectName string `json:"project_name"`
		ChainPath   string `json:"chain_path"`
		Error       string `json:"error"`
	}

	params := map[string]interface{}{
		"code":        code,
		"signing_pub": identity.SigningPublicKey(),
		"mlkem_pub":   identity.MLKEMPublicKey(),
		"name":        identity.Name,
	}

	fmt.Println("Searching for project with invite code...")

	if err := c.CallResult("project.join", params, &result); err != nil {
		return fmt.Errorf("join project: %w", err)
	}

	if !result.Success {
		return fmt.Errorf("join failed: %s", result.Error)
	}

	// Load the chain to get details
	teamChain, err := chain.Load(result.ChainPath)
	if err != nil {
		return fmt.Errorf("load chain: %w", err)
	}

	policy := teamChain.Policy()
	member := teamChain.Member(identity.SigningPublicKey())
	if member == nil {
		return fmt.Errorf("failed to find self in chain after join")
	}

	// Create .envctl directory in current directory
	defaultEnv := "dev"
	if len(member.Environments) > 0 {
		defaultEnv = member.Environments[0]
	}

	projectConfig := &config.ProjectConfig{
		Project:         result.ProjectName,
		Env:             defaultEnv,
		Locked:          true,
		AutoLockMinutes: 480,
	}

	if err := projectConfig.Save(cwd); err != nil {
		fmt.Printf("Warning: could not create .envctl/config: %v\n", err)
	}

	// Ensure .gitignore
	if err := ensureGitignore(cwd); err != nil {
		fmt.Printf("Warning: could not update .gitignore: %v\n", err)
	}

	fmt.Printf("\nJoined project '%s' successfully!\n\n", result.ProjectName)
	fmt.Printf("  Role: %s\n", member.Role)
	fmt.Printf("  Environments: %s\n", join(member.Environments, ", "))
	fmt.Printf("  Team size: %d members\n", len(teamChain.Members()))
	fmt.Println()

	// Show environments
	if len(policy.Environments) > 0 {
		fmt.Println("Available environments:")
		for _, env := range policy.Environments {
			access := ""
			for _, e := range member.Environments {
				if e == env {
					access = " (access granted)"
					break
				}
			}
			fmt.Printf("  - %s%s\n", env, access)
		}
		fmt.Println()
	}

	fmt.Printf("Created .envctl/config\n\n")
	fmt.Printf("Use 'envctl use %s' to unlock secrets.\n", defaultEnv)

	return nil
}

// join is a simple string join helper (to avoid name collision with joinCmd)
func join(strs []string, sep string) string {
	if len(strs) == 0 {
		return "(none)"
	}
	result := strs[0]
	for i := 1; i < len(strs); i++ {
		result += sep + strs[i]
	}
	return result
}

var syncCmd = &cobra.Command{
	Use:   "sync",
	Short: "Sync the project chain and secrets with peers",
	Long: `Synchronize the project chain and secrets with connected peers.

This command will:
1. Request the latest chain blocks from peers
2. Optionally request secrets for environments you have access to

Use this when:
- You've been offline and want to catch up
- You suspect your chain might be out of sync
- You want to ensure you have the latest secrets

Examples:
  envctl project sync
  envctl project sync --secrets`,
	RunE: runSync,
}

var (
	syncSecretsFlag bool
)

func init() {
	projectCmd.AddCommand(syncCmd)

	syncCmd.Flags().BoolVar(&syncSecretsFlag, "secrets", false, "also request secrets from peers")
}

func runSync(cmd *cobra.Command, args []string) error {
	teamName, err := resolveTeamName(nil)
	if err != nil {
		return err
	}

	paths, err := config.GetPaths()
	if err != nil {
		return fmt.Errorf("get paths: %w", err)
	}

	// Check chain exists locally
	chainPath := paths.ChainFile(teamName)
	if !chain.Exists(chainPath) {
		return fmt.Errorf("project '%s' not found locally\nUse 'envctl project join --code <code>' to join a new project", teamName)
	}

	// Load chain
	teamChain, err := chain.Load(chainPath)
	if err != nil {
		return fmt.Errorf("load project: %w", err)
	}

	// Connect to daemon
	c, err := client.Connect()
	if err != nil {
		return fmt.Errorf("connect to daemon: %w\nEnsure daemon is running: envctl daemon start", err)
	}
	defer c.Close()

	fmt.Printf("Syncing project '%s'...\n", teamName)
	fmt.Printf("  Local chain: %d blocks\n", teamChain.Len())

	// Request chain sync from daemon
	var result struct {
		Status      string `json:"status"`
		BlocksBefore int   `json:"blocks_before"`
		BlocksAfter  int   `json:"blocks_after"`
		BlocksAdded  int   `json:"blocks_added"`
	}

	syncParams := map[string]interface{}{
		"team": teamName,
	}

	if err := c.CallResult("chain.sync", syncParams, &result); err != nil {
		// Fallback - just report current state
		fmt.Println("  No peers available for sync")
		return nil
	}

	if result.BlocksAdded > 0 {
		fmt.Printf("  Received %d new block(s)\n", result.BlocksAdded)
		fmt.Printf("  Chain now at %d blocks\n", result.BlocksAfter)
	} else {
		fmt.Println("  Already up to date")
	}

	// Always sync ops chains for all accessible environments (deep sync)
	// Check identity exists
	if !paths.IdentityExists() {
		return fmt.Errorf("no identity found. Run 'envctl init' first")
	}

	// Load public identity to check access
	pub, err := crypto.LoadPublic(paths.IdentityPubFile)
	if err != nil {
		return fmt.Errorf("load public identity: %w", err)
	}

	// Reload chain in case it was updated
	teamChain, err = chain.Load(chainPath)
	if err != nil {
		return fmt.Errorf("reload chain: %w", err)
	}

	member := teamChain.Member(pub.SigningPub)
	if member == nil {
		return fmt.Errorf("you are not a member of this project")
	}

	// Sync ops chains for each environment we have access to
	if len(member.Environments) > 0 {
		fmt.Println()
		fmt.Println("Syncing environment variables...")

		for _, env := range member.Environments {
			var pullResult struct {
				Status       string `json:"status"`
				OpsReceived  int    `json:"ops_received"`
				Message      string `json:"message"`
			}

			pullParams := map[string]interface{}{
				"project":     teamName,
				"environment": env,
			}

			if err := c.CallResult("opschain.pull", pullParams, &pullResult); err != nil {
				fmt.Printf("  %s: failed (%v)\n", env, err)
				continue
			}

			if pullResult.OpsReceived > 0 {
				fmt.Printf("  %s: received %d operation(s)\n", env, pullResult.OpsReceived)
			} else if pullResult.Status == "pending" {
				fmt.Printf("  %s: pull requested (syncing in background)\n", env)
			} else {
				fmt.Printf("  %s: up to date\n", env)
			}
		}
	}

	// Optionally also broadcast secret requests (legacy mechanism)
	if syncSecretsFlag {
		fmt.Println()
		fmt.Println("Requesting secrets from peers...")

		// Request each environment we have access to
		for _, env := range member.Environments {
			var reqResult struct {
				RequestID    string `json:"request_id"`
				PeersNotified int   `json:"peers_notified"`
			}

			reqParams := map[string]interface{}{
				"team": teamName,
				"env":  env,
			}

			if err := c.CallResult("request.broadcast", reqParams, &reqResult); err != nil {
				fmt.Printf("  %s: failed to request (%v)\n", env, err)
				continue
			}

			if reqResult.PeersNotified > 0 {
				fmt.Printf("  %s: requested from %d peer(s)\n", env, reqResult.PeersNotified)
			} else {
				fmt.Printf("  %s: no peers available\n", env)
			}
		}
	}

	fmt.Println()
	fmt.Println("Sync complete.")

	return nil
}
