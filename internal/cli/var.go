package cli

import (
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"uradical.io/go/envctl/internal/client"
	"uradical.io/go/envctl/internal/config"
	"uradical.io/go/envctl/internal/crypto"
	"uradical.io/go/envctl/internal/opschain"
	"uradical.io/go/envctl/internal/tui"
)

func init() {
	// Add var as subcommand of env
	envCmd.AddCommand(envVarCmd)

	envVarCmd.AddCommand(envVarSetCmd)
	envVarCmd.AddCommand(envVarGetCmd)
	envVarCmd.AddCommand(envVarDeleteCmd)
	envVarCmd.AddCommand(envVarListCmd)
	envVarCmd.AddCommand(envVarStatusCmd)
	envVarCmd.AddCommand(envVarLogCmd)
	envVarCmd.AddCommand(envVarPullCmd)
	envVarCmd.AddCommand(envVarPushCmd)

	// Add --env flag to all subcommands
	for _, cmd := range []*cobra.Command{
		envVarSetCmd, envVarGetCmd, envVarDeleteCmd, envVarListCmd,
		envVarStatusCmd, envVarLogCmd, envVarPullCmd, envVarPushCmd,
	} {
		cmd.Flags().StringP("env", "e", "", "target environment (default: current environment)")
	}

	envVarLogCmd.Flags().IntP("limit", "n", 10, "number of operations to show")
}

var envVarCmd = &cobra.Command{
	Use:   "var",
	Short: "Manage environment variables via operations chain",
	Long: `Manage environment variables using an append-only operations chain.

Variables are stored as signed operations, similar to git commits.
Each operation is hash-linked and cryptographically signed.

Unlike the traditional .env file approach, the operations chain:
- Provides a complete audit trail of all changes
- Enables conflict detection when syncing with peers
- Ensures integrity through cryptographic signatures
- Stores values encrypted to your own key

Examples:
  envctl env var set API_KEY "secret123"           # Set a variable in current env
  envctl env var set -e prod API_KEY "prodkey"    # Set in prod environment
  envctl env var get API_KEY                       # Get a variable
  envctl env var delete API_KEY                    # Delete a variable
  envctl env var list                              # List all variables
  envctl env var status                            # Show chain status
  envctl env var log                               # Show recent operations`,
}

// getEnvironment returns the target environment from flag or project config
func getEnvironment(cmd *cobra.Command) (string, error) {
	// Check if --env flag was provided
	envFlag, _ := cmd.Flags().GetString("env")
	if envFlag != "" {
		return envFlag, nil
	}

	// Get from project config
	cwd, err := os.Getwd()
	if err != nil {
		return "", fmt.Errorf("get working directory: %w", err)
	}

	projectConfig, err := config.LoadProjectConfig(cwd)
	if err != nil {
		return "", fmt.Errorf("not in an envctl project: %w", err)
	}

	if projectConfig.Env != "" {
		return projectConfig.Env, nil
	}

	return "dev", nil
}

// getProjectAndEnv returns both project name and environment
func getProjectAndEnv(cmd *cobra.Command) (string, string, error) {
	cwd, err := os.Getwd()
	if err != nil {
		return "", "", fmt.Errorf("get working directory: %w", err)
	}

	projectConfig, err := config.LoadProjectConfig(cwd)
	if err != nil {
		return "", "", fmt.Errorf("not in an envctl project: %w", err)
	}

	environment, err := getEnvironment(cmd)
	if err != nil {
		return "", "", err
	}

	return projectConfig.Project, environment, nil
}

var envVarSetCmd = &cobra.Command{
	Use:   "set <key> <value>",
	Short: "Set a variable",
	Long: `Set a variable in the operations chain.

The value is encrypted to your own key and signed with your identity.
The operation is appended to the chain and can be synced with peers.

Examples:
  envctl env var set API_KEY "secret123"
  envctl env var set -e prod DATABASE_URL "postgres://..."
  envctl env var set DEBUG true`,
	Args: cobra.ExactArgs(2),
	RunE: runEnvVarSet,
}

func runEnvVarSet(cmd *cobra.Command, args []string) error {
	key := args[0]
	value := args[1]

	// Validate key name
	if !isValidEnvKey(key) {
		return fmt.Errorf("invalid key name: %s (must be uppercase letters, numbers, and underscores)", key)
	}

	project, environment, err := getProjectAndEnv(cmd)
	if err != nil {
		return err
	}

	// Load identity
	paths, err := config.GetPaths()
	if err != nil {
		return fmt.Errorf("get paths: %w", err)
	}

	if !paths.IdentityExists() {
		return fmt.Errorf("no identity found. Run 'envctl init' first")
	}

	passphrase, err := tui.ReadPassword("Passphrase: ")
	if err != nil {
		return fmt.Errorf("read passphrase: %w", err)
	}

	identity, err := crypto.LoadEncrypted(paths.IdentityFile, passphrase)
	crypto.ZeroBytes(passphrase)
	if err != nil {
		return fmt.Errorf("load identity: %w", err)
	}

	// Create manager and set variable
	manager := opschain.NewManager(paths.ChainsDir, paths.TempDir, identity)

	if err := manager.Set(project, environment, key, value); err != nil {
		return fmt.Errorf("set variable: %w", err)
	}

	fmt.Printf("Set %s in %s/%s\n", key, project, environment)
	return nil
}

var envVarGetCmd = &cobra.Command{
	Use:   "get <key>",
	Short: "Get a variable's value",
	Long: `Get a variable's value from the operations chain.

The value is decrypted from the chain and printed.

Examples:
  envctl env var get API_KEY
  envctl env var get -e prod DATABASE_URL`,
	Args: cobra.ExactArgs(1),
	RunE: runEnvVarGet,
}

func runEnvVarGet(cmd *cobra.Command, args []string) error {
	key := args[0]

	project, environment, err := getProjectAndEnv(cmd)
	if err != nil {
		return err
	}

	// Load identity
	paths, err := config.GetPaths()
	if err != nil {
		return fmt.Errorf("get paths: %w", err)
	}

	if !paths.IdentityExists() {
		return fmt.Errorf("no identity found. Run 'envctl init' first")
	}

	passphrase, err := tui.ReadPassword("Passphrase: ")
	if err != nil {
		return fmt.Errorf("read passphrase: %w", err)
	}

	identity, err := crypto.LoadEncrypted(paths.IdentityFile, passphrase)
	crypto.ZeroBytes(passphrase)
	if err != nil {
		return fmt.Errorf("load identity: %w", err)
	}

	// Create manager and get variable
	manager := opschain.NewManager(paths.ChainsDir, paths.TempDir, identity)

	value, exists, err := manager.Get(project, environment, key)
	if err != nil {
		return fmt.Errorf("get variable: %w", err)
	}

	if !exists {
		return fmt.Errorf("variable not found: %s", key)
	}

	fmt.Println(value)
	return nil
}

var envVarDeleteCmd = &cobra.Command{
	Use:   "delete <key>",
	Short: "Delete a variable",
	Long: `Delete a variable from the operations chain.

A delete operation is appended to the chain.
The variable's history is preserved in the chain.

Examples:
  envctl env var delete API_KEY
  envctl env var delete -e prod OLD_CONFIG`,
	Args:    cobra.ExactArgs(1),
	Aliases: []string{"rm", "remove"},
	RunE:    runEnvVarDelete,
}

func runEnvVarDelete(cmd *cobra.Command, args []string) error {
	key := args[0]

	project, environment, err := getProjectAndEnv(cmd)
	if err != nil {
		return err
	}

	// Load identity
	paths, err := config.GetPaths()
	if err != nil {
		return fmt.Errorf("get paths: %w", err)
	}

	if !paths.IdentityExists() {
		return fmt.Errorf("no identity found. Run 'envctl init' first")
	}

	passphrase, err := tui.ReadPassword("Passphrase: ")
	if err != nil {
		return fmt.Errorf("read passphrase: %w", err)
	}

	identity, err := crypto.LoadEncrypted(paths.IdentityFile, passphrase)
	crypto.ZeroBytes(passphrase)
	if err != nil {
		return fmt.Errorf("load identity: %w", err)
	}

	// Check if variable exists first
	manager := opschain.NewManager(paths.ChainsDir, paths.TempDir, identity)

	_, exists, err := manager.Get(project, environment, key)
	if err != nil {
		return fmt.Errorf("check variable: %w", err)
	}

	if !exists {
		return fmt.Errorf("variable not found: %s", key)
	}

	if err := manager.Delete(project, environment, key); err != nil {
		return fmt.Errorf("delete variable: %w", err)
	}

	fmt.Printf("Deleted %s from %s/%s\n", key, project, environment)
	return nil
}

var envVarListCmd = &cobra.Command{
	Use:     "list",
	Short:   "List all variables",
	Aliases: []string{"ls"},
	Long: `List all variables in the current or specified environment.

Examples:
  envctl env var list
  envctl env var list -e prod`,
	RunE: runEnvVarList,
}

func runEnvVarList(cmd *cobra.Command, args []string) error {
	project, environment, err := getProjectAndEnv(cmd)
	if err != nil {
		return err
	}

	// Load identity
	paths, err := config.GetPaths()
	if err != nil {
		return fmt.Errorf("get paths: %w", err)
	}

	if !paths.IdentityExists() {
		return fmt.Errorf("no identity found. Run 'envctl init' first")
	}

	passphrase, err := tui.ReadPassword("Passphrase: ")
	if err != nil {
		return fmt.Errorf("read passphrase: %w", err)
	}

	identity, err := crypto.LoadEncrypted(paths.IdentityFile, passphrase)
	crypto.ZeroBytes(passphrase)
	if err != nil {
		return fmt.Errorf("load identity: %w", err)
	}

	// Create manager and list variables
	manager := opschain.NewManager(paths.ChainsDir, paths.TempDir, identity)

	vars, err := manager.List(project, environment)
	if err != nil {
		return fmt.Errorf("list variables: %w", err)
	}

	if len(vars) == 0 {
		fmt.Printf("No variables in %s/%s\n", project, environment)
		return nil
	}

	fmt.Printf("Variables in %s/%s:\n\n", project, environment)

	// Sort keys
	keys := make([]string, 0, len(vars))
	for k := range vars {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	for _, k := range keys {
		v := vars[k]
		// Mask value if it looks sensitive
		display := maskIfSensitive(k, v)
		fmt.Printf("  %s=%s\n", k, display)
	}

	fmt.Printf("\nTotal: %d variables\n", len(vars))
	return nil
}

var envVarStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show chain status",
	Long: `Show the status of the operations chain for the environment.

Examples:
  envctl env var status
  envctl env var status -e prod`,
	RunE: runEnvVarStatus,
}

func runEnvVarStatus(cmd *cobra.Command, args []string) error {
	project, environment, err := getProjectAndEnv(cmd)
	if err != nil {
		return err
	}

	// Load identity
	paths, err := config.GetPaths()
	if err != nil {
		return fmt.Errorf("get paths: %w", err)
	}

	if !paths.IdentityExists() {
		return fmt.Errorf("no identity found. Run 'envctl init' first")
	}

	passphrase, err := tui.ReadPassword("Passphrase: ")
	if err != nil {
		return fmt.Errorf("read passphrase: %w", err)
	}

	identity, err := crypto.LoadEncrypted(paths.IdentityFile, passphrase)
	crypto.ZeroBytes(passphrase)
	if err != nil {
		return fmt.Errorf("load identity: %w", err)
	}

	// Create manager and get status
	manager := opschain.NewManager(paths.ChainsDir, paths.TempDir, identity)

	status, err := manager.Status(project, environment)
	if err != nil {
		return fmt.Errorf("get status: %w", err)
	}

	fmt.Printf("Project:     %s\n", status.Project)
	fmt.Printf("Environment: %s\n", status.Environment)
	fmt.Printf("Operations:  %d\n", status.OpCount)
	fmt.Printf("Variables:   %d\n", status.VarCount)

	if status.OpCount > 0 {
		fmt.Printf("Head seq:    %d\n", status.HeadSeq)
		fmt.Printf("Head hash:   %x\n", status.HeadHash[:8])
		if t, ok := status.LastModified.(time.Time); ok {
			fmt.Printf("Last change: %s\n", t.Format(time.RFC3339))
		}
	}

	return nil
}

var envVarLogCmd = &cobra.Command{
	Use:   "log",
	Short: "Show operation log",
	Long: `Show the operation log for the environment.

Examples:
  envctl env var log
  envctl env var log -e prod
  envctl env var log -n 20`,
	RunE: runEnvVarLog,
}

func runEnvVarLog(cmd *cobra.Command, args []string) error {
	limit, _ := cmd.Flags().GetInt("limit")

	project, environment, err := getProjectAndEnv(cmd)
	if err != nil {
		return err
	}

	// Load identity
	paths, err := config.GetPaths()
	if err != nil {
		return fmt.Errorf("get paths: %w", err)
	}

	if !paths.IdentityExists() {
		return fmt.Errorf("no identity found. Run 'envctl init' first")
	}

	passphrase, err := tui.ReadPassword("Passphrase: ")
	if err != nil {
		return fmt.Errorf("read passphrase: %w", err)
	}

	identity, err := crypto.LoadEncrypted(paths.IdentityFile, passphrase)
	crypto.ZeroBytes(passphrase)
	if err != nil {
		return fmt.Errorf("load identity: %w", err)
	}

	// Create manager and get log
	manager := opschain.NewManager(paths.ChainsDir, paths.TempDir, identity)

	ops, err := manager.Log(project, environment, limit)
	if err != nil {
		return fmt.Errorf("get log: %w", err)
	}

	if len(ops) == 0 {
		fmt.Println("No operations yet.")
		return nil
	}

	// Print in reverse order (newest first)
	for i := len(ops) - 1; i >= 0; i-- {
		op := ops[i]
		opType := string(op.Op)
		if op.Op == opschain.OpSet {
			opType = "set"
		} else {
			opType = "del"
		}

		hash := op.Hash()
		shortHash := fmt.Sprintf("%x", hash[:4])

		fmt.Printf("%s %s %s\n", shortHash, opType, op.Key)
		fmt.Printf("    Author: %s\n", op.AuthorFingerprint())
		fmt.Printf("    Date:   %s\n", op.Timestamp.Format(time.RFC3339))
		fmt.Println()
	}

	return nil
}

// isValidEnvKey checks if a key name is valid for environment variables
func isValidEnvKey(key string) bool {
	if len(key) == 0 {
		return false
	}

	for i, c := range key {
		if i == 0 && c >= '0' && c <= '9' {
			return false // Can't start with a number
		}
		if !((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_') {
			return false
		}
	}

	return true
}

// maskIfSensitive masks values that look like secrets
func maskIfSensitive(key, value string) string {
	lowerKey := strings.ToLower(key)
	sensitive := strings.Contains(lowerKey, "secret") ||
		strings.Contains(lowerKey, "password") ||
		strings.Contains(lowerKey, "token") ||
		strings.Contains(lowerKey, "key") ||
		strings.Contains(lowerKey, "apikey") ||
		strings.Contains(lowerKey, "api_key")

	if sensitive {
		if len(value) > 4 {
			return value[:2] + "..." + value[len(value)-2:]
		}
		return "****"
	}

	if len(value) > 50 {
		return value[:47] + "..."
	}

	return value
}

var envVarPullCmd = &cobra.Command{
	Use:   "pull",
	Short: "Pull operations from peers",
	Long: `Pull operations from connected team members.

Requests the latest operations from peers who are members of this project.
Any new operations will be merged into your local chain.

The daemon must be running to communicate with peers.

Examples:
  envctl env var pull
  envctl env var pull -e prod`,
	RunE: runEnvVarPull,
}

func runEnvVarPull(cmd *cobra.Command, args []string) error {
	project, environment, err := getProjectAndEnv(cmd)
	if err != nil {
		return err
	}

	// Connect to daemon
	c, err := client.Connect()
	if err != nil {
		return fmt.Errorf("connect to daemon: %w\nStart daemon with: envctl daemon start", err)
	}
	defer c.Close()

	// Send pull request
	params := map[string]string{
		"project":     project,
		"environment": environment,
	}

	var result struct {
		Success   bool   `json:"success"`
		RequestID string `json:"request_id"`
		Message   string `json:"message"`
		Error     string `json:"error"`
	}

	if err := c.CallResult("opschain.pull", params, &result); err != nil {
		return fmt.Errorf("pull ops: %w", err)
	}

	if !result.Success {
		if result.Error != "" {
			return fmt.Errorf("%s", result.Error)
		}
		return fmt.Errorf("pull failed")
	}

	fmt.Println(result.Message)
	return nil
}

var envVarPushCmd = &cobra.Command{
	Use:   "push",
	Short: "Push operations to peers",
	Long: `Push operations to connected team members.

Sends your local operations to all connected peers who are members of this project.
Peers will merge the operations into their local chains.

The daemon must be running to communicate with peers.

Examples:
  envctl env var push
  envctl env var push -e prod`,
	RunE: runEnvVarPush,
}

func runEnvVarPush(cmd *cobra.Command, args []string) error {
	project, environment, err := getProjectAndEnv(cmd)
	if err != nil {
		return err
	}

	// Load identity to export operations
	paths, err := config.GetPaths()
	if err != nil {
		return fmt.Errorf("get paths: %w", err)
	}

	if !paths.IdentityExists() {
		return fmt.Errorf("no identity found. Run 'envctl init' first")
	}

	passphrase, err := tui.ReadPassword("Passphrase: ")
	if err != nil {
		return fmt.Errorf("read passphrase: %w", err)
	}

	identity, err := crypto.LoadEncrypted(paths.IdentityFile, passphrase)
	crypto.ZeroBytes(passphrase)
	if err != nil {
		return fmt.Errorf("load identity: %w", err)
	}

	// Get operations to push
	manager := opschain.NewManager(paths.ChainsDir, paths.TempDir, identity)

	exported, err := manager.ExportRange(project, environment, 0)
	if err != nil {
		return fmt.Errorf("export operations: %w", err)
	}

	if len(exported) == 0 {
		fmt.Println("No operations to push.")
		return nil
	}

	// Convert to wire format
	wireOps := make([]map[string]interface{}, len(exported))
	for i, exp := range exported {
		wireOps[i] = map[string]interface{}{
			"seq":             exp.Op.Seq,
			"timestamp":       exp.Op.Timestamp.UnixNano(),
			"author":          exp.Op.Author,
			"op":              string(exp.Op.Op),
			"key":             exp.Op.Key,
			"encrypted_value": exp.Op.EncryptedValue, // Original encrypted value (for signature verification)
			"value":           exp.PlaintextValue,    // Plaintext (for recipient to cache)
			"prev_hash":       exp.Op.PrevHash,
			"signature":       exp.Op.Signature,
		}
	}

	// Connect to daemon
	c, err := client.Connect()
	if err != nil {
		return fmt.Errorf("connect to daemon: %w\nStart daemon with: envctl daemon start", err)
	}
	defer c.Close()

	// Send push request
	params := map[string]interface{}{
		"project":     project,
		"environment": environment,
		"operations":  wireOps,
	}

	var result struct {
		Success   bool   `json:"success"`
		RequestID string `json:"request_id"`
		SentTo    int    `json:"sent_to"`
		TotalOps  int    `json:"total_ops"`
		Error     string `json:"error"`
	}

	if err := c.CallResult("opschain.push", params, &result); err != nil {
		return fmt.Errorf("push ops: %w", err)
	}

	if !result.Success {
		if result.Error != "" {
			return fmt.Errorf("%s", result.Error)
		}
		return fmt.Errorf("push failed")
	}

	fmt.Printf("Pushed %d operations to %d peer(s)\n", result.TotalOps, result.SentTo)
	return nil
}
