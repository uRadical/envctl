package cli

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"

	"github.com/spf13/cobra"
	"envctl.dev/go/envctl/internal/chain"
	"envctl.dev/go/envctl/internal/client"
	"envctl.dev/go/envctl/internal/config"
	"envctl.dev/go/envctl/internal/crypto"
	"envctl.dev/go/envctl/internal/opschain"
	"envctl.dev/go/envctl/internal/tui"
)

func init() {
	rootCmd.AddCommand(envCmd)

	envCmd.AddCommand(envListCmd)
	envCmd.AddCommand(envUseCmd)
	envCmd.AddCommand(envApplyCmd)
	envCmd.AddCommand(envShellCmd)
	envCmd.AddCommand(envCurrentCmd)
	envCmd.AddCommand(envEditCmd)
	envCmd.AddCommand(envClearCmd)
	envCmd.AddCommand(envCreateCmd)
	envCmd.AddCommand(envDeleteCmd)
	// envVarCmd is added in var.go's init()

	envCurrentCmd.Flags().Bool("prompt", false, "output for shell prompt")
	envEditCmd.Flags().StringP("env", "e", "", "target environment (default: current environment)")
	envApplyCmd.Flags().StringP("env", "e", "", "target environment (default: current environment)")
	envShellCmd.Flags().StringP("env", "e", "", "target environment (default: current environment)")
	envDeleteCmd.Flags().Bool("force", false, "force remove and revoke access from members")
}

var envCmd = &cobra.Command{
	Use:   "env",
	Short: "Environment file management",
	Long: `Manage .env files in your project.

Supports multiple environment variants (.env.dev, .env.prod, etc.)
and switching between them via symlinks.`,
}

var envListCmd = &cobra.Command{
	Use:   "list",
	Short: "List environments in the project",
	Long: `List all environments available in the current project.

Shows environments defined in the project chain (e.g., dev, staging, prod)
along with how many team members have access to each.

The current environment (from .envctl/config) is marked with *.`,
	RunE: runEnvList,
}

func runEnvList(cmd *cobra.Command, args []string) error {
	teamName, err := resolveTeamName(nil)
	if err != nil {
		return err
	}

	paths, err := config.GetPaths()
	if err != nil {
		return fmt.Errorf("get paths: %w", err)
	}

	chainPath := paths.ChainFile(teamName)
	teamChain, err := chain.Load(chainPath)
	if err != nil {
		return fmt.Errorf("load project: %w", err)
	}

	policy := teamChain.Policy()

	// Get current environment from .envctl/config
	cwd, _ := os.Getwd()
	currentEnv := ""
	if projectConfig, err := config.LoadProjectConfig(cwd); err == nil {
		currentEnv = projectConfig.Env
	}

	fmt.Printf("Environments for '%s':\n\n", teamName)

	for _, envName := range policy.Environments {
		members := teamChain.MembersWithEnvAccess(envName)

		marker := "  "
		if envName == currentEnv {
			marker = "* "
		}

		defaultMarker := ""
		for _, d := range policy.DefaultAccess {
			if d == envName {
				defaultMarker = " [default]"
				break
			}
		}
		fmt.Printf("%s%-12s (%d members)%s\n", marker, envName, len(members), defaultMarker)
	}

	return nil
}

var envUseCmd = &cobra.Command{
	Use:   "use <name>",
	Short: "Switch to a different environment",
	Long: `Sync and export environment variables to .env file.

This command:
1. Syncs the latest variables from peers (if daemon is running)
2. Exports all variables for the environment to .env
3. Updates .envctl to track the current environment

Examples:
  envctl env use dev      # Export dev variables to .env
  envctl env use prod     # Export prod variables to .env`,
	Args: cobra.ExactArgs(1),
	RunE: runEnvUse,
}

func runEnvUse(cmd *cobra.Command, args []string) error {
	envName := args[0]

	cwd, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("get working directory: %w", err)
	}

	// Load project config to get project name
	projectConfig, err := config.LoadProjectConfig(cwd)
	if err != nil {
		return fmt.Errorf("load project config: %w\nRun 'envctl project init' first", err)
	}

	project := projectConfig.Project
	if project == "" {
		return fmt.Errorf("no project configured in .envctl")
	}

	// Get paths
	paths, err := config.GetPaths()
	if err != nil {
		return fmt.Errorf("get paths: %w", err)
	}

	// Try to sync from peers first (if daemon is running)
	c, err := client.Connect()
	if err == nil {
		defer c.Close()

		fmt.Printf("Syncing %s/%s from peers...\n", project, envName)

		var syncResult struct {
			Success     bool   `json:"success"`
			OpsReceived int    `json:"ops_received"`
			Status      string `json:"status"`
			Error       string `json:"error"`
		}

		err := c.CallResult("opschain.pull", map[string]interface{}{
			"project":     project,
			"environment": envName,
		}, &syncResult)

		if err != nil {
			fmt.Printf("  Warning: sync failed: %v\n", err)
		} else if syncResult.OpsReceived > 0 {
			fmt.Printf("  Received %d new operations\n", syncResult.OpsReceived)
		} else {
			fmt.Printf("  Up to date\n")
		}
	}

	// Load identity to decrypt variables
	passphrase, err := tui.ReadPassword("Passphrase: ")
	if err != nil {
		return fmt.Errorf("read passphrase: %w", err)
	}

	identity, err := crypto.LoadEncrypted(paths.IdentityFile, passphrase)
	crypto.ZeroBytes(passphrase)
	if err != nil {
		return fmt.Errorf("load identity: %w", err)
	}

	// Load variables from ops chain
	manager := opschain.NewManager(paths.ChainsDir, paths.TempDir, identity)

	vars, err := manager.List(project, envName)
	if err != nil {
		return fmt.Errorf("list variables: %w", err)
	}

	if len(vars) == 0 {
		fmt.Printf("No variables found for %s/%s\n", project, envName)
		return nil
	}

	// Write to .env file
	targetPath := filepath.Join(cwd, ".env")

	// Backup existing .env if it's a regular file (not symlink)
	if info, err := os.Lstat(targetPath); err == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			// Remove existing symlink
			if err := os.Remove(targetPath); err != nil {
				return fmt.Errorf("remove existing symlink: %w", err)
			}
		} else if info.Mode().IsRegular() {
			// Backup existing file
			backupPath := filepath.Join(cwd, ".env.backup")
			if err := os.Rename(targetPath, backupPath); err != nil {
				return fmt.Errorf("backup existing .env: %w", err)
			}
			fmt.Printf("Backed up existing .env to .env.backup\n")
		}
	}

	// Write variables to .env
	f, err := os.OpenFile(targetPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("create .env file: %w", err)
	}
	defer f.Close()

	// Write header
	fmt.Fprintf(f, "# Environment: %s (from %s)\n", envName, project)
	fmt.Fprintf(f, "# Generated by envctl - do not edit manually\n\n")

	// Sort keys for consistent output
	keys := make([]string, 0, len(vars))
	for k := range vars {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	// Write variables
	for _, key := range keys {
		value := vars[key]
		// Quote values that contain special characters
		if strings.ContainsAny(value, " \t\n\"'\\$") {
			value = fmt.Sprintf("\"%s\"", strings.ReplaceAll(value, "\"", "\\\""))
		}
		fmt.Fprintf(f, "%s=%s\n", key, value)
	}

	fmt.Printf("Exported %d variables to .env\n", len(vars))

	// Update .envctl
	projectConfig.Env = envName
	if err := config.SaveProjectConfig(cwd, projectConfig); err != nil {
		fmt.Printf("Warning: could not update .envctl: %v\n", err)
	}

	return nil
}

var envApplyCmd = &cobra.Command{
	Use:   "apply [flags] -- <command> [args...]",
	Short: "Run a command with environment variables applied",
	Long: `Run a command with environment variables from the ops chain applied.

Unlike 'env use', this command does NOT write a .env file to disk.
Instead, it decrypts the variables and passes them directly to the
subprocess environment. This is more secure as secrets never touch
the filesystem.

The variables are only accessible to the spawned process and its
children. They are not visible to other processes on the system.

Use '--' to separate envctl flags from the command to run.

Examples:
  envctl env apply -- npm start
  envctl env apply -e prod -- ./deploy.sh
  envctl env apply -- python manage.py runserver
  envctl env apply -- sh -c 'echo $MY_SECRET'`,
	Args: cobra.MinimumNArgs(1),
	RunE: runEnvApply,
}

func runEnvApply(cmd *cobra.Command, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("no command specified")
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

	// Load variables from ops chain
	manager := opschain.NewManager(paths.ChainsDir, paths.TempDir, identity)

	vars, err := manager.List(project, environment)
	if err != nil {
		return fmt.Errorf("list variables: %w", err)
	}

	// Build environment for subprocess
	// Start with current environment and add/override with our vars
	env := os.Environ()
	for key, value := range vars {
		env = append(env, fmt.Sprintf("%s=%s", key, value))
	}

	// Execute the command
	execCmd := exec.Command(args[0], args[1:]...)
	execCmd.Env = env
	execCmd.Stdin = os.Stdin
	execCmd.Stdout = os.Stdout
	execCmd.Stderr = os.Stderr

	// Run and return exit code
	if err := execCmd.Run(); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			os.Exit(exitErr.ExitCode())
		}
		return fmt.Errorf("execute command: %w", err)
	}

	return nil
}

var envShellCmd = &cobra.Command{
	Use:   "shell",
	Short: "Start a shell with environment variables applied",
	Long: `Start an interactive shell with environment variables from the ops chain applied.

Unlike 'env use', this command does NOT write a .env file to disk.
Instead, it decrypts the variables and starts a new shell with them
set in the environment. This is more secure as secrets never touch
the filesystem.

The shell used matches your current shell ($SHELL on Unix, or
PowerShell/cmd on Windows). Type 'exit' to leave the shell and
clear the secrets from memory.

Examples:
  envctl env shell           # Start shell with current env's secrets
  envctl env shell -e prod   # Start shell with prod secrets`,
	RunE: runEnvShell,
}

func runEnvShell(cmd *cobra.Command, args []string) error {
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

	// Load variables from ops chain
	manager := opschain.NewManager(paths.ChainsDir, paths.TempDir, identity)

	vars, err := manager.List(project, environment)
	if err != nil {
		return fmt.Errorf("list variables: %w", err)
	}

	// Detect user's shell
	shell := getUserShell()

	// Build environment for subprocess
	env := os.Environ()
	for key, value := range vars {
		env = append(env, fmt.Sprintf("%s=%s", key, value))
	}

	// Add marker so user knows they're in an envctl shell
	env = append(env, fmt.Sprintf("ENVCTL_ENV=%s", environment))

	fmt.Printf("Starting %s with %d secrets from %s/%s\n", filepath.Base(shell), len(vars), project, environment)
	fmt.Printf("Type 'exit' to leave and clear secrets from memory.\n\n")

	// Execute the shell
	execCmd := exec.Command(shell)
	execCmd.Env = env
	execCmd.Stdin = os.Stdin
	execCmd.Stdout = os.Stdout
	execCmd.Stderr = os.Stderr

	// Run and return exit code
	if err := execCmd.Run(); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			os.Exit(exitErr.ExitCode())
		}
		return fmt.Errorf("execute shell: %w", err)
	}

	fmt.Println("\nExited envctl shell. Secrets cleared from memory.")
	return nil
}

// getUserShell returns the user's preferred shell
func getUserShell() string {
	if runtime.GOOS == "windows" {
		// Try PowerShell first (modern Windows)
		if pwsh, err := exec.LookPath("pwsh"); err == nil {
			return pwsh
		}
		if ps, err := exec.LookPath("powershell"); err == nil {
			return ps
		}
		// Fall back to cmd.exe
		if comspec := os.Getenv("COMSPEC"); comspec != "" {
			return comspec
		}
		return "cmd.exe"
	}

	// Unix: use $SHELL
	if shell := os.Getenv("SHELL"); shell != "" {
		return shell
	}

	// Fallback
	return "/bin/sh"
}

var envCurrentCmd = &cobra.Command{
	Use:   "current",
	Short: "Show current environment",
	RunE:  runEnvCurrent,
}

func runEnvCurrent(cmd *cobra.Command, args []string) error {
	promptMode, _ := cmd.Flags().GetBool("prompt")

	cwd, err := os.Getwd()
	if err != nil {
		if promptMode {
			return nil // Silent fail for prompt
		}
		return fmt.Errorf("get working directory: %w", err)
	}

	// Check .envctl file
	projectConfig, err := config.LoadProjectConfig(cwd)
	if err != nil && promptMode {
		return nil // Silent if no .envctl
	}

	envName := "unknown"
	if projectConfig != nil && projectConfig.Env != "" {
		envName = projectConfig.Env
	} else {
		// Try to detect from symlink
		envPath := filepath.Join(cwd, ".env")
		if info, err := os.Lstat(envPath); err == nil {
			if info.Mode()&os.ModeSymlink != 0 {
				target, err := os.Readlink(envPath)
				if err == nil && strings.HasPrefix(target, ".env.") {
					envName = strings.TrimPrefix(target, ".env.")
				}
			}
		}
	}

	if promptMode {
		// Output for shell prompt
		color := ""
		switch envName {
		case "prod", "production":
			color = "\033[31m" // Red
		case "stage", "staging":
			color = "\033[33m" // Yellow
		default:
			color = "\033[32m" // Green
		}
		fmt.Printf("%senv:%s\033[0m", color, envName)
	} else {
		fmt.Printf("Current environment: %s\n", envName)
	}

	return nil
}

var envClearCmd = &cobra.Command{
	Use:   "clear",
	Short: "Remove the .env file",
	Long: `Remove the .env file from the project directory.

This is the opposite of 'env use'. Use this to remove plaintext secrets
from disk when you're done working.

The variables remain in the ops chain and can be restored with 'env use'.

Examples:
  envctl env clear`,
	RunE: runEnvClear,
}

func runEnvClear(cmd *cobra.Command, args []string) error {
	cwd, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("get working directory: %w", err)
	}

	// Find project config
	projectConfig, err := config.LoadProjectConfig(cwd)
	if err != nil {
		return fmt.Errorf("not in an envctl project: %w", err)
	}

	// Remove .env file
	dotEnvPath := filepath.Join(cwd, ".env")
	if _, err := os.Stat(dotEnvPath); os.IsNotExist(err) {
		fmt.Println("No .env file to remove.")
		return nil
	}

	if err := os.Remove(dotEnvPath); err != nil {
		return fmt.Errorf("remove .env: %w", err)
	}

	fmt.Println("Removed .env")
	if projectConfig.Env != "" {
		fmt.Printf("Environment '%s' cleared from disk\n", projectConfig.Env)
	}

	return nil
}

var envEditCmd = &cobra.Command{
	Use:   "edit",
	Short: "Edit environment variables in your editor",
	Long: `Open environment variables in your $EDITOR for bulk editing.

This command:
1. Exports current variables to a temporary file in .env format
2. Opens the file in your $EDITOR (or vim/nano if not set)
3. Detects changes when you save and close
4. Creates operations for any additions, changes, or deletions

Examples:
  envctl env edit           # Edit current environment
  envctl env edit -e prod   # Edit prod environment`,
	RunE: runEnvEdit,
}

func runEnvEdit(cmd *cobra.Command, args []string) error {
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

	// Create manager and get current variables
	manager := opschain.NewManager(paths.ChainsDir, paths.TempDir, identity)

	currentVars, err := manager.List(project, environment)
	if err != nil {
		return fmt.Errorf("list variables: %w", err)
	}

	// Create temp file with current variables
	tmpFile, err := os.CreateTemp("", "envctl-edit-*.env")
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}
	tmpPath := tmpFile.Name()
	defer os.Remove(tmpPath)

	// Write header and current variables
	fmt.Fprintf(tmpFile, "# Environment: %s/%s\n", project, environment)
	fmt.Fprintf(tmpFile, "# Edit variables below. Lines starting with # are ignored.\n")
	fmt.Fprintf(tmpFile, "# Delete a line to remove that variable.\n")
	fmt.Fprintf(tmpFile, "# Add new lines in KEY=value format to add variables.\n\n")

	// Sort keys for consistent output
	keys := make([]string, 0, len(currentVars))
	for k := range currentVars {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	for _, key := range keys {
		value := currentVars[key]
		// Quote values that contain special characters
		if strings.ContainsAny(value, " \t\n\"'\\$#") {
			value = fmt.Sprintf("\"%s\"", strings.ReplaceAll(value, "\"", "\\\""))
		}
		fmt.Fprintf(tmpFile, "%s=%s\n", key, value)
	}
	tmpFile.Close()

	// Find editor
	editor := os.Getenv("EDITOR")
	if editor == "" {
		editor = os.Getenv("VISUAL")
	}
	if editor == "" {
		// Try common editors
		for _, e := range []string{"vim", "vi", "nano"} {
			if _, err := exec.LookPath(e); err == nil {
				editor = e
				break
			}
		}
	}
	if editor == "" {
		return fmt.Errorf("no editor found. Set $EDITOR environment variable")
	}

	// Open editor
	editorCmd := exec.Command(editor, tmpPath)
	editorCmd.Stdin = os.Stdin
	editorCmd.Stdout = os.Stdout
	editorCmd.Stderr = os.Stderr

	if err := editorCmd.Run(); err != nil {
		return fmt.Errorf("editor failed: %w", err)
	}

	// Read modified file
	newVars, err := parseEnvFile(tmpPath)
	if err != nil {
		return fmt.Errorf("parse edited file: %w", err)
	}

	// Diff and apply changes
	var added, modified, deleted []string

	// Check for additions and modifications
	for key, newValue := range newVars {
		if !isValidEnvKey(key) {
			fmt.Printf("Warning: skipping invalid key: %s\n", key)
			continue
		}

		oldValue, exists := currentVars[key]
		if !exists {
			added = append(added, key)
			if err := manager.Set(project, environment, key, newValue); err != nil {
				return fmt.Errorf("set %s: %w", key, err)
			}
		} else if oldValue != newValue {
			modified = append(modified, key)
			if err := manager.Set(project, environment, key, newValue); err != nil {
				return fmt.Errorf("update %s: %w", key, err)
			}
		}
	}

	// Check for deletions
	for key := range currentVars {
		if _, exists := newVars[key]; !exists {
			deleted = append(deleted, key)
			if err := manager.Delete(project, environment, key); err != nil {
				return fmt.Errorf("delete %s: %w", key, err)
			}
		}
	}

	// Print summary
	if len(added) == 0 && len(modified) == 0 && len(deleted) == 0 {
		fmt.Println("No changes.")
		return nil
	}

	if len(added) > 0 {
		fmt.Printf("Added: %s\n", strings.Join(added, ", "))
	}
	if len(modified) > 0 {
		fmt.Printf("Modified: %s\n", strings.Join(modified, ", "))
	}
	if len(deleted) > 0 {
		fmt.Printf("Deleted: %s\n", strings.Join(deleted, ", "))
	}

	return nil
}

// parseEnvFile parses a .env file and returns a map of key-value pairs
func parseEnvFile(path string) (map[string]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	vars := make(map[string]string)
	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Parse KEY=value
		idx := strings.Index(line, "=")
		if idx == -1 {
			continue // Skip invalid lines
		}

		key := strings.TrimSpace(line[:idx])
		value := strings.TrimSpace(line[idx+1:])

		// Handle quoted values
		if len(value) >= 2 {
			if (value[0] == '"' && value[len(value)-1] == '"') ||
				(value[0] == '\'' && value[len(value)-1] == '\'') {
				value = value[1 : len(value)-1]
				// Unescape quotes
				value = strings.ReplaceAll(value, "\\\"", "\"")
				value = strings.ReplaceAll(value, "\\'", "'")
			}
		}

		vars[key] = value
	}

	return vars, scanner.Err()
}

// ensureGitignore ensures .envctl/ and .env are in .gitignore
func ensureGitignore(projectDir string) error {
	gitDir := projectDir + "/.git"
	if _, err := os.Stat(gitDir); os.IsNotExist(err) {
		// Not a git repo, skip silently
		return nil
	}

	gitignorePath := projectDir + "/.gitignore"

	entries := []string{
		".envctl/",
		".env",
		".env.*",
		"!.env.example",
	}

	// Read existing .gitignore
	existing := ""
	if data, err := os.ReadFile(gitignorePath); err == nil {
		existing = string(data)
	}

	// Check what's missing
	var toAdd []string
	for _, entry := range entries {
		found := false
		for _, line := range strings.Split(existing, "\n") {
			if strings.TrimSpace(line) == entry {
				found = true
				break
			}
		}
		if !found {
			toAdd = append(toAdd, entry)
		}
	}

	if len(toAdd) == 0 {
		return nil // Already configured
	}

	// Append to .gitignore
	f, err := os.OpenFile(gitignorePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer f.Close()

	// Ensure we start on a new line
	if len(existing) > 0 && !strings.HasSuffix(existing, "\n") {
		f.WriteString("\n")
	}

	// Add header comment and entries
	f.WriteString("\n# envctl - secrets management\n")
	for _, entry := range toAdd {
		f.WriteString(entry + "\n")
	}

	return nil
}

var envCreateCmd = &cobra.Command{
	Use:   "create <environment>",
	Short: "Create a new environment in the project",
	Long: `Create a new environment for storing secrets.

Environments are isolated sets of variables (e.g., dev, staging, prod).
Team members can be granted access to specific environments.

Examples:
  envctl env create staging
  envctl env create production`,
	Args: cobra.ExactArgs(1),
	RunE: runEnvCreate,
}

func runEnvCreate(cmd *cobra.Command, args []string) error {
	envName := strings.TrimSpace(args[0])

	if !isValidEnvName(envName) {
		return fmt.Errorf("invalid environment name: must be lowercase alphanumeric with hyphens, 1-32 chars")
	}

	teamName, err := resolveTeamName(nil)
	if err != nil {
		return err
	}

	paths, err := config.GetPaths()
	if err != nil {
		return fmt.Errorf("get paths: %w", err)
	}

	chainPath := paths.ChainFile(teamName)
	teamChain, err := chain.Load(chainPath)
	if err != nil {
		return fmt.Errorf("load project: %w", err)
	}

	policy := teamChain.Policy()

	// Check if environment already exists
	if policy.IsValidEnvironment(envName) {
		return fmt.Errorf("environment '%s' already exists", envName)
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

	// Check permission
	if err := teamChain.CanPropose(chain.ActionAddEnv, identity.SigningPublicKey()); err != nil {
		return fmt.Errorf("cannot create environment: %w", err)
	}

	// Create add env subject
	subject := chain.EnvChange{
		Environment: envName,
	}

	head := teamChain.Head()
	block, err := chain.NewBlock(head, chain.ActionAddEnv, subject, identity)
	if err != nil {
		return fmt.Errorf("create block: %w", err)
	}

	status := teamChain.GetApprovalStatus(block)
	if status.Required > 0 {
		fmt.Printf("Proposal created. Requires %d approval(s).\n", status.Required)
	} else {
		if err := teamChain.AppendBlock(block); err != nil {
			return fmt.Errorf("append block: %w", err)
		}
		if err := teamChain.Save(chainPath); err != nil {
			return fmt.Errorf("save chain: %w", err)
		}
		client.NotifyChainChange()
		fmt.Printf("Created environment '%s'\n", envName)
	}

	return nil
}

var envDeleteCmd = &cobra.Command{
	Use:   "delete <environment>",
	Short: "Delete an environment from the project",
	Long: `Delete an environment and all its variables.

This removes the environment definition from the project. Any secrets
stored in this environment will no longer be accessible.

Use --force to also revoke access from members who have access to this environment.

Examples:
  envctl env delete staging
  envctl env delete old-env --force`,
	Args: cobra.ExactArgs(1),
	RunE: runEnvDelete,
}

func runEnvDelete(cmd *cobra.Command, args []string) error {
	envName := strings.TrimSpace(args[0])
	force, _ := cmd.Flags().GetBool("force")

	teamName, err := resolveTeamName(nil)
	if err != nil {
		return err
	}

	paths, err := config.GetPaths()
	if err != nil {
		return fmt.Errorf("get paths: %w", err)
	}

	chainPath := paths.ChainFile(teamName)
	teamChain, err := chain.Load(chainPath)
	if err != nil {
		return fmt.Errorf("load project: %w", err)
	}

	policy := teamChain.Policy()

	// Check if environment exists
	if !policy.IsValidEnvironment(envName) {
		return fmt.Errorf("environment '%s' does not exist", envName)
	}

	// Can't remove the last environment
	if len(policy.Environments) == 1 {
		return fmt.Errorf("cannot delete the last environment")
	}

	// Check if any members have access
	membersWithAccess := teamChain.MembersWithEnvAccess(envName)
	if len(membersWithAccess) > 0 && !force {
		names := make([]string, len(membersWithAccess))
		for i, m := range membersWithAccess {
			names[i] = m.Name
		}
		return fmt.Errorf("%d members have access to '%s': %s. Use --force to revoke and delete",
			len(membersWithAccess), envName, strings.Join(names, ", "))
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

	// Check permission
	if err := teamChain.CanPropose(chain.ActionRemoveEnv, identity.SigningPublicKey()); err != nil {
		return fmt.Errorf("cannot delete environment: %w", err)
	}

	// Create remove env subject
	subject := chain.EnvChange{
		Environment: envName,
	}

	head := teamChain.Head()
	block, err := chain.NewBlock(head, chain.ActionRemoveEnv, subject, identity)
	if err != nil {
		return fmt.Errorf("create block: %w", err)
	}

	status := teamChain.GetApprovalStatus(block)
	if status.Required > 0 {
		fmt.Printf("Proposal created. Requires %d approval(s).\n", status.Required)
	} else {
		if err := teamChain.AppendBlock(block); err != nil {
			return fmt.Errorf("append block: %w", err)
		}
		if err := teamChain.Save(chainPath); err != nil {
			return fmt.Errorf("save chain: %w", err)
		}
		client.NotifyChainChange()
		fmt.Printf("Deleted environment '%s'\n", envName)
	}

	return nil
}
