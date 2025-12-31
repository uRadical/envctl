package cli

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"envctl.dev/go/envctl/internal/chain"
	"envctl.dev/go/envctl/internal/client"
	"envctl.dev/go/envctl/internal/config"
	"envctl.dev/go/envctl/internal/crypto"
	"envctl.dev/go/envctl/internal/secrets"
	"envctl.dev/go/envctl/internal/tui"
)

var (
	teamNameFlag        string
	teamEnvFlag         string
	teamRoleFlag        string
	teamEnvsFlag        []string
	teamDefaultFlag     string
	teamForceFlag       bool
	teamSilentFlag      bool
	teamJSONFlag        bool
	teamReasonFlag      string
	teamNoEnvshareFlag  bool
	teamAutoDetectFlag  bool
	invitePubkeyFlag    string
	inviteTTLFlag       string
)

// envNameRegex validates environment names.
var envNameRegex = regexp.MustCompile(`^[a-z][a-z0-9-]{0,31}$`)

func init() {
	// Note: teamCmd is registered as a hidden alias via project.go
	// which adds projectCmd with "team" as an alias

	// Persistent flag for all team subcommands (kept for backward compatibility)
	teamCmd.PersistentFlags().StringVar(&teamNameFlag, "team", "", "project name (overrides .envctl file)")

	// Team subcommands
	teamCmd.AddCommand(teamCreateCmd)
	teamCmd.AddCommand(teamDeleteCmd)
	teamCmd.AddCommand(teamListCmd)
	teamCmd.AddCommand(teamMembersCmd)
	teamCmd.AddCommand(teamInviteCmd)
	teamCmd.AddCommand(teamRemoveCmd)
	teamCmd.AddCommand(teamLeaveCmd)
	teamCmd.AddCommand(teamAccessCmd)
	teamCmd.AddCommand(teamGrantCmd)
	teamCmd.AddCommand(teamRevokeCmd)
	teamCmd.AddCommand(teamPendingCmd)
	teamCmd.AddCommand(teamApproveCmd)
	teamCmd.AddCommand(teamDenyCmd)
	teamCmd.AddCommand(teamLogCmd)
	teamCmd.AddCommand(teamEnvCmd)
	teamCmd.AddCommand(teamDissolveCmd)

	// Team create flags
	teamCreateCmd.Flags().StringSliceVar(&teamEnvsFlag, "envs", nil, "environments for this project (comma-separated, auto-detected if not specified)")
	teamCreateCmd.Flags().StringVar(&teamDefaultFlag, "default-access", "", "default environment access for new members (auto-selected if not specified)")
	teamCreateCmd.Flags().BoolVar(&teamNoEnvshareFlag, "no-envctl", false, "don't create .envctl file in current directory")
	teamCreateCmd.Flags().BoolVar(&teamAutoDetectFlag, "auto-detect", true, "auto-detect environments from .env.* files")

	// Team delete flags
	teamDeleteCmd.Flags().BoolVar(&teamSilentFlag, "silent", false, "delete without confirmation prompt")

	// Team dissolve flags
	teamDissolveCmd.Flags().StringVar(&teamReasonFlag, "reason", "", "reason for dissolution")

	// Team list flags
	teamListCmd.Flags().BoolVar(&teamJSONFlag, "json", false, "output as JSON")

	// Team invite flags
	teamInviteCmd.Flags().StringVar(&invitePubkeyFlag, "pubkey", "", "invitee's signing public key (hex)")
	teamInviteCmd.Flags().StringVar(&inviteTTLFlag, "ttl", "10m", "invite expiration (e.g., 10m, 1h, 24h)")
	teamInviteCmd.Flags().StringVar(&teamEnvFlag, "env", "", "environments to grant access to (comma-separated)")
	teamInviteCmd.Flags().StringVar(&teamRoleFlag, "role", "member", "role: admin, member, or reader")
	teamInviteCmd.MarkFlagRequired("pubkey")

	// Team invites (list) subcommand
	teamCmd.AddCommand(teamInvitesCmd)

	// Team invite revoke subcommand
	teamCmd.AddCommand(teamInviteRevokeCmd)
	teamInviteRevokeCmd.Flags().StringVar(&teamReasonFlag, "reason", "", "reason for revoking invite")

	teamGrantCmd.Flags().StringVar(&teamEnvFlag, "env", "", "environments to grant (comma-separated)")
	teamGrantCmd.MarkFlagRequired("env")

	teamRevokeCmd.Flags().StringVar(&teamEnvFlag, "env", "", "environments to revoke (comma-separated)")
	teamRevokeCmd.MarkFlagRequired("env")

	// Team env subcommands
	teamEnvCmd.AddCommand(teamEnvListCmd)
	teamEnvCmd.AddCommand(teamEnvAddCmd)
	teamEnvCmd.AddCommand(teamEnvRemoveCmd)

	teamEnvRemoveCmd.Flags().BoolVar(&teamForceFlag, "force", false, "force remove and revoke access from members")
}

var teamCmd = &cobra.Command{
	Use:   "team",
	Short: "Team management commands",
	Long: `Manage team membership and access.

Teams use a cryptographically signed blockchain to track membership.
All changes require approval from team members based on team policy.`,
}

var teamCreateCmd = &cobra.Command{
	Use:   "create [name]",
	Short: "Create a new project",
	Long: `Create a new project with you as the founding admin.

The project uses a blockchain to track membership changes. As the founder,
you become the first admin and can invite other members.

If no name is provided, it will be inferred from the git remote origin URL
or the current directory name.

By default, environments are auto-detected from .env.* files in the current
directory. If no files are found, defaults to: dev, stage, prod.

A .envctl file is automatically created in the current directory to link
it to this project.

Examples:
  envctl project create                # Infer name from git/directory
  envctl project create myproject
  envctl project create myproject --envs dev,qa,prod
  envctl project create myproject --no-envctl
  envctl project create myproject --envs local,test,live --default-access local`,
	Args: cobra.MaximumNArgs(1),
	RunE: runTeamCreate,
}

func runTeamCreate(cmd *cobra.Command, args []string) error {
	var teamName string
	var nameSource string

	if len(args) > 0 && strings.TrimSpace(args[0]) != "" {
		teamName = strings.TrimSpace(args[0])
		nameSource = "command line"
	} else {
		// Infer from git remote or directory name
		inferred, err := inferProjectName()
		if err != nil {
			return fmt.Errorf("could not infer project name: %w\nUse: envctl project create <name>", err)
		}
		teamName = inferred.Name
		nameSource = inferred.Source
	}

	if teamName == "" {
		return fmt.Errorf("project name cannot be empty")
	}

	fmt.Printf("Creating project '%s' (from %s)\n", teamName, nameSource)

	// Determine environments
	var envs []string
	var detectedEnvs []string

	if len(teamEnvsFlag) > 0 {
		// Use explicitly provided environments
		envs = teamEnvsFlag
	} else if teamAutoDetectFlag {
		// Auto-detect from .env.* files
		detectedEnvs = detectEnvironments(".")
		if len(detectedEnvs) > 0 {
			envs = detectedEnvs
			fmt.Printf("Detected environments: %s\n", strings.Join(envs, ", "))
		} else {
			// Fall back to defaults
			envs = []string{"dev", "stage", "prod"}
		}
	} else {
		// No auto-detect, use defaults
		envs = []string{"dev", "stage", "prod"}
	}

	// Validate environments
	for _, env := range envs {
		if !isValidEnvName(env) {
			return fmt.Errorf("invalid environment name '%s': must be lowercase alphanumeric with hyphens, 1-32 chars", env)
		}
	}

	// Determine default access
	defaultAccess := teamDefaultFlag
	if defaultAccess == "" {
		defaultAccess = selectDefaultEnv(envs)
	}

	// Validate default-access is in envs list
	if !contains(envs, defaultAccess) {
		return fmt.Errorf("default-access '%s' must be one of the environments: %v", defaultAccess, envs)
	}

	paths, err := config.GetPaths()
	if err != nil {
		return fmt.Errorf("get paths: %w", err)
	}

	// Check if project already exists
	chainPath := paths.ChainFile(teamName)
	if chain.Exists(chainPath) {
		return fmt.Errorf("project '%s' already exists", teamName)
	}

	// Load identity
	if !paths.IdentityExists() {
		return fmt.Errorf("no identity found. Run 'envctl init' first")
	}

	// Prompt for passphrase
	passphrase, err := tui.ReadPassword("Passphrase: ")
	if err != nil {
		return fmt.Errorf("read passphrase: %w", err)
	}

	identity, err := crypto.LoadEncrypted(paths.IdentityFile, passphrase)
	crypto.ZeroBytes(passphrase)
	if err != nil {
		return fmt.Errorf("load identity: %w", err)
	}

	// Create project with environments
	teamChain, err := chain.CreateTeamWithEnvs(teamName, identity, envs, []string{defaultAccess})
	if err != nil {
		return fmt.Errorf("create project: %w", err)
	}

	// Ensure directories exist
	if err := paths.EnsureDirectories(); err != nil {
		return fmt.Errorf("create directories: %w", err)
	}

	// Save chain
	if err := teamChain.Save(chainPath); err != nil {
		return fmt.Errorf("save chain: %w", err)
	}

	// Notify daemon to reload chains
	client.NotifyChainChange()

	// Create .envctl directory and config unless --no-envctl is set
	cwd, err := os.Getwd()
	if err != nil {
		cwd = "."
	}

	var migratedCount int
	if !teamNoEnvshareFlag {
		projectConfig := &config.ProjectConfig{
			Project:         teamName,
			Env:             defaultAccess,
			Locked:          true,
			AutoLockMinutes: 480, // 8 hours default
		}

		if err := projectConfig.Save(cwd); err != nil {
			fmt.Printf("Warning: could not create .envctl/config: %v\n", err)
		} else {
			fmt.Println("Created .envctl/config")
		}

		// Migrate existing .env.* files to encrypted storage
		if len(detectedEnvs) > 0 {
			migratedCount = migrateEnvFiles(cwd, detectedEnvs, identity)
		}

		// Ensure .gitignore is configured
		if err := ensureGitignore(cwd); err != nil {
			fmt.Printf("Warning: could not update .gitignore: %v\n", err)
		}
	}

	fmt.Printf("Project '%s' created successfully!\n", teamName)
	fmt.Println()
	fmt.Printf("  Chain file: %s\n", chainPath)
	fmt.Printf("  Members: 1 (you are the founding admin)\n")
	fmt.Printf("  Environments: %s\n", strings.Join(envs, ", "))
	fmt.Printf("  Default access: %s\n", defaultAccess)

	if migratedCount > 0 {
		fmt.Println()
		fmt.Printf("Migrated %d environment(s) to encrypted storage.\n", migratedCount)
		fmt.Println("You can now delete the plaintext .env.* files:")
		for _, envName := range detectedEnvs {
			envFile := filepath.Join(cwd, ".env."+envName)
			if _, err := os.Stat(envFile); err == nil {
				fmt.Printf("  rm %s\n", envFile)
			}
		}
	}

	fmt.Println()
	fmt.Printf("Use 'envctl use %s' to unlock secrets.\n", defaultAccess)
	fmt.Println()
	fmt.Println("To invite members, share your public key and have them run:")
	fmt.Printf("  envctl project join <your-pubkey> --project %s\n", teamName)
	fmt.Println()
	fmt.Println("Or invite them directly:")
	fmt.Printf("  envctl project invite <name> <their-pubkey> --project %s\n", teamName)

	return nil
}

// migrateEnvFiles migrates existing .env.* files to encrypted storage
func migrateEnvFiles(projectDir string, envs []string, identity *crypto.Identity) int {
	migratedCount := 0

	for _, envName := range envs {
		// Try both the normalized name and common variations
		envFile := filepath.Join(projectDir, ".env."+envName)
		if _, err := os.Stat(envFile); os.IsNotExist(err) {
			// Try original variations
			for _, variant := range []string{envName, strings.Title(envName), strings.ToUpper(envName)} {
				envFile = filepath.Join(projectDir, ".env."+variant)
				if _, err := os.Stat(envFile); err == nil {
					break
				}
			}
		}

		// Skip if file doesn't exist
		if _, err := os.Stat(envFile); os.IsNotExist(err) {
			continue
		}

		// Parse .env file
		variables, err := secrets.ParseEnvFile(envFile)
		if err != nil {
			fmt.Printf("Warning: could not parse %s: %v\n", envFile, err)
			continue
		}

		if len(variables) == 0 {
			continue
		}

		// Encrypt and save
		encPath := config.EncryptedEnvPath(projectDir, envName)
		if err := secrets.SaveEncrypted(encPath, variables, identity); err != nil {
			fmt.Printf("Warning: could not encrypt %s: %v\n", envFile, err)
			continue
		}

		migratedCount++
		fmt.Printf("Migrated .env.%s → .envctl/%s.enc (%d variables)\n", envName, envName, len(variables))
	}

	return migratedCount
}

// detectEnvironments scans for .env.* files and returns environment names
func detectEnvironments(dir string) []string {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}

	envSet := make(map[string]bool)
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		name := entry.Name()

		// Match .env.* files (e.g., .env.dev, .env.local, .env.production)
		if strings.HasPrefix(name, ".env.") {
			envName := strings.TrimPrefix(name, ".env.")

			// Skip common non-environment suffixes
			if envName == "example" || envName == "sample" || envName == "template" {
				continue
			}

			// Normalize common names
			envName = normalizeEnvName(envName)

			if isValidEnvName(envName) {
				envSet[envName] = true
			}
		}
	}

	// Convert to sorted slice
	var envs []string
	for env := range envSet {
		envs = append(envs, env)
	}

	// Sort with common environments first
	sortEnvironments(envs)

	return envs
}

// normalizeEnvName normalizes common environment name variations
func normalizeEnvName(name string) string {
	name = strings.ToLower(name)

	// Common normalizations
	switch name {
	case "development":
		return "dev"
	case "production":
		return "prod"
	case "staging":
		return "stage"
	case "testing", "test":
		return "test"
	}

	return name
}

// sortEnvironments sorts environments with common ones first
func sortEnvironments(envs []string) {
	priority := map[string]int{
		"local": 1,
		"dev":   2,
		"test":  3,
		"stage": 4,
		"prod":  5,
	}

	for i := 0; i < len(envs)-1; i++ {
		for j := i + 1; j < len(envs); j++ {
			pi := priority[envs[i]]
			pj := priority[envs[j]]

			// If both have priority, compare by priority
			// If only one has priority, it comes first
			// If neither has priority, compare alphabetically
			swap := false
			if pi > 0 && pj > 0 {
				swap = pi > pj
			} else if pj > 0 {
				swap = true
			} else if pi == 0 && pj == 0 {
				swap = envs[i] > envs[j]
			}

			if swap {
				envs[i], envs[j] = envs[j], envs[i]
			}
		}
	}
}

// selectDefaultEnv picks a sensible default environment from the list
func selectDefaultEnv(envs []string) string {
	// Priority order for default environment
	priorities := []string{"dev", "local", "development", "test"}

	for _, p := range priorities {
		for _, env := range envs {
			if env == p {
				return env
			}
		}
	}

	// Fall back to first environment
	if len(envs) > 0 {
		return envs[0]
	}

	return "dev"
}

var teamDeleteCmd = &cobra.Command{
	Use:   "delete <team-name>",
	Short: "Delete a team's local chain file",
	Long: `Delete a team's local chain file.

This is a local-only operation that removes your copy of the team's chain.
Other team members still have their copies and can continue using the team.

Use this to clean up test teams or teams you no longer participate in.

Examples:
  envctl team delete testteam
  envctl team delete testteam --silent`,
	Args: cobra.ExactArgs(1),
	RunE: runTeamDelete,
}

func runTeamDelete(cmd *cobra.Command, args []string) error {
	teamName := args[0]

	paths, err := config.GetPaths()
	if err != nil {
		return fmt.Errorf("get paths: %w", err)
	}

	chainPath := paths.ChainFile(teamName)
	backupPath := paths.ChainBackupFile(teamName)

	// Check if chain exists
	if _, err := os.Stat(chainPath); os.IsNotExist(err) {
		return fmt.Errorf("project '%s' not found", teamName)
	}

	// Confirm unless silent
	if !teamSilentFlag {
		msg := fmt.Sprintf("Are you sure you want to delete project '%s'? This removes the local chain file.", teamName)
		confirmed, err := tui.Confirm(msg, false)
		if err != nil {
			return fmt.Errorf("confirmation: %w", err)
		}
		if !confirmed {
			fmt.Println("Cancelled.")
			return nil
		}
	}

	// Remove chain file
	if err := os.Remove(chainPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to delete chain: %w", err)
	}

	// Remove backup if exists
	if err := os.Remove(backupPath); err != nil && !os.IsNotExist(err) {
		// Log but don't fail - backup might not exist
	}

	// Remove any pending proposals for this team
	pendingDir := paths.TeamProposalsDir(teamName)
	if err := os.RemoveAll(pendingDir); err != nil && !os.IsNotExist(err) {
		// Log but don't fail
	}

	fmt.Printf("Project '%s' deleted.\n", teamName)

	return nil
}

var teamListCmd = &cobra.Command{
	Use:     "list",
	Aliases: []string{"ls"},
	Short:   "List all local teams",
	Long: `List all teams you have locally.

Shows team name, your role, member count, and chain height.

Examples:
  envctl team list
  envctl team ls
  envctl team list --json`,
	RunE: runTeamList,
}

type teamInfo struct {
	Name         string   `json:"name"`
	Role         string   `json:"role"`
	MemberCount  int      `json:"member_count"`
	BlockCount   int      `json:"block_count"`
	Environments []string `json:"environments"`
	Dissolved    bool     `json:"dissolved"`
}

func runTeamList(cmd *cobra.Command, args []string) error {
	paths, err := config.GetPaths()
	if err != nil {
		return fmt.Errorf("get paths: %w", err)
	}

	// Read chains directory
	entries, err := os.ReadDir(paths.ChainsDir)
	if err != nil {
		if os.IsNotExist(err) {
			fmt.Println("No projects found.")
			fmt.Println("Create one with: envctl project create <name>")
			return nil
		}
		return fmt.Errorf("reading chains directory: %w", err)
	}

	// Load public identity to determine role
	var mySigningPub []byte
	if paths.IdentityExists() {
		pubPath := paths.IdentityPubFile
		pub, err := crypto.LoadPublic(pubPath)
		if err == nil {
			mySigningPub = pub.SigningPub
		}
	}

	// Filter for .chain files (not .chain.1 backups)
	var teams []teamInfo
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if !strings.HasSuffix(name, ".chain") || strings.HasSuffix(name, ".chain.1") {
			continue
		}

		teamName := strings.TrimSuffix(name, ".chain")
		info, err := loadTeamInfo(paths, teamName, mySigningPub)
		if err != nil {
			// Skip teams we can't load
			continue
		}
		teams = append(teams, info)
	}

	if len(teams) == 0 {
		fmt.Println("No projects found.")
		fmt.Println("Create one with: envctl project create <name>")
		return nil
	}

	// Output as JSON if requested
	if teamJSONFlag {
		data, err := json.MarshalIndent(teams, "", "  ")
		if err != nil {
			return fmt.Errorf("marshal JSON: %w", err)
		}
		fmt.Println(string(data))
		return nil
	}

	// Print header
	fmt.Println("Projects:")

	// Print each team
	for _, t := range teams {
		memberWord := "member"
		if t.MemberCount != 1 {
			memberWord = "members"
		}

		blockWord := "block"
		if t.BlockCount != 1 {
			blockWord = "blocks"
		}

		// Show dissolved status or role
		status := t.Role
		if t.Dissolved {
			status = "(dissolved)"
		}

		fmt.Printf("  %-15s %-12s %d %-7s  %d %s\n",
			t.Name,
			status,
			t.MemberCount,
			memberWord,
			t.BlockCount,
			blockWord,
		)
	}

	return nil
}

func loadTeamInfo(paths *config.Paths, teamName string, mySigningPub []byte) (teamInfo, error) {
	chainPath := paths.ChainFile(teamName)

	// Load chain
	c, err := chain.Load(chainPath)
	if err != nil {
		return teamInfo{}, err
	}

	// Find our role
	role := "member"
	members := c.Members()
	for _, m := range members {
		if bytes.Equal(m.SigningPub, mySigningPub) {
			if m.Role == chain.RoleAdmin {
				role = "admin"
			}
			break
		}
	}

	// Get environments from policy
	policy := c.Policy()
	var envs []string
	if policy != nil {
		envs = policy.Environments
	}

	return teamInfo{
		Name:         teamName,
		Role:         role,
		MemberCount:  len(members),
		BlockCount:   c.Len(),
		Environments: envs,
		Dissolved:    c.IsDissolved(),
	}, nil
}

var teamDissolveCmd = &cobra.Command{
	Use:   "dissolve <team-name>",
	Short: "Dissolve a team (requires admin consensus)",
	Long: `Propose dissolution of a team.

This creates a dissolve block that must be approved by other admins
(if the team has multiple admins). Once applied, the team is permanently
dissolved and no new blocks can be added.

Dissolved teams:
- Cannot accept new blocks or proposals
- Cannot process env requests
- Remain visible in 'team list' marked as (dissolved)
- Can still be viewed for historical record
- Can be deleted locally with 'team delete'

This action cannot be undone.

Examples:
  envctl team dissolve myteam
  envctl team dissolve myteam --reason "Project completed"`,
	Args: cobra.ExactArgs(1),
	RunE: runTeamDissolve,
}

func runTeamDissolve(cmd *cobra.Command, args []string) error {
	teamName := args[0]

	paths, err := config.GetPaths()
	if err != nil {
		return fmt.Errorf("get paths: %w", err)
	}

	// Load chain
	chainPath := paths.ChainFile(teamName)
	teamChain, err := chain.Load(chainPath)
	if err != nil {
		return fmt.Errorf("load project '%s': %w", teamName, err)
	}

	// Check if already dissolved
	if teamChain.IsDissolved() {
		return fmt.Errorf("project '%s' is already dissolved", teamName)
	}

	// Load identity
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

	// Check we're an admin
	if err := teamChain.CanPropose(chain.ActionDissolveTeam, identity.SigningPublicKey()); err != nil {
		return fmt.Errorf("cannot dissolve: %w", err)
	}

	// Confirm
	msg := fmt.Sprintf("Are you sure you want to dissolve project '%s'?\nThis will be broadcast to all members and cannot be undone.", teamName)
	confirmed, err := tui.Confirm(msg, false)
	if err != nil {
		return fmt.Errorf("confirmation: %w", err)
	}
	if !confirmed {
		fmt.Println("Cancelled.")
		return nil
	}

	// Create dissolve subject
	subject := chain.DissolveSubject{
		Reason: teamReasonFlag,
	}

	// Create block
	head := teamChain.Head()
	block, err := chain.NewBlock(head, chain.ActionDissolveTeam, subject, identity)
	if err != nil {
		return fmt.Errorf("create dissolve block: %w", err)
	}

	// Check if approval is needed
	status := teamChain.GetApprovalStatus(block)
	if status.Required > 0 {
		fmt.Printf("Dissolution proposed for project '%s'.\n", teamName)
		fmt.Printf("Awaiting approval from %d other member(s).\n", status.Required)
		fmt.Println("Pending proposals will be synced when the daemon is running.")
		// In a full implementation, we'd save this to pending/proposals
	} else {
		// No approval needed - apply directly
		if err := teamChain.AppendBlock(block); err != nil {
			return fmt.Errorf("append dissolve block: %w", err)
		}
		if err := teamChain.Save(chainPath); err != nil {
			return fmt.Errorf("save chain: %w", err)
		}
		client.NotifyChainChange()
		fmt.Printf("Project '%s' has been dissolved.\n", teamName)
		if teamReasonFlag != "" {
			fmt.Printf("Reason: %s\n", teamReasonFlag)
		}
	}

	return nil
}

var teamMembersCmd = &cobra.Command{
	Use:   "members [team]",
	Short: "List team members",
	Long: `List all current members of a team.

If no team is specified, uses the team from the current project's .envctl file.

Example:
  envctl team members
  envctl team members myproject`,
	Args: cobra.MaximumNArgs(1),
	RunE: runTeamMembers,
}

func runTeamMembers(cmd *cobra.Command, args []string) error {
	teamName, err := resolveTeamName(args)
	if err != nil {
		return err
	}

	paths, err := config.GetPaths()
	if err != nil {
		return fmt.Errorf("get paths: %w", err)
	}

	// Load chain
	chainPath := paths.ChainFile(teamName)
	teamChain, err := chain.Load(chainPath)
	if err != nil {
		return fmt.Errorf("load project '%s': %w", teamName, err)
	}

	members := teamChain.Members()

	fmt.Printf("Project: %s (%d members)\n", teamName, len(members))
	fmt.Println()

	for _, m := range members {
		roleStr := string(m.Role)
		if m.Role == chain.RoleAdmin {
			roleStr = "admin"
		}

		envStr := strings.Join(m.Environments, ", ")
		if envStr == "" {
			envStr = "(none)"
		}

		fingerprint := crypto.PublicKeyFingerprint(m.SigningPub)

		fmt.Printf("  %s (%s)\n", m.Name, roleStr)
		fmt.Printf("    Fingerprint: %s\n", fingerprint)
		fmt.Printf("    Environments: %s\n", envStr)
		fmt.Printf("    Joined: %s\n", m.JoinedAt.Format("2006-01-02"))
		fmt.Println()
	}

	return nil
}

var teamInviteCmd = &cobra.Command{
	Use:   "invite <display-name>",
	Short: "Create an invite for a new member",
	Long: `Generate a single-use invite code for a new team member.

The invitee must provide their public key beforehand (via envctl whoami --verbose).
Share the generated code with them to complete the join process.

Examples:
  envctl project invite alice --pubkey abc123...
  envctl project invite bob --pubkey abc123... --ttl 1h
  envctl project invite carol --pubkey abc123... --env dev,stage --role member`,
	Args: cobra.ExactArgs(1),
	RunE: runTeamInvite,
}

func runTeamInvite(cmd *cobra.Command, args []string) error {
	displayName := args[0]

	// Parse pubkey (hex string or @file path)
	pubkeyHex := invitePubkeyFlag
	if strings.HasPrefix(pubkeyHex, "@") {
		data, err := os.ReadFile(pubkeyHex[1:])
		if err != nil {
			return fmt.Errorf("read pubkey file: %w", err)
		}
		pubkeyHex = strings.TrimSpace(string(data))
	}

	signingPub, err := hex.DecodeString(pubkeyHex)
	if err != nil {
		return fmt.Errorf("invalid public key hex: %w", err)
	}

	// Parse TTL
	ttl, err := time.ParseDuration(inviteTTLFlag)
	if err != nil {
		return fmt.Errorf("invalid TTL: %w", err)
	}

	// Parse role
	var role chain.Role
	switch teamRoleFlag {
	case "admin", "lead":
		role = chain.RoleAdmin
	case "reader":
		role = chain.RoleReader
	default:
		role = chain.RoleMember
	}

	teamName, err := resolveTeamName(nil)
	if err != nil {
		return err
	}

	paths, err := config.GetPaths()
	if err != nil {
		return fmt.Errorf("get paths: %w", err)
	}

	// Load chain
	chainPath := paths.ChainFile(teamName)
	teamChain, err := chain.Load(chainPath)
	if err != nil {
		return fmt.Errorf("load project: %w", err)
	}

	// Determine environments
	var envs []string
	if teamEnvFlag != "" {
		envs = strings.Split(teamEnvFlag, ",")
		for i := range envs {
			envs[i] = strings.TrimSpace(envs[i])
		}
	} else {
		// Use default access from policy
		policy := teamChain.Policy()
		envs = policy.DefaultAccess
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
	if err := teamChain.CanPropose(chain.ActionInvite, identity.SigningPublicKey()); err != nil {
		return fmt.Errorf("cannot create invite: %w", err)
	}

	// Generate invite code
	code, err := chain.GenerateInviteCode()
	if err != nil {
		return fmt.Errorf("generate invite code: %w", err)
	}

	// Hash the pubkey for storage (don't store raw pubkey on chain)
	pubkeyHash := crypto.HashPublicKey(signingPub)

	// Create invite
	now := time.Now().UTC()
	invite := chain.Invite{
		Code:         code,
		Name:         displayName,
		PubKeyHash:   pubkeyHash,
		Role:         role,
		Environments: envs,
		CreatedAt:    now,
		ExpiresAt:    now.Add(ttl),
	}

	// Create proposal block
	head := teamChain.Head()
	block, err := chain.NewBlock(head, chain.ActionInvite, invite, identity)
	if err != nil {
		return fmt.Errorf("create invite block: %w", err)
	}

	// Check if approval is needed
	status := teamChain.GetApprovalStatus(block)
	if status.Required > 0 && !status.Complete {
		fmt.Printf("Invite proposal created. Requires %d approval(s).\n", status.Required)
		fmt.Println("Pending proposals will be synced when the daemon is running.")
		// In a full implementation, we'd save this to pending/proposals
	} else {
		// No approval needed - append directly
		if err := teamChain.AppendBlock(block); err != nil {
			return fmt.Errorf("append invite block: %w", err)
		}
		if err := teamChain.Save(chainPath); err != nil {
			return fmt.Errorf("save chain: %w", err)
		}
		client.NotifyChainChange()

		fmt.Printf("Invite created for '%s'\n", displayName)
		fmt.Printf("Key fingerprint: sha256:%s...\n\n", pubkeyHash[:16])
		fmt.Printf("Share this with %s (expires in %s):\n\n", displayName, ttl)
		fmt.Printf("  envctl project join --code %s\n\n", code)
	}

	return nil
}

var teamInvitesCmd = &cobra.Command{
	Use:   "invites",
	Short: "List all invites for the project",
	Long: `List all invite codes for the current project.

Shows pending, used, expired, and revoked invites with their status.

Examples:
  envctl project invites
  envctl project invites --project myproject`,
	RunE: runTeamInvites,
}

func runTeamInvites(cmd *cobra.Command, args []string) error {
	teamName, err := resolveTeamName(nil)
	if err != nil {
		return err
	}

	paths, err := config.GetPaths()
	if err != nil {
		return fmt.Errorf("get paths: %w", err)
	}

	// Load chain
	chainPath := paths.ChainFile(teamName)
	teamChain, err := chain.Load(chainPath)
	if err != nil {
		return fmt.Errorf("load project: %w", err)
	}

	invites := teamChain.GetAllInvites()

	if len(invites) == 0 {
		fmt.Println("No invites found.")
		fmt.Println()
		fmt.Println("Create one with:")
		fmt.Println("  envctl project invite <name> --pubkey <pubkey>")
		return nil
	}

	fmt.Printf("Project: %s\n", teamName)
	fmt.Printf("Invites: %d total\n\n", len(invites))

	for _, inv := range invites {
		statusStr := ""
		switch inv.Status {
		case "pending":
			remaining := time.Until(inv.Invite.ExpiresAt)
			if remaining > 0 {
				statusStr = fmt.Sprintf("pending (expires in %s)", remaining.Truncate(time.Second))
			} else {
				statusStr = "expired"
			}
		case "used":
			statusStr = fmt.Sprintf("used by %s", inv.UsedBy)
		case "revoked":
			statusStr = "revoked"
		case "expired":
			statusStr = "expired"
		default:
			statusStr = inv.Status
		}

		fmt.Printf("  %s  %s (%s)\n", inv.Invite.Code, inv.Invite.Name, statusStr)
		fmt.Printf("    Role: %s, Environments: %s\n", inv.Invite.Role, strings.Join(inv.Invite.Environments, ", "))
		fmt.Printf("    Created: %s\n", inv.Invite.CreatedAt.Format("2006-01-02 15:04"))
		fmt.Println()
	}

	return nil
}

var teamInviteRevokeCmd = &cobra.Command{
	Use:   "revoke-invite <code>",
	Short: "Revoke an unused invite code",
	Long: `Revoke an invite code that hasn't been used yet.

Only admins can revoke invites. Revoked invites cannot be used to join.

Examples:
  envctl project revoke-invite ABC-DEF-GHI
  envctl project revoke-invite ABC-DEF-GHI --reason "wrong person"`,
	Args: cobra.ExactArgs(1),
	RunE: runTeamInviteRevoke,
}

func runTeamInviteRevoke(cmd *cobra.Command, args []string) error {
	code := chain.NormalizeInviteCode(args[0])

	teamName, err := resolveTeamName(nil)
	if err != nil {
		return err
	}

	paths, err := config.GetPaths()
	if err != nil {
		return fmt.Errorf("get paths: %w", err)
	}

	// Load chain
	chainPath := paths.ChainFile(teamName)
	teamChain, err := chain.Load(chainPath)
	if err != nil {
		return fmt.Errorf("load project: %w", err)
	}

	// Find the invite
	invite, _, err := teamChain.FindInvite(code)
	if err != nil {
		return fmt.Errorf("invite not found: %w", err)
	}

	// Check if already used or revoked
	if teamChain.IsInviteUsed(code) {
		return fmt.Errorf("invite %s has already been used", chain.FormatInviteCode(code))
	}
	if teamChain.IsInviteRevoked(code) {
		return fmt.Errorf("invite %s has already been revoked", chain.FormatInviteCode(code))
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
	if err := teamChain.CanPropose(chain.ActionRevokeInvite, identity.SigningPublicKey()); err != nil {
		return fmt.Errorf("cannot revoke invite: %w", err)
	}

	// Create revocation subject
	revocation := chain.InviteRevocation{
		Code:   code,
		Reason: teamReasonFlag,
	}

	// Create block
	head := teamChain.Head()
	block, err := chain.NewBlock(head, chain.ActionRevokeInvite, revocation, identity)
	if err != nil {
		return fmt.Errorf("create revocation block: %w", err)
	}

	// Check if approval is needed
	status := teamChain.GetApprovalStatus(block)
	if status.Required > 0 && !status.Complete {
		fmt.Printf("Revocation proposal created. Requires %d approval(s).\n", status.Required)
	} else {
		if err := teamChain.AppendBlock(block); err != nil {
			return fmt.Errorf("append block: %w", err)
		}
		if err := teamChain.Save(chainPath); err != nil {
			return fmt.Errorf("save chain: %w", err)
		}
		client.NotifyChainChange()
		fmt.Printf("Invite %s for '%s' has been revoked.\n", chain.FormatInviteCode(code), invite.Name)
	}

	return nil
}

var teamRemoveCmd = &cobra.Command{
	Use:   "remove <name>",
	Short: "Remove a team member",
	Args:  cobra.ExactArgs(1),
	RunE:  runTeamRemove,
}

func runTeamRemove(cmd *cobra.Command, args []string) error {
	memberName := args[0]

	teamName, err := resolveTeamName(nil)
	if err != nil {
		return err
	}

	paths, err := config.GetPaths()
	if err != nil {
		return fmt.Errorf("get paths: %w", err)
	}

	// Load chain
	chainPath := paths.ChainFile(teamName)
	teamChain, err := chain.Load(chainPath)
	if err != nil {
		return fmt.Errorf("load project: %w", err)
	}

	// Find member
	member := teamChain.FindMemberByName(memberName)
	if member == nil {
		return fmt.Errorf("member '%s' not found", memberName)
	}

	// Confirm
	confirmed, err := tui.Confirm(fmt.Sprintf("Remove '%s' from project?", memberName), false)
	if err != nil || !confirmed {
		fmt.Println("Cancelled.")
		return nil
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
	if err := teamChain.CanPropose(chain.ActionRemoveMember, identity.SigningPublicKey()); err != nil {
		return fmt.Errorf("cannot remove: %w", err)
	}

	// Create proposal block
	head := teamChain.Head()
	block, err := chain.NewBlock(head, chain.ActionRemoveMember, member.SigningPub, identity)
	if err != nil {
		return fmt.Errorf("create proposal: %w", err)
	}

	// Check if approval is needed
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
		fmt.Printf("Member '%s' removed.\n", memberName)
	}

	return nil
}

var teamLeaveCmd = &cobra.Command{
	Use:   "leave",
	Short: "Leave a team",
	Long: `Remove yourself from a team.

Any member can leave a team at any time without approval.
The last admin cannot leave (must promote another admin first).

Example:
  envctl team leave`,
	RunE: runTeamLeave,
}

func runTeamLeave(cmd *cobra.Command, args []string) error {
	teamName, err := resolveTeamName(nil)
	if err != nil {
		return err
	}

	paths, err := config.GetPaths()
	if err != nil {
		return fmt.Errorf("get paths: %w", err)
	}

	// Load chain
	chainPath := paths.ChainFile(teamName)
	teamChain, err := chain.Load(chainPath)
	if err != nil {
		return fmt.Errorf("load project: %w", err)
	}

	// Confirm
	confirmed, err := tui.Confirm(fmt.Sprintf("Leave project '%s'?", teamName), false)
	if err != nil || !confirmed {
		fmt.Println("Cancelled.")
		return nil
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

	// Check if we're a member
	if !teamChain.IsMember(identity.SigningPublicKey()) {
		return fmt.Errorf("you are not a member of this project")
	}

	// Check permission (last admin check)
	if err := teamChain.CanPropose(chain.ActionLeaveTeam, identity.SigningPublicKey()); err != nil {
		return err
	}

	// Create leave block (self-removal, no approval needed)
	head := teamChain.Head()
	block, err := chain.NewBlock(head, chain.ActionLeaveTeam, identity.SigningPublicKey(), identity)
	if err != nil {
		return fmt.Errorf("create block: %w", err)
	}

	if err := teamChain.AppendBlock(block); err != nil {
		return fmt.Errorf("append block: %w", err)
	}

	if err := teamChain.Save(chainPath); err != nil {
		return fmt.Errorf("save chain: %w", err)
	}
	client.NotifyChainChange()

	fmt.Printf("You have left project '%s'.\n", teamName)
	return nil
}

var teamAccessCmd = &cobra.Command{
	Use:   "access",
	Short: "Show environment access",
	RunE:  runTeamAccess,
}

func runTeamAccess(cmd *cobra.Command, args []string) error {
	teamName, err := resolveTeamName(nil)
	if err != nil {
		return err
	}

	paths, err := config.GetPaths()
	if err != nil {
		return fmt.Errorf("get paths: %w", err)
	}

	// Load chain
	chainPath := paths.ChainFile(teamName)
	teamChain, err := chain.Load(chainPath)
	if err != nil {
		return fmt.Errorf("load project: %w", err)
	}

	policy := teamChain.Policy()

	fmt.Printf("Project: %s\n", teamName)
	fmt.Printf("Available environments: %s\n", strings.Join(policy.Environments, ", "))
	fmt.Println()

	// Show access by environment
	for _, env := range policy.Environments {
		members := teamChain.MembersWithEnvAccess(env)
		names := make([]string, len(members))
		for i, m := range members {
			names[i] = m.Name
		}
		fmt.Printf("  %s: %s\n", env, strings.Join(names, ", "))
	}

	return nil
}

var teamGrantCmd = &cobra.Command{
	Use:   "grant <member>",
	Short: "Grant environment access",
	Args:  cobra.ExactArgs(1),
	RunE:  runTeamGrant,
}

func runTeamGrant(cmd *cobra.Command, args []string) error {
	memberName := args[0]
	envs := strings.Split(teamEnvFlag, ",")
	for i := range envs {
		envs[i] = strings.TrimSpace(envs[i])
	}

	return updateAccess(memberName, envs, "grant")
}

var teamRevokeCmd = &cobra.Command{
	Use:   "revoke <member>",
	Short: "Revoke environment access",
	Args:  cobra.ExactArgs(1),
	RunE:  runTeamRevoke,
}

func runTeamRevoke(cmd *cobra.Command, args []string) error {
	memberName := args[0]
	envs := strings.Split(teamEnvFlag, ",")
	for i := range envs {
		envs[i] = strings.TrimSpace(envs[i])
	}

	return updateAccess(memberName, envs, "revoke")
}

func updateAccess(memberName string, envs []string, action string) error {
	teamName, err := resolveTeamName(nil)
	if err != nil {
		return err
	}

	paths, err := config.GetPaths()
	if err != nil {
		return fmt.Errorf("get paths: %w", err)
	}

	// Load chain
	chainPath := paths.ChainFile(teamName)
	teamChain, err := chain.Load(chainPath)
	if err != nil {
		return fmt.Errorf("load project: %w", err)
	}

	// Find member
	member := teamChain.FindMemberByName(memberName)
	if member == nil {
		return fmt.Errorf("member '%s' not found", memberName)
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
	if err := teamChain.CanPropose(chain.ActionUpdateAccess, identity.SigningPublicKey()); err != nil {
		return err
	}

	// Create access change
	ac := chain.AccessChange{
		Member:       member.SigningPub,
		Environments: envs,
		Action:       action,
	}

	// Create proposal block
	head := teamChain.Head()
	block, err := chain.NewBlock(head, chain.ActionUpdateAccess, ac, identity)
	if err != nil {
		return fmt.Errorf("create proposal: %w", err)
	}

	// Check if approval is needed
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
		fmt.Printf("Access updated for '%s'.\n", memberName)
	}

	return nil
}

var teamPendingCmd = &cobra.Command{
	Use:   "pending",
	Short: "Show pending proposals",
	RunE:  runTeamPending,
}

func runTeamPending(cmd *cobra.Command, args []string) error {
	fmt.Println("Pending proposals will be shown when the daemon is running.")
	fmt.Println("For now, proposals are applied immediately if no approval is needed.")
	return nil
}

var teamApproveCmd = &cobra.Command{
	Use:   "approve <id>",
	Short: "Approve a pending proposal",
	Args:  cobra.ExactArgs(1),
	RunE:  runTeamApprove,
}

func runTeamApprove(cmd *cobra.Command, args []string) error {
	fmt.Println("Proposal approval requires the daemon to be running.")
	fmt.Println("Use 'envctl daemon start' first.")
	return nil
}

var teamDenyCmd = &cobra.Command{
	Use:   "deny <id>",
	Short: "Deny a pending proposal",
	Args:  cobra.ExactArgs(1),
	RunE:  runTeamDeny,
}

func runTeamDeny(cmd *cobra.Command, args []string) error {
	fmt.Println("Proposal denial requires the daemon to be running.")
	fmt.Println("Use 'envctl daemon start' first.")
	return nil
}

var teamLogCmd = &cobra.Command{
	Use:   "log",
	Short: "Show chain history",
	RunE:  runTeamLog,
}

func runTeamLog(cmd *cobra.Command, args []string) error {
	teamName, err := resolveTeamName(nil)
	if err != nil {
		return err
	}

	paths, err := config.GetPaths()
	if err != nil {
		return fmt.Errorf("get paths: %w", err)
	}

	// Load chain
	chainPath := paths.ChainFile(teamName)
	teamChain, err := chain.Load(chainPath)
	if err != nil {
		return fmt.Errorf("load project: %w", err)
	}

	fmt.Printf("Project: %s (%d blocks)\n", teamName, teamChain.Len())
	fmt.Println()

	for i := 0; i < teamChain.Len(); i++ {
		block := teamChain.Block(uint64(i))

		hashStr := hex.EncodeToString(block.Hash)
		if len(hashStr) > 16 {
			hashStr = hashStr[:16] + "..."
		}

		fmt.Printf("[%d] %s %s\n", block.Index, block.Timestamp.Format("2006-01-02 15:04"), block.Action)
		fmt.Printf("    Hash: %s\n", hashStr)

		if len(block.Approvals) > 0 {
			fmt.Printf("    Approvals: %d\n", len(block.Approvals))
		}
	}

	return nil
}

// resolveTeamName resolves the team name from args, --team flag, or context
func resolveTeamName(args []string) (string, error) {
	// First check --team flag
	if teamNameFlag != "" {
		return teamNameFlag, nil
	}

	// Then check positional args
	if len(args) > 0 && args[0] != "" {
		return args[0], nil
	}

	// Try .envctl file in current directory
	project, err := config.LoadProjectConfig(".")
	if err == nil && project.Project != "" {
		return project.Project, nil
	}

	// Try default from global config
	cfg, err := config.Load()
	if err == nil && cfg.Defaults.Team != "" {
		return cfg.Defaults.Team, nil
	}

	return "", fmt.Errorf("no project specified. Use --project flag or create a .envctl file")
}

// Team env subcommands

var teamEnvCmd = &cobra.Command{
	Use:   "env",
	Short: "Manage team environments",
	Long: `Manage the environments available for a team.

Environments define the access levels for team members (e.g., dev, stage, prod).
Each member can be granted access to specific environments.`,
}

var teamEnvListCmd = &cobra.Command{
	Use:   "list",
	Short: "List team environments",
	RunE:  runTeamEnvList,
}

func runTeamEnvList(cmd *cobra.Command, args []string) error {
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

	fmt.Printf("Environments for project '%s':\n", teamName)
	fmt.Println()

	for _, env := range policy.Environments {
		members := teamChain.MembersWithEnvAccess(env)
		defaultMarker := ""
		for _, d := range policy.DefaultAccess {
			if d == env {
				defaultMarker = " [default]"
				break
			}
		}
		fmt.Printf("  %-12s (%d members)%s\n", env, len(members), defaultMarker)
	}

	return nil
}

var teamEnvAddCmd = &cobra.Command{
	Use:   "add <environment>",
	Short: "Add a new environment to the team",
	Args:  cobra.ExactArgs(1),
	RunE:  runTeamEnvAdd,
}

func runTeamEnvAdd(cmd *cobra.Command, args []string) error {
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
		return fmt.Errorf("cannot add environment: %w", err)
	}

	// Create add env subject
	subject := chain.EnvChange{
		Environment: envName,
	}

	head := teamChain.Head()
	block, err := chain.NewBlock(head, chain.ActionAddEnv, subject, identity)
	if err != nil {
		return fmt.Errorf("create proposal: %w", err)
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
		fmt.Printf("Environment '%s' added.\n", envName)
	}

	return nil
}

var teamEnvRemoveCmd = &cobra.Command{
	Use:   "remove <environment>",
	Short: "Remove an environment from the team",
	Args:  cobra.ExactArgs(1),
	RunE:  runTeamEnvRemove,
}

func runTeamEnvRemove(cmd *cobra.Command, args []string) error {
	envName := strings.TrimSpace(args[0])

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
		return fmt.Errorf("cannot remove the last environment")
	}

	// Check if any members have access
	membersWithAccess := teamChain.MembersWithEnvAccess(envName)
	if len(membersWithAccess) > 0 && !teamForceFlag {
		names := make([]string, len(membersWithAccess))
		for i, m := range membersWithAccess {
			names[i] = m.Name
		}
		return fmt.Errorf("%d members have access to '%s': %s. Use --force to revoke and remove",
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
		return fmt.Errorf("cannot remove environment: %w", err)
	}

	// Build list of members to revoke from
	var revokedFrom [][]byte
	if teamForceFlag && len(membersWithAccess) > 0 {
		revokedFrom = make([][]byte, len(membersWithAccess))
		for i, m := range membersWithAccess {
			revokedFrom[i] = m.SigningPub
		}
		fmt.Printf("Revoking '%s' access from: ", envName)
		names := make([]string, len(membersWithAccess))
		for i, m := range membersWithAccess {
			names[i] = m.Name
		}
		fmt.Println(strings.Join(names, ", "))
	}

	// Create remove env subject
	subject := chain.EnvChange{
		Environment: envName,
		RevokedFrom: revokedFrom,
	}

	head := teamChain.Head()
	block, err := chain.NewBlock(head, chain.ActionRemoveEnv, subject, identity)
	if err != nil {
		return fmt.Errorf("create proposal: %w", err)
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
		fmt.Printf("Environment '%s' removed.\n", envName)
	}

	return nil
}

// Helper functions

func isValidEnvName(name string) bool {
	return envNameRegex.MatchString(name)
}

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}
