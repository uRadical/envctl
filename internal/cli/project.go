package cli

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"uradical.io/go/envctl/internal/chain"
	"uradical.io/go/envctl/internal/config"
)

// projectNameFlag is an alias for teamNameFlag used with --project flag
var projectNameFlag string

func init() {
	// Add project as the primary command
	rootCmd.AddCommand(projectCmd)

	// Make team an alias for project (hidden from help but still works)
	teamCmd.Aliases = []string{}
	teamCmd.Hidden = true

	// Add --project flag as alias for --team on project command
	projectCmd.PersistentFlags().StringVar(&projectNameFlag, "project", "", "project name (overrides .envctl file)")

	// Copy all subcommands from team to project
	projectCmd.AddCommand(projectCreateCmd)
	projectCmd.AddCommand(projectDeleteCmd)
	projectCmd.AddCommand(projectListCmd)
	projectCmd.AddCommand(projectMembersCmd)
	projectCmd.AddCommand(projectInviteCmd)
	projectCmd.AddCommand(projectRemoveCmd)
	projectCmd.AddCommand(projectLeaveCmd)
	projectCmd.AddCommand(projectAccessCmd)
	projectCmd.AddCommand(projectGrantCmd)
	projectCmd.AddCommand(projectRevokeCmd)
	projectCmd.AddCommand(projectPendingCmd)
	projectCmd.AddCommand(projectApproveCmd)
	projectCmd.AddCommand(projectDenyCmd)
	projectCmd.AddCommand(projectLogCmd)
	projectCmd.AddCommand(projectEnvCmd)
	projectCmd.AddCommand(projectDissolveCmd)
	projectCmd.AddCommand(projectInvitesCmd)
	projectCmd.AddCommand(projectInviteRevokeCmd)

	// Project create flags
	projectCreateCmd.Flags().StringSliceVar(&teamEnvsFlag, "envs", []string{"dev", "stage", "prod"}, "environments for this project (comma-separated)")
	projectCreateCmd.Flags().StringVar(&teamDefaultFlag, "default-access", "dev", "default environment access for new members")

	// Project delete flags
	projectDeleteCmd.Flags().BoolVar(&teamSilentFlag, "silent", false, "delete without confirmation prompt")

	// Project dissolve flags
	projectDissolveCmd.Flags().StringVar(&teamReasonFlag, "reason", "", "reason for dissolution")

	// Project list flags
	projectListCmd.Flags().BoolVar(&teamJSONFlag, "json", false, "output as JSON")

	// Project invite flags
	projectInviteCmd.Flags().StringVar(&invitePubkeyFlag, "pubkey", "", "invitee's signing public key (hex)")
	projectInviteCmd.Flags().StringVar(&inviteTTLFlag, "ttl", "10m", "invite expiration (e.g., 10m, 1h, 24h)")
	projectInviteCmd.Flags().StringVar(&teamEnvFlag, "env", "", "environments to grant access to (comma-separated)")
	projectInviteCmd.Flags().StringVar(&teamRoleFlag, "role", "member", "role: admin, member, or reader")
	projectInviteCmd.MarkFlagRequired("pubkey")

	// Project invite revoke flags
	projectInviteRevokeCmd.Flags().StringVar(&teamReasonFlag, "reason", "", "reason for revoking invite")

	projectGrantCmd.Flags().StringVar(&teamEnvFlag, "env", "", "environments to grant (comma-separated)")
	projectGrantCmd.MarkFlagRequired("env")

	projectRevokeCmd.Flags().StringVar(&teamEnvFlag, "env", "", "environments to revoke (comma-separated)")
	projectRevokeCmd.MarkFlagRequired("env")

	// Project env subcommands
	projectEnvCmd.AddCommand(projectEnvListCmd)
	projectEnvCmd.AddCommand(projectEnvAddCmd)
	projectEnvCmd.AddCommand(projectEnvRemoveCmd)

	projectEnvRemoveCmd.Flags().BoolVar(&teamForceFlag, "force", false, "force remove and revoke access from members")

	// Project link command
	projectCmd.AddCommand(projectLinkCmd)
}

// projectPreRun copies --project flag value to teamNameFlag for compatibility
func projectPreRun(cmd *cobra.Command, args []string) {
	if projectNameFlag != "" && teamNameFlag == "" {
		teamNameFlag = projectNameFlag
	}
}

var projectCmd = &cobra.Command{
	Use:     "project",
	Aliases: []string{"team"},
	Short:   "Project management commands",
	Long: `Manage project membership and access.

Projects use a cryptographically signed blockchain to track membership.
All changes require approval from project members based on project policy.

The 'team' command is an alias for 'project'.`,
	PersistentPreRun: projectPreRun,
}

var projectCreateCmd = &cobra.Command{
	Use:   "create <name>",
	Short: "Create a new project",
	Long: `Create a new project with you as the founding admin.

The project uses a blockchain to track membership changes. As the founder,
you become the first admin and can invite other members.

By default, projects have three environments: dev, stage, prod.
You can customise this with the --envs flag.

Examples:
  envctl project create myproject
  envctl project create myproject --envs dev,qa,prod
  envctl project create myproject --envs local,test,live --default-access local`,
	Args: cobra.ExactArgs(1),
	RunE: runTeamCreate,
}

var projectDeleteCmd = &cobra.Command{
	Use:   "delete <project-name>",
	Short: "Delete a project's local chain file",
	Long: `Delete a project's local chain file.

This is a local-only operation that removes your copy of the project's chain.
Other project members still have their copies and can continue using the project.

Use this to clean up test projects or projects you no longer participate in.

Examples:
  envctl project delete testproject
  envctl project delete testproject --silent`,
	Args: cobra.ExactArgs(1),
	RunE: runTeamDelete,
}

var projectListCmd = &cobra.Command{
	Use:     "list",
	Aliases: []string{"ls"},
	Short:   "List all local projects",
	Long: `List all projects you have locally.

Shows project name, your role, member count, and chain height.

Examples:
  envctl project list
  envctl project ls
  envctl project list --json`,
	RunE: runTeamList,
}

var projectMembersCmd = &cobra.Command{
	Use:   "members [project]",
	Short: "List project members",
	Long: `List all current members of a project.

If no project is specified, uses the project from the current directory's .envctl file.

Example:
  envctl project members
  envctl project members myproject`,
	Args: cobra.MaximumNArgs(1),
	RunE: runTeamMembers,
}

var projectInviteCmd = &cobra.Command{
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

var projectRemoveCmd = &cobra.Command{
	Use:   "remove <name>",
	Short: "Remove a project member",
	Args:  cobra.ExactArgs(1),
	RunE:  runTeamRemove,
}

var projectLeaveCmd = &cobra.Command{
	Use:   "leave",
	Short: "Leave a project",
	Long: `Remove yourself from a project.

Any member can leave a project at any time without approval.
The last admin cannot leave (must promote another admin first).

Example:
  envctl project leave`,
	RunE: runTeamLeave,
}

var projectAccessCmd = &cobra.Command{
	Use:   "access",
	Short: "Show environment access",
	RunE:  runTeamAccess,
}

var projectGrantCmd = &cobra.Command{
	Use:   "grant <member>",
	Short: "Grant environment access",
	Args:  cobra.ExactArgs(1),
	RunE:  runTeamGrant,
}

var projectRevokeCmd = &cobra.Command{
	Use:   "revoke <member>",
	Short: "Revoke environment access",
	Args:  cobra.ExactArgs(1),
	RunE:  runTeamRevoke,
}

var projectPendingCmd = &cobra.Command{
	Use:   "pending",
	Short: "Show pending proposals",
	RunE:  runTeamPending,
}

var projectApproveCmd = &cobra.Command{
	Use:   "approve <id>",
	Short: "Approve a pending proposal",
	Args:  cobra.ExactArgs(1),
	RunE:  runTeamApprove,
}

var projectDenyCmd = &cobra.Command{
	Use:   "deny <id>",
	Short: "Deny a pending proposal",
	Args:  cobra.ExactArgs(1),
	RunE:  runTeamDeny,
}

var projectLogCmd = &cobra.Command{
	Use:   "log",
	Short: "Show chain history",
	RunE:  runTeamLog,
}

var projectDissolveCmd = &cobra.Command{
	Use:   "dissolve <project-name>",
	Short: "Dissolve a project (requires admin consensus)",
	Long: `Propose dissolution of a project.

This creates a dissolve block that must be approved by other admins
(if the project has multiple admins). Once applied, the project is permanently
dissolved and no new blocks can be added.

Dissolved projects:
- Cannot accept new blocks or proposals
- Cannot process env requests
- Remain visible in 'project list' marked as (dissolved)
- Can still be viewed for historical record
- Can be deleted locally with 'project delete'

This action cannot be undone.

Examples:
  envctl project dissolve myproject
  envctl project dissolve myproject --reason "Project completed"`,
	Args: cobra.ExactArgs(1),
	RunE: runTeamDissolve,
}

var projectInvitesCmd = &cobra.Command{
	Use:   "invites",
	Short: "List all invites for the project",
	Long: `List all invites for the project, showing their status.

Invites can be:
- valid: Not yet used, within TTL
- expired: TTL has passed without use
- used: Converted to a member-add block
- revoked: Admin cancelled the invite

Examples:
  envctl project invites
  envctl project invites myproject`,
	Args: cobra.MaximumNArgs(1),
	RunE: runTeamInvites,
}

var projectInviteRevokeCmd = &cobra.Command{
	Use:   "revoke-invite <code>",
	Short: "Revoke an unused invite code",
	Long: `Revoke an unused invite code.

Only valid (unused, non-expired) invites can be revoked.
This creates a revoke block on the chain.

Examples:
  envctl project revoke-invite ABC-DEF-GHI
  envctl project revoke-invite ABC-DEF-GHI --reason "Wrong person"`,
	Args: cobra.ExactArgs(1),
	RunE: runTeamInviteRevoke,
}

// Project env subcommands

var projectEnvCmd = &cobra.Command{
	Use:   "env",
	Short: "Manage project environments",
	Long: `Manage the environments available for a project.

Environments define the access levels for project members (e.g., dev, stage, prod).
Each member can be granted access to specific environments.`,
}

var projectEnvListCmd = &cobra.Command{
	Use:   "list",
	Short: "List project environments",
	RunE:  runTeamEnvList,
}

var projectEnvAddCmd = &cobra.Command{
	Use:   "add <environment>",
	Short: "Add a new environment to the project",
	Args:  cobra.ExactArgs(1),
	RunE:  runTeamEnvAdd,
}

var projectEnvRemoveCmd = &cobra.Command{
	Use:   "remove <environment>",
	Short: "Remove an environment from the project",
	Args:  cobra.ExactArgs(1),
	RunE:  runTeamEnvRemove,
}

var projectLinkCmd = &cobra.Command{
	Use:   "link <project-name>",
	Short: "Link current directory to an existing project",
	Long: `Create a .envctl/config file to associate this directory with a project.

Use this when you want to work with a project that was created elsewhere
or shared by a team member.

The project must exist in your local chains directory (from receiving
an invite or syncing).

Examples:
  envctl project link myproject
  envctl project link myproject   # in Bob's project directory`,
	Args: cobra.ExactArgs(1),
	RunE: runProjectLink,
}

func runProjectLink(cmd *cobra.Command, args []string) error {
	projectName := args[0]

	paths, err := config.GetPaths()
	if err != nil {
		return fmt.Errorf("get paths: %w", err)
	}

	// Check if project chain exists
	chainPath := paths.ChainFile(projectName)
	if !chain.Exists(chainPath) {
		return fmt.Errorf("project '%s' not found locally. Have you received an invite?", projectName)
	}

	// Check if .envctl/config already exists
	cwd, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("get working directory: %w", err)
	}

	if config.ProjectConfigExists(cwd) {
		existing, err := config.LoadProjectConfig(cwd)
		if err == nil && existing.Project != "" {
			return fmt.Errorf("directory already linked to project '%s'. Remove .envctl/config first to relink", existing.Project)
		}
	}

	// Load chain to get default environment
	teamChain, err := chain.Load(chainPath)
	if err != nil {
		return fmt.Errorf("load project: %w", err)
	}

	policy := teamChain.Policy()
	defaultEnv := "dev"
	if len(policy.DefaultAccess) > 0 {
		defaultEnv = policy.DefaultAccess[0]
	} else if len(policy.Environments) > 0 {
		defaultEnv = policy.Environments[0]
	}

	// Create .envctl/config
	projectConfig := &config.ProjectConfig{
		Project:         projectName,
		Env:             defaultEnv,
		Locked:          true,
		AutoLockMinutes: 480, // 8 hours default
	}

	if err := projectConfig.Save(cwd); err != nil {
		return fmt.Errorf("create .envctl/config: %w", err)
	}

	// Ensure .gitignore is configured
	if err := ensureGitignore(cwd); err != nil {
		fmt.Printf("Warning: could not update .gitignore: %v\n", err)
	}

	fmt.Printf("Linked directory to project '%s'\n", projectName)
	fmt.Printf("Default environment: %s\n", defaultEnv)
	fmt.Println()
	fmt.Println("You can now use:")
	fmt.Printf("  envctl fetch %s    # Get secrets sent by team members\n", defaultEnv)
	fmt.Printf("  envctl use %s      # Decrypt local secrets\n", defaultEnv)

	return nil
}
