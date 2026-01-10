package cli

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
	"envctl.dev/go/envctl/internal/config"
	"envctl.dev/go/envctl/internal/crypto"
	"envctl.dev/go/envctl/internal/opschain"
	"envctl.dev/go/envctl/internal/secrets"
	"envctl.dev/go/envctl/internal/tui"
)

// CI public key filename stored in .envctl directory
const ciPublicKeyFile = "ci_pubkey"

// resolveCIProject resolves project name and directory for CI commands.
// Returns (projectName, projectDir, error).
// If --project flag is set, it overrides .envctl/config.
// projectDir is needed to find/store the CI public key.
func resolveCIProject(cmd *cobra.Command) (string, string, error) {
	projectFlag, _ := cmd.Flags().GetString("project")

	cwd, err := os.Getwd()
	if err != nil {
		return "", "", fmt.Errorf("get working directory: %w", err)
	}

	// Try to find project config in current directory
	projectConfig, projectDir, err := config.FindProjectConfig(cwd)

	if projectFlag != "" {
		// --project flag overrides the project name
		// but we still use the projectDir from cwd if available
		if err != nil {
			// Not in a project directory - use cwd as projectDir
			projectDir = cwd
		}
		return projectFlag, projectDir, nil
	}

	// No --project flag, must be in a project directory
	if err != nil {
		return "", "", fmt.Errorf("not in a project directory. Use --project flag or run 'envctl project link <name>' first")
	}

	return projectConfig.Project, projectDir, nil
}

// resolveCIProjectAndEnv resolves project, environment, and directory for CI commands.
// Returns (projectName, environment, projectDir, error).
func resolveCIProjectAndEnv(cmd *cobra.Command) (string, string, string, error) {
	projectName, projectDir, err := resolveCIProject(cmd)
	if err != nil {
		return "", "", "", err
	}

	// Get environment from --env flag or project config
	envFlag, _ := cmd.Flags().GetString("env")
	if envFlag != "" {
		return projectName, envFlag, projectDir, nil
	}

	// Try to get from project config
	cwd, _ := os.Getwd()
	if projectConfig, err := config.LoadProjectConfig(cwd); err == nil && projectConfig.Env != "" {
		return projectName, projectConfig.Env, projectDir, nil
	}

	// Default to "dev" if no environment specified
	return projectName, "dev", projectDir, nil
}

func init() {
	rootCmd.AddCommand(ciCmd)

	ciCmd.AddCommand(ciKeygenCmd)
	ciCmd.AddCommand(ciExportCmd)
	ciCmd.AddCommand(ciApplyCmd)

	// Global CI flags
	ciCmd.PersistentFlags().StringP("project", "p", "", "project name (overrides .envctl file)")

	// keygen flags
	ciKeygenCmd.Flags().BoolP("force", "f", false, "replace existing CI key")

	// export flags
	ciExportCmd.Flags().StringP("env", "e", "", "target environment (default: current environment)")
	ciExportCmd.Flags().StringP("output", "o", "", "output file (default: stdout)")
	ciExportCmd.Flags().Bool("sign", true, "sign bundle with exporter's identity")

	// apply flags
	ciApplyCmd.Flags().StringP("bundle", "b", "", "bundle file (default: .envctl/secrets.enc)")
	ciApplyCmd.Flags().String("key-env", "ENVCTL_CI_KEY", "environment variable containing CI private key")
}

var ciCmd = &cobra.Command{
	Use:   "ci",
	Short: "CI/CD integration commands",
	Long: `Commands for CI/CD pipeline integration.

These commands enable offline secrets decryption in CI builds
without network access to team members or relay servers.

The workflow is:
  1. Generate a CI keypair:  envctl ci keygen
  2. Copy private key to CI: (GitHub Secrets, GitLab CI vars, etc.)
  3. Export bundle:          envctl ci export -o .envctl/secrets.enc
  4. Commit bundle:          git add .envctl/secrets.enc && git commit
  5. Use in CI:              ENVCTL_CI_KEY=... envctl ci apply -- npm test

The encrypted bundle can be safely committed to your repository.
Only someone with the CI private key can decrypt it.

Security:
  - Uses ML-KEM-768 (post-quantum) for key encapsulation
  - Public key stored in project, private key only shown once
  - Any admin with the public key can export bundles
  - Only CI runners with the private key can decrypt`,
}

var ciKeygenCmd = &cobra.Command{
	Use:   "keygen",
	Short: "Generate a CI encryption keypair",
	Long: `Generate a new ML-KEM-768 keypair for CI bundle encryption.

The public key is stored in .envctl/ci_pubkey and should be committed
to your repository. Any team admin can use it to export encrypted bundles.

The private key is displayed ONCE and must be stored in your CI platform's
secrets manager (e.g., GitHub Secrets, GitLab CI Variables).

Examples:
  envctl ci keygen                  # Generate keypair (uses project from .envctl)
  envctl ci keygen -p myproject     # Generate for specific project
  envctl ci keygen --force          # Replace existing keypair`,
	RunE: runCIKeygen,
}

func runCIKeygen(cmd *cobra.Command, args []string) error {
	force, _ := cmd.Flags().GetBool("force")

	// Resolve project name and directory
	projectName, projectDir, err := resolveCIProject(cmd)
	if err != nil {
		return err
	}

	// Check for existing CI key
	pubKeyPath := filepath.Join(projectDir, ".envctl", ciPublicKeyFile)
	if _, err := os.Stat(pubKeyPath); err == nil && !force {
		return secrets.ErrCIKeyExists
	}

	// Generate ML-KEM-768 keypair
	keypair, err := secrets.GenerateCIKeyPair()
	if err != nil {
		return fmt.Errorf("generate keypair: %w", err)
	}
	defer crypto.ZeroBytes(keypair.PrivateKey)

	// Ensure .envctl directory exists
	envctlDir := filepath.Join(projectDir, ".envctl")
	if err := os.MkdirAll(envctlDir, 0755); err != nil {
		return fmt.Errorf("create .envctl directory: %w", err)
	}

	// Save public key
	if err := os.WriteFile(pubKeyPath, []byte(keypair.EncodePublicKey()), 0644); err != nil {
		return fmt.Errorf("save public key: %w", err)
	}

	// Display private key to user
	fmt.Fprintf(os.Stderr, "Generated CI keypair for project \"%s\"\n\n", projectName)
	fmt.Fprintf(os.Stderr, "Public key saved to: %s\n", pubKeyPath)
	fmt.Fprintf(os.Stderr, "Commit this file to your repository.\n\n")
	fmt.Fprintf(os.Stderr, "CI Private Key (store in your CI platform's secrets as ENVCTL_CI_KEY):\n\n")

	// Output private key to stdout (can be piped/redirected)
	fmt.Println(keypair.EncodePrivateKey())

	// Red + bold warning that won't be shown again
	fmt.Fprintf(os.Stderr, "\n\033[1;31mThis private key will NOT be shown again.\033[0m\n")
	fmt.Fprintf(os.Stderr, "Store it securely in your CI platform now.\n")

	return nil
}

var ciExportCmd = &cobra.Command{
	Use:   "export",
	Short: "Export encrypted secrets bundle",
	Long: `Export current environment variables as an encrypted CI bundle.

The bundle is encrypted with the project's CI public key using ML-KEM-768,
allowing any CI job with the private key to decrypt without network access.

The public key must exist (run 'envctl ci keygen' first).
The bundle includes a signature from your identity for audit purposes.

Examples:
  envctl ci export                              # To stdout (uses project from .envctl)
  envctl ci export -p myproject -e prod         # Export specific project/env
  envctl ci export -o .envctl/secrets.enc       # To file
  envctl ci export -e prod -o .envctl/prod.enc  # Export prod env to file`,
	RunE: runCIExport,
}

func runCIExport(cmd *cobra.Command, args []string) error {
	project, environment, projectDir, err := resolveCIProjectAndEnv(cmd)
	if err != nil {
		return err
	}

	signBundle, _ := cmd.Flags().GetBool("sign")
	outputPath, _ := cmd.Flags().GetString("output")

	// Load CI public key
	pubKeyPath := filepath.Join(projectDir, ".envctl", ciPublicKeyFile)
	pubKeyData, err := os.ReadFile(pubKeyPath)
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("%w\nRun 'envctl ci keygen' first to generate a CI keypair", secrets.ErrNoCIKey)
		}
		return fmt.Errorf("read public key: %w", err)
	}

	pubKey, err := secrets.ParseCIPublicKey(strings.TrimSpace(string(pubKeyData)))
	if err != nil {
		return fmt.Errorf("parse public key: %w", err)
	}

	// Load identity for decrypting current vars and signing
	paths, err := config.GetPaths()
	if err != nil {
		return fmt.Errorf("get paths: %w", err)
	}

	if !paths.IdentityExists() {
		return fmt.Errorf("no identity found. Run 'envctl identity init' first")
	}

	passphrase, err := tui.ReadPassword("Identity passphrase: ")
	if err != nil {
		return fmt.Errorf("read passphrase: %w", err)
	}

	identity, err := crypto.LoadEncrypted(paths.IdentityFile, passphrase)
	crypto.ZeroBytes(passphrase)
	if err != nil {
		return fmt.Errorf("load identity: %w", err)
	}

	// Get variables from opschain
	manager := opschain.NewManager(paths.ChainsDir, paths.TempDir, identity)
	vars, err := manager.List(project, environment)
	if err != nil {
		return fmt.Errorf("list variables: %w", err)
	}

	if len(vars) == 0 {
		return fmt.Errorf("no variables found for %s/%s", project, environment)
	}

	// Create bundle metadata
	meta := secrets.BundleMeta{
		Project:             project,
		Environment:         environment,
		ExporterFingerprint: identity.Fingerprint(),
	}

	// Encrypt bundle with ML-KEM public key
	bundle, err := secrets.EncryptBundle(vars, pubKey, meta)
	if err != nil {
		return fmt.Errorf("encrypt bundle: %w", err)
	}

	// Sign if requested
	if signBundle {
		if err := secrets.SignBundle(bundle, identity); err != nil {
			return fmt.Errorf("sign bundle: %w", err)
		}
	}

	// Serialize to JSON
	data, err := secrets.SerializeBundle(bundle)
	if err != nil {
		return fmt.Errorf("serialize bundle: %w", err)
	}

	// Output
	if outputPath == "" {
		fmt.Println(string(data))
	} else {
		// Ensure parent directory exists
		if err := os.MkdirAll(filepath.Dir(outputPath), 0755); err != nil {
			return fmt.Errorf("create directory: %w", err)
		}

		if err := os.WriteFile(outputPath, data, 0644); err != nil {
			return fmt.Errorf("write bundle: %w", err)
		}
		fmt.Fprintf(os.Stderr, "Exported %d variables to %s\n", len(vars), outputPath)
	}

	return nil
}

var ciApplyCmd = &cobra.Command{
	Use:   "apply [flags] -- <command> [args...]",
	Short: "Run command with secrets from CI bundle",
	Long: `Decrypt a CI bundle and run a command with the secrets in environment.

This is designed for CI/CD pipelines. The CI private key is read from an
environment variable (default: ENVCTL_CI_KEY). Secrets are decrypted
in memory and passed to the command - never written to disk.

No daemon or identity is required - just the bundle file and CI private key.

Examples:
  ENVCTL_CI_KEY=... envctl ci apply -- npm test
  ENVCTL_CI_KEY=... envctl ci apply -b .envctl/prod.enc -- ./deploy.sh
  envctl ci apply --bundle secrets.enc -- make build`,
	Args: cobra.MinimumNArgs(1),
	RunE: runCIApply,
}

func runCIApply(cmd *cobra.Command, args []string) error {
	bundlePath, _ := cmd.Flags().GetString("bundle")
	keyEnvVar, _ := cmd.Flags().GetString("key-env")

	// Default bundle location
	if bundlePath == "" {
		cwd, _ := os.Getwd()
		bundlePath = filepath.Join(cwd, ".envctl", "secrets.enc")
	}

	// Get CI private key from environment
	ciKeyStr := os.Getenv(keyEnvVar)
	if ciKeyStr == "" {
		return fmt.Errorf("CI private key not found in %s environment variable", keyEnvVar)
	}

	privateKey, err := secrets.ParseCIPrivateKey(strings.TrimSpace(ciKeyStr))
	if err != nil {
		return fmt.Errorf("invalid CI private key: %w", err)
	}
	defer crypto.ZeroBytes(privateKey)

	// Load and parse bundle
	bundleData, err := os.ReadFile(bundlePath)
	if err != nil {
		return fmt.Errorf("read bundle %s: %w", bundlePath, err)
	}

	bundle, err := secrets.ParseBundle(bundleData)
	if err != nil {
		return fmt.Errorf("parse bundle: %w", err)
	}

	// Decrypt bundle with ML-KEM private key
	vars, err := secrets.DecryptBundle(bundle, privateKey)
	if err != nil {
		return fmt.Errorf("decrypt bundle: %w", err)
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
