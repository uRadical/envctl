package cli

import (
	"encoding/hex"
	"fmt"

	"github.com/spf13/cobra"
	"uradical.io/go/envctl/internal/config"
	"uradical.io/go/envctl/internal/crypto"
)

var whoamiVerbose bool

func init() {
	rootCmd.AddCommand(whoamiCmd)

	whoamiCmd.Flags().BoolVarP(&whoamiVerbose, "verbose", "", false, "show full public keys")
}

var whoamiCmd = &cobra.Command{
	Use:   "whoami",
	Short: "Show identity information",
	Long: `Display your envctl identity information.

Shows the identity name, fingerprint, and public key files.
Does not require the daemon to be running.

Examples:
  envctl whoami
  envctl whoami --verbose`,
	RunE: runWhoami,
}

func runWhoami(cmd *cobra.Command, args []string) error {
	paths, err := config.GetPaths()
	if err != nil {
		return fmt.Errorf("get paths: %w", err)
	}

	// Check if identity exists
	if !paths.IdentityExists() {
		fmt.Println("No identity found.")
		fmt.Println()
		fmt.Println("To create an identity, run: envctl init")
		return nil
	}

	// Load public identity (doesn't require passphrase)
	pub, err := crypto.LoadPublic(paths.IdentityPubFile)
	if err != nil {
		return fmt.Errorf("load public identity: %w", err)
	}

	fmt.Printf("Name:        %s\n", pub.Name)
	fmt.Printf("Fingerprint: %s\n", pub.Fingerprint())
	fmt.Printf("Created:     %s\n", pub.CreatedAt.Format("2006-01-02 15:04:05 UTC"))
	fmt.Println()
	fmt.Printf("Identity file: %s\n", paths.IdentityFile)
	fmt.Printf("Public key:    %s\n", paths.IdentityPubFile)

	if whoamiVerbose {
		fmt.Println()
		fmt.Println("ML-KEM Public Key (encryption):")
		fmt.Printf("  %s\n", hex.EncodeToString(pub.MLKEMPub))
		fmt.Println()
		fmt.Println("Ed25519 Public Key (signing):")
		fmt.Printf("  %s\n", hex.EncodeToString(pub.SigningPub))
	}

	return nil
}
