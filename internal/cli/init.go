package cli

import (
	"github.com/spf13/cobra"
)

// Top-level init command - alias for 'identity init'
var initCmd = &cobra.Command{
	Use:   "init",
	Short: "Initialize envctl",
	Long: `Initialize a new envctl identity on this device.

This is an alias for 'envctl identity init'.

Each device has its own identity with unique cryptographic keys.
By default, the identity is encrypted with a passphrase for protection at rest.
Use --yubikey to store the identity on a YubiKey for hardware-backed security.
Use --keychain to store the passphrase in the system keychain for auto-unlock.

Examples:
  envctl init
  envctl init --keychain
  envctl init --name alan-laptop
  envctl init --name alan-laptop --yubikey`,
	RunE: runIdentityInit,
}

func init() {
	rootCmd.AddCommand(initCmd)

	// Mirror the same flags as identity init
	initCmd.Flags().StringVar(&initName, "name", "", "identity name (default: username-hostname)")
	initCmd.Flags().BoolVar(&initYubiKey, "yubikey", false, "store identity on YubiKey for hardware-backed security")
	initCmd.Flags().BoolVar(&initKeychain, "keychain", false, "store passphrase in system keychain for auto-unlock")
}
