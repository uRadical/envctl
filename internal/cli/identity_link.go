package cli

import (
	"fmt"
	"time"

	"github.com/spf13/cobra"

	"envctl.dev/go/envctl/internal/config"
	"envctl.dev/go/envctl/internal/crypto"
	"envctl.dev/go/envctl/internal/link"
	"envctl.dev/go/envctl/internal/tui"
)

var identityLinkCmd = &cobra.Command{
	Use:   "link",
	Short: "Link identity to another device",
	Long: `Transfer your identity to a new device securely.

On your existing device:
  envctl identity link

On your new device:
  envctl identity link --code XXXXXX

The devices will establish an encrypted connection using the code
for authentication. Your identity is transferred directly between
devices without passing through any server.

The pairing code is valid for 5 minutes and can only be used once.`,
	RunE: runIdentityLink,
}

func init() {
	identityLinkCmd.Flags().String("code", "", "linking code from source device")
	identityLinkCmd.Flags().String("addr", "", "direct address of source device (optional)")
	identityCmd.AddCommand(identityLinkCmd)
}

func runIdentityLink(cmd *cobra.Command, args []string) error {
	code, _ := cmd.Flags().GetString("code")

	if code == "" {
		return runLinkSource()
	}
	addr, _ := cmd.Flags().GetString("addr")
	return runLinkTarget(code, addr)
}

func runLinkSource() error {
	paths, err := config.GetPaths()
	if err != nil {
		return fmt.Errorf("get paths: %w", err)
	}

	// Check identity exists
	if !paths.SoftwareIdentityExists() {
		if paths.YubiKeyIdentityExists() {
			return fmt.Errorf("device linking is not supported for YubiKey identities")
		}
		return fmt.Errorf("no identity found. Create one with: envctl init")
	}

	// Load identity
	passphrase, err := tui.ReadPassword("Enter passphrase: ")
	if err != nil {
		return err
	}

	identity, err := crypto.LoadEncrypted(paths.IdentityFile, passphrase)
	crypto.ZeroBytes(passphrase)
	if err != nil {
		return fmt.Errorf("invalid passphrase: %w", err)
	}

	// Create linking session
	session, err := link.NewSourceSession(identity)
	if err != nil {
		return fmt.Errorf("creating session: %w", err)
	}

	// Display UI
	fmt.Println()
	fmt.Println("+----------------------------------------+")
	fmt.Println("|         Device Linking Active          |")
	fmt.Println("|                                        |")
	fmt.Printf("|         Code:  %-6s                  |\n", session.FormattedCode())
	fmt.Println("|                                        |")
	fmt.Println("|  On your new device, run:              |")
	fmt.Printf("|  envctl identity link --code %s  |\n", session.Code)
	fmt.Println("|                                        |")
	fmt.Printf("|  Expires in %s                        |\n", formatLinkDuration(session.TimeRemaining()))
	fmt.Println("+----------------------------------------+")
	fmt.Println()

	// Start countdown display in background
	done := make(chan struct{})
	go func() {
		ticker := time.NewTicker(1 * time.Second)
		defer ticker.Stop()

		for {
			select {
			case <-done:
				return
			case <-session.Done():
				return
			case <-ticker.C:
				remaining := session.TimeRemaining()
				if remaining <= 0 {
					return
				}
				fmt.Printf("\rWaiting for connection... %s remaining  ", formatLinkDuration(remaining))
			}
		}
	}()

	// Run source protocol
	err = link.RunSource(session, func(status string) {
		fmt.Printf("\r%-50s\n", status)
	})

	close(done)

	if err != nil {
		return fmt.Errorf("linking failed: %w", err)
	}

	return nil
}

func runLinkTarget(code string, addr string) error {
	paths, err := config.GetPaths()
	if err != nil {
		return fmt.Errorf("get paths: %w", err)
	}

	// Check no identity exists
	if paths.SoftwareIdentityExists() || paths.YubiKeyIdentityExists() {
		return fmt.Errorf("identity already exists on this device. Remove it first if you want to link.")
	}

	// Parse and validate code
	code, err = link.ParseCode(code)
	if err != nil {
		return err
	}

	// Run target protocol
	identity, err := link.RunTarget(link.TargetOptions{
		Code:       code,
		SourceAddr: addr,
		OnStatus: func(status string) {
			fmt.Println(status)
		},
		OnConfirm: func(fingerprint string) bool {
			fmt.Println()
			fmt.Println("Verify this fingerprint matches your other device:")
			fmt.Printf("  Fingerprint: %s\n", fingerprint)
			fmt.Println()

			ok, err := tui.Confirm("Correct?", false)
			if err != nil {
				return false
			}
			return ok
		},
	})

	if err != nil {
		return fmt.Errorf("linking failed: %w", err)
	}

	// Prompt for passphrase to save
	fmt.Println()
	passphrase, err := tui.ReadPassword("Enter passphrase (same as source device): ")
	if err != nil {
		return err
	}

	// Ensure directories exist
	if err := paths.EnsureDirectories(); err != nil {
		crypto.ZeroBytes(passphrase)
		return fmt.Errorf("create directories: %w", err)
	}

	// Save identity
	if err := identity.SaveEncrypted(paths.IdentityFile, passphrase); err != nil {
		crypto.ZeroBytes(passphrase)
		return fmt.Errorf("saving identity: %w", err)
	}

	// Save public identity
	if err := identity.SavePublic(paths.IdentityPubFile); err != nil {
		crypto.ZeroBytes(passphrase)
		return fmt.Errorf("saving public identity: %w", err)
	}

	crypto.ZeroBytes(passphrase)

	fmt.Println()
	fmt.Println("Identity linked successfully.")
	fmt.Printf("  Name:        %s\n", identity.Name)
	fmt.Printf("  Fingerprint: %s\n", identity.Fingerprint())
	fmt.Println()
	fmt.Println("Ready to use. Start the daemon with: envctl daemon start")

	return nil
}

func formatLinkDuration(d time.Duration) string {
	if d < 0 {
		return "0:00"
	}
	mins := int(d.Minutes())
	secs := int(d.Seconds()) % 60
	return fmt.Sprintf("%d:%02d", mins, secs)
}
