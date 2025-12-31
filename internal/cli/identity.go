package cli

import (
	"crypto/ed25519"
	"fmt"
	"os"
	"os/user"
	"strings"
	"time"

	"github.com/skip2/go-qrcode"
	"github.com/spf13/cobra"

	"envctl.dev/go/envctl/internal/client"
	"envctl.dev/go/envctl/internal/config"
	"envctl.dev/go/envctl/internal/crypto"
	"envctl.dev/go/envctl/internal/keychain"
	"envctl.dev/go/envctl/internal/tui"
)

var identityCmd = &cobra.Command{
	Use:   "identity",
	Short: "Manage your identity",
	Long: `Manage your envctl identity.

Your identity is the cryptographic keypair that identifies you on the network.
It can be stored in software (passphrase-protected) or on a YubiKey.

Commands:
  export      Export identity as paper backup (mnemonic words)
  recover     Recover identity from paper backup
  rotate-key  Rotate your identity keys
  link        Link identity to another device
  migrate     Migrate identity to YubiKey
  keys        List configured keys`,
}

var (
	initName     string
	initYubiKey  bool
	initKeychain bool
)

func init() {
	rootCmd.AddCommand(identityCmd)
	identityCmd.AddCommand(identityInitCmd)

	identityInitCmd.Flags().StringVar(&initName, "name", "", "identity name (default: username-hostname)")
	identityInitCmd.Flags().BoolVar(&initYubiKey, "yubikey", false, "store identity on YubiKey for hardware-backed security")
	identityInitCmd.Flags().BoolVar(&initKeychain, "keychain", false, "store passphrase in system keychain for auto-unlock")
}

// Init command

var identityInitCmd = &cobra.Command{
	Use:   "init",
	Short: "Initialize envctl identity",
	Long: `Initialize a new envctl identity on this device.

Each device has its own identity with unique cryptographic keys.
By default, the identity is encrypted with a passphrase for protection at rest.
Use --yubikey to store the identity on a YubiKey for hardware-backed security.
Use --keychain to store the passphrase in the system keychain for auto-unlock.

Examples:
  envctl identity init
  envctl identity init --keychain
  envctl identity init --name alan-laptop
  envctl identity init --name alan-laptop --yubikey`,
	RunE: runIdentityInit,
}

func runIdentityInit(cmd *cobra.Command, args []string) error {
	paths, err := config.GetPaths()
	if err != nil {
		return fmt.Errorf("get paths: %w", err)
	}

	// Check if identity already exists
	if paths.IdentityExists() {
		fmt.Println("Identity already exists.")
		if paths.SoftwareIdentityExists() {
			fmt.Printf("  Identity file: %s\n", paths.IdentityFile)
		}
		if paths.HybridIdentityExists() {
			fmt.Printf("  Hybrid identity: %s\n", paths.HybridIdentityFile())
		}
		if paths.YubiKeyIdentityExists() {
			fmt.Printf("  YubiKey config: %s\n", paths.IdentityConfigFile)
		}
		fmt.Printf("  Public key file: %s\n", paths.IdentityPubFile)
		fmt.Println()
		fmt.Println("To view your identity, run: envctl whoami")
		fmt.Println("To create a new identity, first remove the existing files.")
		return nil
	}

	// Determine identity name
	name := initName
	if name == "" {
		name, err = defaultIdentityName()
		if err != nil {
			return fmt.Errorf("determine identity name: %w", err)
		}

		// Prompt for name with default
		name, err = tui.ReadLineDefault("Identity name: ", name)
		if err != nil {
			return fmt.Errorf("read name: %w", err)
		}
	}

	// Validate name
	name = strings.TrimSpace(name)
	if name == "" {
		return fmt.Errorf("identity name cannot be empty")
	}
	if len(name) > 64 {
		return fmt.Errorf("identity name too long (max 64 characters)")
	}

	// Ensure directories exist
	if err := paths.EnsureDirectories(); err != nil {
		return fmt.Errorf("create directories: %w", err)
	}

	// Branch based on YubiKey flag
	if initYubiKey {
		return initYubiKeyIdentity(paths, name)
	}

	return initSoftwareIdentity(paths, name, initKeychain)
}

func initSoftwareIdentity(paths *config.Paths, name string, useKeychain bool) error {
	// Prompt for passphrase
	fmt.Println()
	fmt.Println("Your identity will be encrypted with a passphrase.")
	fmt.Println("This passphrase is required to start the daemon.")
	fmt.Println()

	passphrase, err := tui.ReadPasswordConfirm("Passphrase: ", "Confirm passphrase: ")
	if err != nil {
		return fmt.Errorf("read passphrase: %w", err)
	}

	if len(passphrase) < 8 {
		return fmt.Errorf("passphrase must be at least 8 characters")
	}

	// Generate identity
	fmt.Println()
	fmt.Print("Generating identity...")

	identity, err := crypto.GenerateIdentity(name)
	if err != nil {
		fmt.Println(" failed")
		return fmt.Errorf("generate identity: %w", err)
	}

	fmt.Println(" done")

	// Save encrypted identity
	fmt.Print("Saving encrypted identity...")

	if err := identity.SaveEncrypted(paths.IdentityFile, passphrase); err != nil {
		fmt.Println(" failed")
		return fmt.Errorf("save identity: %w", err)
	}

	fmt.Println(" done")

	// Save public identity
	fmt.Print("Saving public key...")

	if err := identity.SavePublic(paths.IdentityPubFile); err != nil {
		fmt.Println(" failed")
		return fmt.Errorf("save public key: %w", err)
	}

	fmt.Println(" done")

	// Store passphrase in keychain if requested
	keychainStored := false
	if useKeychain {
		fmt.Print("Storing passphrase in keychain...")
		if err := keychain.Store(string(passphrase)); err != nil {
			fmt.Println(" failed")
			fmt.Printf("  Warning: %v\n", err)
			fmt.Println("  The daemon will prompt for passphrase on start.")
		} else {
			fmt.Println(" done")
			keychainStored = true
		}
	}

	// Clear passphrase from memory
	crypto.ZeroBytes(passphrase)

	fmt.Println()
	fmt.Println("Identity created successfully!")
	fmt.Println()
	fmt.Printf("  Name: %s\n", identity.Name)
	fmt.Printf("  Fingerprint: %s\n", identity.Fingerprint())
	fmt.Printf("  Storage: Software (passphrase-protected)\n")
	if keychainStored {
		fmt.Printf("  Keychain: passphrase stored for auto-unlock\n")
	}
	fmt.Printf("  Identity file: %s\n", paths.IdentityFile)
	fmt.Printf("  Public key file: %s\n", paths.IdentityPubFile)
	fmt.Println()
	fmt.Println("Next steps:")
	fmt.Println("  1. Start the daemon: envctl daemon start")
	fmt.Println("  2. Create a project: envctl project create <name>")
	fmt.Println("     Or join a project: envctl project join <pubkey> --project <name>")

	return nil
}

func initYubiKeyIdentity(paths *config.Paths, name string) error {
	// Check if YubiKey support is available
	if !crypto.HasYubiKeySupport() {
		return fmt.Errorf("YubiKey support not available. Ensure pcscd is running (Linux: sudo systemctl start pcscd)")
	}

	fmt.Println()
	fmt.Println("Initializing hardware-backed hybrid identity with YubiKey...")
	fmt.Println()
	fmt.Println("This creates a hybrid identity with:")
	fmt.Println("  • P-256 key on YubiKey (extraction resistant)")
	fmt.Println("  • ML-DSA-65 key in software (post-quantum secure)")
	fmt.Println("  • Both signatures required for all operations")
	fmt.Println()

	// Wait for YubiKey
	fmt.Println("Insert YubiKey and press Enter...")
	if _, err := tui.ReadLine(""); err != nil {
		return err
	}

	// Find YubiKeys
	keys, err := crypto.FindYubiKeys()
	if err != nil {
		return fmt.Errorf("finding YubiKeys: %w", err)
	}

	if len(keys) == 0 {
		return fmt.Errorf("no YubiKey found. Make sure it's properly inserted")
	}

	// Use first YubiKey (could prompt to choose if multiple)
	yk := keys[0]
	defer yk.Close()

	// Close any extra keys
	for i := 1; i < len(keys); i++ {
		keys[i].Close()
	}

	fmt.Printf("YubiKey found (serial: %d)\n", yk.Serial())
	fmt.Println()

	// Prompt for PIN
	pin, err := tui.ReadPassword("Enter PIV PIN (default: 123456): ")
	if err != nil {
		return fmt.Errorf("read PIN: %w", err)
	}

	pinStr := string(pin)
	if pinStr == "" {
		pinStr = "123456"
	}

	// Check if using default PIN
	if pinStr == "123456" {
		fmt.Println()
		fmt.Println("Default PIN detected. You should change it for security.")
		newPIN, err := tui.ReadPassword("Set new PIN (6-8 digits): ")
		if err != nil {
			return fmt.Errorf("read new PIN: %w", err)
		}

		if len(newPIN) < 6 || len(newPIN) > 8 {
			return fmt.Errorf("PIN must be 6-8 digits")
		}

		confirm, err := tui.ReadPassword("Confirm PIN: ")
		if err != nil {
			return fmt.Errorf("confirm PIN: %w", err)
		}

		if string(newPIN) != string(confirm) {
			return fmt.Errorf("PINs do not match")
		}

		if err := yk.ChangePIN(pinStr, string(newPIN)); err != nil {
			return fmt.Errorf("changing PIN: %w", err)
		}

		pinStr = string(newPIN)
		fmt.Println("PIN changed successfully.")
	}

	// Generate hybrid identity (YubiKey P-256 + ML-DSA-65 + ML-KEM-768)
	fmt.Println()
	fmt.Println("Generating hybrid identity (this may take a moment)...")

	// Need direct access to piv.YubiKey for hybrid identity
	// The crypto.YubiKey wrapper doesn't expose it, so we'll use the internal card
	identity, err := crypto.GenerateHybridIdentity(name, yk.Card(), pinStr, func(msg string) {
		fmt.Println(msg)
	})
	if err != nil {
		return fmt.Errorf("generating hybrid identity: %w", err)
	}

	// Save hybrid identity
	hybridPath := paths.HybridIdentityFile()
	if err := identity.Save(hybridPath); err != nil {
		return fmt.Errorf("saving hybrid identity: %w", err)
	}

	// Also save public identity for compatibility with P2P protocol
	pub := &crypto.PublicIdentity{
		Name:       name,
		SigningPub: identity.SigningPublicKey(), // ML-DSA public key
		MLKEMPub:   identity.MLKEMPublicKey(),   // ML-KEM public key
		CreatedAt:  time.Now().UTC(),
	}

	pubData, err := pub.Serialize()
	if err != nil {
		return fmt.Errorf("serializing public identity: %w", err)
	}

	if err := os.WriteFile(paths.IdentityPubFile, pubData, 0644); err != nil {
		return fmt.Errorf("saving public identity: %w", err)
	}

	// Cache PIN for session
	crypto.CachePIN(pinStr, 30*time.Minute)

	fmt.Println()
	fmt.Println("Hybrid identity created successfully!")
	fmt.Println()
	fmt.Printf("  Name:        %s\n", name)
	fmt.Printf("  Fingerprint: %s\n", identity.Fingerprint())
	fmt.Printf("  Storage:     Hardware (YubiKey + PQC hybrid)\n")
	fmt.Printf("  YubiKey:     %d\n", identity.Serial())
	fmt.Printf("  Identity:    %s\n", hybridPath)
	fmt.Printf("  Public key:  %s\n", paths.IdentityPubFile)
	fmt.Println()
	fmt.Println("Your identity is protected by your YubiKey.")
	fmt.Println("Touch is required for signing and decryption operations.")
	fmt.Println()
	fmt.Println("Security features:")
	fmt.Println("  • P-256 key cannot be extracted from YubiKey")
	fmt.Println("  • ML-DSA-65 provides post-quantum signature security")
	fmt.Println("  • ML-KEM-768 provides post-quantum encryption security")
	fmt.Println("  • PQC keys are encrypted with YubiKey-derived secret")
	fmt.Println()
	fmt.Println("Next steps:")
	fmt.Println("  1. Start the daemon: envctl daemon start")
	fmt.Println("  2. Create a project: envctl project create <name>")
	fmt.Println("     Or join a project: envctl project join <pubkey> --project <name>")

	return nil
}

func defaultIdentityName() (string, error) {
	u, err := user.Current()
	if err != nil {
		return "", err
	}

	hostname, err := os.Hostname()
	if err != nil {
		hostname = "local"
	}

	// Truncate hostname if needed
	if len(hostname) > 20 {
		hostname = hostname[:20]
	}

	// Clean up hostname (remove domain parts)
	if idx := strings.Index(hostname, "."); idx > 0 {
		hostname = hostname[:idx]
	}

	return fmt.Sprintf("%s-%s", u.Username, hostname), nil
}

// Export command

var identityExportCmd = &cobra.Command{
	Use:   "export",
	Short: "Export identity for backup",
	Long: `Export your identity as a paper backup using recovery words.

The recovery words can be used to restore your identity on a new machine.
Store them securely - anyone with these words can become you.

Examples:
  envctl identity export --paper
  envctl identity export --paper --plain
  envctl identity export --paper --qr
  envctl identity export --paper --output backup.txt`,
	RunE: runIdentityExport,
}

func init() {
	identityExportCmd.Flags().Bool("paper", false, "export as paper backup (mnemonic words)")
	identityExportCmd.Flags().Bool("plain", false, "plain text output (no box)")
	identityExportCmd.Flags().Bool("qr", false, "display as QR code")
	identityExportCmd.Flags().String("output", "", "write to file instead of stdout")
	identityCmd.AddCommand(identityExportCmd)
}

func runIdentityExport(cmd *cobra.Command, args []string) error {
	paper, _ := cmd.Flags().GetBool("paper")
	plain, _ := cmd.Flags().GetBool("plain")
	qrFlag, _ := cmd.Flags().GetBool("qr")
	output, _ := cmd.Flags().GetString("output")

	if !paper {
		return fmt.Errorf("only --paper export is currently supported")
	}

	paths, err := config.GetPaths()
	if err != nil {
		return fmt.Errorf("get paths: %w", err)
	}

	// Check if identity exists
	if !paths.IdentityExists() {
		return fmt.Errorf("no identity found. Create one with: envctl init")
	}

	// Prompt for passphrase
	passphrase, err := tui.ReadPassword("Passphrase: ")
	if err != nil {
		return fmt.Errorf("read passphrase: %w", err)
	}
	defer crypto.ZeroBytes(passphrase)

	// Load identity
	identity, err := crypto.LoadEncrypted(paths.IdentityFile, passphrase)
	if err != nil {
		return fmt.Errorf("loading identity: %w", err)
	}

	// Convert to entropy
	entropy, err := identity.ToEntropy()
	if err != nil {
		return fmt.Errorf("serializing identity: %w", err)
	}
	defer crypto.ZeroBytes(entropy)

	// Encode as mnemonic
	mnemonic, err := crypto.EntropyToMnemonic(entropy)
	if err != nil {
		return fmt.Errorf("encoding mnemonic: %w", err)
	}

	words := crypto.MnemonicToWords(mnemonic)

	// Format output
	var result string

	if qrFlag {
		result, err = generateQRCode(mnemonic)
		if err != nil {
			return fmt.Errorf("generating QR code: %w", err)
		}
	} else if plain {
		result = fmt.Sprintf("Recovery words: %s\n", mnemonic)
	} else {
		result = formatPaperBackup(identity, words)
	}

	// Output
	if output != "" {
		if err := os.WriteFile(output, []byte(result), 0600); err != nil {
			return fmt.Errorf("writing file: %w", err)
		}
		fmt.Printf("Backup written to %s\n", output)
		fmt.Println("Store this file securely and delete after printing.")
	} else {
		fmt.Print(result)
	}

	return nil
}

func formatPaperBackup(identity *crypto.Identity, words []string) string {
	fingerprint := identity.Fingerprint()
	created := identity.CreatedAt.Format("2006-01-02")

	var sb strings.Builder

	sb.WriteString("\n")
	sb.WriteString("+==============================================================+\n")
	sb.WriteString("|                    ENVSHARE IDENTITY BACKUP                  |\n")
	sb.WriteString("|                                                              |\n")
	sb.WriteString(fmt.Sprintf("|  Name:        %-43s |\n", identity.Name))
	sb.WriteString(fmt.Sprintf("|  Fingerprint: %-43s |\n", fingerprint))
	sb.WriteString(fmt.Sprintf("|  Created:     %-43s |\n", created))
	sb.WriteString("|                                                              |\n")
	sb.WriteString("|  Recovery Words (24):                                        |\n")
	sb.WriteString("|                                                              |\n")

	// Format words in 4 columns, 6 rows
	for row := 0; row < 6; row++ {
		sb.WriteString("|  ")
		for col := 0; col < 4; col++ {
			idx := row + (col * 6)
			if idx < len(words) {
				num := idx + 1
				word := words[idx]
				sb.WriteString(fmt.Sprintf("%2d. %-10s", num, word))
			}
		}
		sb.WriteString(" |\n")
	}

	sb.WriteString("|                                                              |\n")
	sb.WriteString("|  WARNING: Store this in a secure location.                   |\n")
	sb.WriteString("|  Anyone with these words can recover your identity.          |\n")
	sb.WriteString("+==============================================================+\n")
	sb.WriteString("\nPrint this page and store securely.\n")

	return sb.String()
}

func generateQRCode(data string) (string, error) {
	qr, err := qrcode.New(data, qrcode.Medium)
	if err != nil {
		return "", err
	}
	return qr.ToSmallString(false), nil
}

// Recover command

var identityRecoverCmd = &cobra.Command{
	Use:   "recover",
	Short: "Recover identity from paper backup",
	Long: `Recover your identity using the 24 recovery words from a paper backup.

You will be prompted to enter the words and set a new passphrase.

Examples:
  envctl identity recover
  envctl identity recover --words "apple banana cherry ..."
  envctl identity recover --name myname --words "..."`,
	RunE: runIdentityRecover,
}

func init() {
	identityRecoverCmd.Flags().String("words", "", "recovery words (space-separated)")
	identityRecoverCmd.Flags().String("name", "", "identity name (required)")
	identityCmd.AddCommand(identityRecoverCmd)
}

func runIdentityRecover(cmd *cobra.Command, args []string) error {
	wordsFlag, _ := cmd.Flags().GetString("words")
	nameFlag, _ := cmd.Flags().GetString("name")

	paths, err := config.GetPaths()
	if err != nil {
		return fmt.Errorf("get paths: %w", err)
	}

	// Check if identity already exists
	if paths.IdentityExists() {
		return fmt.Errorf("identity already exists at %s\nDelete it first if you want to recover a different identity", paths.IdentityFile)
	}

	// Get recovery words
	var mnemonic string

	if wordsFlag != "" {
		mnemonic = wordsFlag
	} else {
		fmt.Println("Enter recovery words (24 words, space-separated):")
		fmt.Print("> ")

		line, err := tui.ReadLine("")
		if err != nil {
			return fmt.Errorf("reading input: %w", err)
		}

		mnemonic = strings.TrimSpace(line)
	}

	// Validate mnemonic
	if err := crypto.ValidateMnemonic(mnemonic); err != nil {
		return fmt.Errorf("invalid recovery words: %w", err)
	}

	// Decode mnemonic to entropy
	entropy, err := crypto.MnemonicToEntropy(mnemonic)
	if err != nil {
		return fmt.Errorf("decoding recovery words: %w", err)
	}
	defer crypto.ZeroBytes(entropy)

	// Get name
	name := nameFlag
	if name == "" {
		name, err = tui.ReadLine("Enter identity name: ")
		if err != nil {
			return fmt.Errorf("reading name: %w", err)
		}
		name = strings.TrimSpace(name)
	}

	if name == "" {
		return fmt.Errorf("identity name is required")
	}

	if len(name) > 64 {
		return fmt.Errorf("identity name too long (max 64 characters)")
	}

	// Reconstruct identity
	identity, err := crypto.IdentityFromEntropy(entropy, name)
	if err != nil {
		return fmt.Errorf("reconstructing identity: %w", err)
	}

	fmt.Println()
	fmt.Println("Recovered identity:")
	fmt.Printf("  Name:        %s\n", identity.Name)
	fmt.Printf("  Fingerprint: %s\n", identity.Fingerprint())
	fmt.Println()

	// Get new passphrase
	fmt.Println("Set a passphrase to encrypt your recovered identity.")
	passphrase, err := tui.ReadPasswordConfirm("Passphrase: ", "Confirm passphrase: ")
	if err != nil {
		return err
	}

	if len(passphrase) < 8 {
		return fmt.Errorf("passphrase must be at least 8 characters")
	}

	// Ensure directories exist
	if err := paths.EnsureDirectories(); err != nil {
		return fmt.Errorf("create directories: %w", err)
	}

	// Save encrypted identity
	fmt.Print("Saving encrypted identity...")

	if err := identity.SaveEncrypted(paths.IdentityFile, passphrase); err != nil {
		fmt.Println(" failed")
		return fmt.Errorf("save identity: %w", err)
	}

	fmt.Println(" done")

	// Save public identity
	fmt.Print("Saving public key...")

	if err := identity.SavePublic(paths.IdentityPubFile); err != nil {
		fmt.Println(" failed")
		return fmt.Errorf("save public key: %w", err)
	}

	fmt.Println(" done")

	// Clear passphrase from memory
	crypto.ZeroBytes(passphrase)

	fmt.Println()
	fmt.Println("Identity recovered successfully!")
	fmt.Printf("  Identity file: %s\n", paths.IdentityFile)
	fmt.Printf("  Public key file: %s\n", paths.IdentityPubFile)

	return nil
}

// Migrate command

var identityMigrateCmd = &cobra.Command{
	Use:   "migrate",
	Short: "Migrate identity to YubiKey",
	Long: `Migrate your software identity to a YubiKey for hardware-backed security.

This imports your existing signing key onto the YubiKey and generates a new
X25519 key for encryption (since ML-KEM is not supported on YubiKey).

Note: The key exchange key will be regenerated, so you may need to re-receive
secrets from peers after migration.

Examples:
  envctl identity migrate --yubikey`,
	RunE: runIdentityMigrate,
}

func init() {
	identityMigrateCmd.Flags().Bool("yubikey", false, "migrate to YubiKey")
	identityCmd.AddCommand(identityMigrateCmd)
}

func runIdentityMigrate(cmd *cobra.Command, args []string) error {
	toYubiKey, _ := cmd.Flags().GetBool("yubikey")

	if !toYubiKey {
		return fmt.Errorf("specify --yubikey to migrate to hardware key")
	}

	paths, err := config.GetPaths()
	if err != nil {
		return fmt.Errorf("get paths: %w", err)
	}

	// Check if software identity exists
	if !paths.SoftwareIdentityExists() {
		return fmt.Errorf("no software identity found at %s", paths.IdentityFile)
	}

	// Check if YubiKey identity already exists
	if paths.YubiKeyIdentityExists() {
		return fmt.Errorf("YubiKey identity already configured. Remove %s first", paths.IdentityConfigFile)
	}

	// Check if YubiKey support is available
	if !crypto.HasYubiKeySupport() {
		return fmt.Errorf("YubiKey support not available. Ensure pcscd is running")
	}

	fmt.Println("This will move your identity to YubiKey.")
	fmt.Println("The software key will be deleted after migration.")
	fmt.Println()
	fmt.Println("Note: The key exchange key will be regenerated on the YubiKey.")
	fmt.Println("You may need to re-receive secrets from peers after migration.")
	fmt.Println()

	ok, err := tui.Confirm("Continue?", false)
	if err != nil {
		return err
	}
	if !ok {
		fmt.Println("Migration cancelled.")
		return nil
	}

	// Load existing software identity
	passphrase, err := tui.ReadPassword("Enter passphrase for existing identity: ")
	if err != nil {
		return fmt.Errorf("read passphrase: %w", err)
	}

	identity, err := crypto.LoadEncrypted(paths.IdentityFile, passphrase)
	if err != nil {
		return fmt.Errorf("loading identity: %w", err)
	}

	crypto.ZeroBytes(passphrase)

	// Wait for YubiKey
	fmt.Println()
	fmt.Println("Insert YubiKey and press Enter...")
	if _, err := tui.ReadLine(""); err != nil {
		return err
	}

	// Find YubiKey
	keys, err := crypto.FindYubiKeys()
	if err != nil {
		return fmt.Errorf("finding YubiKeys: %w", err)
	}

	if len(keys) == 0 {
		return fmt.Errorf("no YubiKey found")
	}

	yk := keys[0]
	defer yk.Close()

	for i := 1; i < len(keys); i++ {
		keys[i].Close()
	}

	fmt.Printf("YubiKey found (serial: %d)\n", yk.Serial())
	fmt.Println()

	// Prompt for PIN
	pin, err := tui.ReadPassword("Enter PIV PIN: ")
	if err != nil {
		return fmt.Errorf("read PIN: %w", err)
	}

	pinStr := string(pin)

	// Extract signing key seed and create Ed25519 private key
	entropy, err := identity.ToEntropy()
	if err != nil {
		return fmt.Errorf("extracting key: %w", err)
	}

	signingKey := ed25519.NewKeyFromSeed(entropy)
	crypto.ZeroBytes(entropy)

	// Import signing key to YubiKey
	fmt.Println()
	if err := yk.ImportSigningKey(signingKey, func(msg string) {
		fmt.Print(msg)
	}); err != nil {
		return fmt.Errorf("importing signing key: %w", err)
	}
	fmt.Println(" done")

	// Generate new P-256 ECDH key on YubiKey
	ecdhPub, err := yk.GenerateECDHKey(func(msg string) {
		fmt.Print(msg)
	})
	if err != nil {
		return fmt.Errorf("generating ECDH key: %w", err)
	}
	fmt.Println(" done")

	// Save identity config
	cfg := &config.YubiKeyIdentityConfig{
		Type:       config.IdentityTypeYubiKey,
		Name:       identity.Name,
		Serial:     yk.Serial(),
		SigningPub: identity.SigningPublicKey(),
		ECDHPub:    ecdhPub,
		CreatedAt:  time.Now().UTC(),
	}

	if err := cfg.Save(); err != nil {
		return fmt.Errorf("saving identity config: %w", err)
	}

	// Delete software identity
	fmt.Print("Removing software identity...")
	if err := os.Remove(paths.IdentityFile); err != nil {
		fmt.Printf(" warning: %v\n", err)
	} else {
		fmt.Println(" done")
	}

	// Cache PIN
	crypto.CachePIN(pinStr, 30*time.Minute)

	fmt.Println()
	fmt.Println("Identity migrated to YubiKey!")
	fmt.Println()
	fmt.Printf("  Name:        %s\n", identity.Name)
	fmt.Printf("  Fingerprint: %s\n", identity.Fingerprint())
	fmt.Printf("  Storage:     YubiKey (serial: %d)\n", yk.Serial())
	fmt.Println()
	fmt.Println("Touch is required for each signing/decryption operation.")

	return nil
}

// Pubkey command

var identityPubkeyCmd = &cobra.Command{
	Use:   "pubkey",
	Short: "Output public key for invites",
	Long: `Output your signing public key in hex format, ready to share for project invites.

This is the key that others need when running:
  envctl project invite <name> <pubkey>

Examples:
  envctl identity pubkey
  envctl identity pubkey | pbcopy   # Copy to clipboard on macOS`,
	RunE: runIdentityPubkey,
}

func init() {
	identityCmd.AddCommand(identityPubkeyCmd)
}

func runIdentityPubkey(cmd *cobra.Command, args []string) error {
	paths, err := config.GetPaths()
	if err != nil {
		return fmt.Errorf("get paths: %w", err)
	}

	// Check for YubiKey identity first
	if paths.YubiKeyIdentityExists() {
		cfg, err := config.LoadYubiKeyIdentityConfig()
		if err != nil {
			return fmt.Errorf("loading YubiKey identity: %w", err)
		}
		fmt.Printf("%x\n", cfg.SigningPub)
		return nil
	}

	// Check for software identity
	if !paths.SoftwareIdentityExists() {
		return fmt.Errorf("no identity found. Create one with: envctl init")
	}

	pub, err := crypto.LoadPublic(paths.IdentityPubFile)
	if err != nil {
		return fmt.Errorf("loading public key: %w", err)
	}

	fmt.Printf("%x\n", pub.SigningPub)
	return nil
}

// Keys command

var identityKeysCmd = &cobra.Command{
	Use:   "keys",
	Short: "List configured keys",
	Long: `List all configured identity keys.

Shows whether you have a software identity, YubiKey identity, or both.

Examples:
  envctl identity keys`,
	RunE: runIdentityKeys,
}

func init() {
	identityCmd.AddCommand(identityKeysCmd)
}

func runIdentityKeys(cmd *cobra.Command, args []string) error {
	paths, err := config.GetPaths()
	if err != nil {
		return fmt.Errorf("get paths: %w", err)
	}

	fmt.Println("Configured keys:")
	fmt.Println()

	found := false

	// Check for software identity
	if paths.SoftwareIdentityExists() {
		found = true
		pub, err := crypto.LoadPublic(paths.IdentityPubFile)
		if err != nil {
			fmt.Printf("  1. Software identity (error loading: %v)\n", err)
		} else {
			fmt.Printf("  1. Software identity\n")
			fmt.Printf("     Name:        %s\n", pub.Name)
			fmt.Printf("     Fingerprint: %s\n", pub.Fingerprint())
			fmt.Printf("     File:        %s\n", paths.IdentityFile)
		}
		fmt.Println()
	}

	// Check for YubiKey identity
	if paths.YubiKeyIdentityExists() {
		found = true
		cfg, err := config.LoadYubiKeyIdentityConfig()
		if err != nil {
			fmt.Printf("  2. YubiKey identity (error loading: %v)\n", err)
		} else {
			fmt.Printf("  2. YubiKey identity\n")
			fmt.Printf("     Name:        %s\n", cfg.Name)
			fmt.Printf("     Serial:      %d\n", cfg.Serial)
			fmt.Printf("     Fingerprint: %s\n", crypto.PublicKeyFingerprint(cfg.SigningPub))
			fmt.Printf("     Config:      %s\n", paths.IdentityConfigFile)

			// Check if YubiKey is currently connected
			if crypto.HasYubiKeySupport() {
				yk, err := crypto.OpenYubiKey(cfg.Serial)
				if err != nil {
					fmt.Printf("     Status:      Not connected\n")
				} else {
					fmt.Printf("     Status:      Connected\n")
					yk.Close()
				}
			}
		}
		fmt.Println()
	}

	if !found {
		fmt.Println("  No identity configured.")
		fmt.Println()
		fmt.Println("Create one with:")
		fmt.Println("  envctl init              # Software identity")
		fmt.Println("  envctl init --yubikey    # YubiKey identity")
	}

	return nil
}

// Rotate-key command

var identityRotateKeyCmd = &cobra.Command{
	Use:   "rotate-key",
	Short: "Rotate your identity keys",
	Long: `Generate a new key pair and re-encrypt all your secrets.

This operation:
1. Generates a new Ed25519 + ML-KEM key pair
2. Decrypts all secrets with your current key
3. Re-encrypts them with the new key
4. Atomically swaps the keys
5. Announces your new public key to team members

Your old key is backed up and securely deleted after 7 days.

Examples:
  envctl identity rotate-key
  envctl identity rotate-key --same-passphrase
  envctl identity rotate-key --local-only`,
	RunE: runIdentityRotateKey,
}

func init() {
	identityRotateKeyCmd.Flags().Bool("same-passphrase", false, "keep the same passphrase")
	identityRotateKeyCmd.Flags().Bool("local-only", false, "skip team announcement")
	identityRotateKeyCmd.Flags().Bool("force", false, "skip confirmation prompt")
	identityRotateKeyCmd.Flags().StringSlice("search-dirs", nil, "directories to search for secrets (default: current directory)")
	identityCmd.AddCommand(identityRotateKeyCmd)
}

func runIdentityRotateKey(cmd *cobra.Command, args []string) error {
	samePassphrase, _ := cmd.Flags().GetBool("same-passphrase")
	localOnly, _ := cmd.Flags().GetBool("local-only")
	force, _ := cmd.Flags().GetBool("force")
	searchDirs, _ := cmd.Flags().GetStringSlice("search-dirs")

	paths, err := config.GetPaths()
	if err != nil {
		return fmt.Errorf("get paths: %w", err)
	}

	// Check if software identity exists
	if !paths.SoftwareIdentityExists() {
		if paths.YubiKeyIdentityExists() {
			return fmt.Errorf("key rotation is not supported for YubiKey identities")
		}
		return fmt.Errorf("no identity found. Create one with: envctl init")
	}

	// Confirmation
	if !force {
		fmt.Println("This will generate a new key pair and re-encrypt all your secrets.")
		if !localOnly {
			fmt.Println("Your team will be notified of your new public key.")
		}
		fmt.Println()
		ok, err := tui.Confirm("Continue?", false)
		if err != nil {
			return err
		}
		if !ok {
			fmt.Println("Rotation cancelled.")
			return nil
		}
	}

	// Get current passphrase
	currentPassphrase, err := tui.ReadPassword("Enter current passphrase: ")
	if err != nil {
		return err
	}

	// Load current identity
	identity, err := crypto.LoadEncrypted(paths.IdentityFile, currentPassphrase)
	if err != nil {
		crypto.ZeroBytes(currentPassphrase)
		return fmt.Errorf("invalid passphrase: %w", err)
	}

	// Get new passphrase
	var newPassphrase []byte
	if !samePassphrase {
		fmt.Println()
		fmt.Println("Enter new passphrase (or press Enter to keep same):")
		newPassphrase, err = tui.ReadPassword("New passphrase: ")
		if err != nil {
			crypto.ZeroBytes(currentPassphrase)
			return err
		}

		if len(newPassphrase) > 0 {
			confirm, err := tui.ReadPassword("Confirm new passphrase: ")
			if err != nil {
				crypto.ZeroBytes(currentPassphrase)
				crypto.ZeroBytes(newPassphrase)
				return err
			}

			if string(newPassphrase) != string(confirm) {
				crypto.ZeroBytes(currentPassphrase)
				crypto.ZeroBytes(newPassphrase)
				crypto.ZeroBytes(confirm)
				return fmt.Errorf("passphrases do not match")
			}
			crypto.ZeroBytes(confirm)

			if len(newPassphrase) < 8 {
				crypto.ZeroBytes(currentPassphrase)
				crypto.ZeroBytes(newPassphrase)
				return fmt.Errorf("passphrase must be at least 8 characters")
			}
		} else {
			newPassphrase = nil // Will use current passphrase
		}
	}

	// Default search directories
	if len(searchDirs) == 0 {
		cwd, err := os.Getwd()
		if err != nil {
			cwd = "."
		}
		searchDirs = []string{cwd}
	}

	fmt.Println()
	fmt.Println("Rotating key...")

	// Perform rotation
	opts := crypto.RotateKeyOptions{
		IdentityFile:    paths.IdentityFile,
		IdentityPubFile: paths.IdentityPubFile,
		NewPassphrase:   newPassphrase,
		LocalOnly:       localOnly,
		SecretsDirs:     searchDirs,
	}

	rotation, err := crypto.RotateKey(identity, currentPassphrase, opts)
	crypto.ZeroBytes(currentPassphrase)

	if err != nil {
		return fmt.Errorf("rotation failed: %w", err)
	}

	fmt.Println("  ✓ Generated new key pair")
	fmt.Printf("  ✓ Re-encrypted %d secrets\n", rotation.SecretCount())
	fmt.Println("  ✓ Committed changes")

	// Announce to team
	if !localOnly {
		if err := announceRotation(rotation); err != nil {
			fmt.Printf("  ⚠ Failed to announce to team: %v\n", err)
			fmt.Println("    Your local rotation succeeded. Team sync will retry.")
		} else {
			fmt.Println("  ✓ Announced to team")
		}
	}

	fmt.Println()
	fmt.Println("Done.")
	fmt.Printf("  Old fingerprint: %s\n", rotation.OldIdentity.Fingerprint())
	fmt.Printf("  New fingerprint: %s\n", rotation.NewIdentity.Fingerprint())
	fmt.Println()
	fmt.Printf("Old key backed up to %s.bak\n", paths.IdentityFile)
	fmt.Println("(will be securely deleted in 7 days)")

	return nil
}

func announceRotation(rotation *crypto.KeyRotation) error {
	ann, err := rotation.CreateAnnouncement()
	if err != nil {
		return err
	}

	// Connect to daemon and broadcast
	c, err := client.Connect()
	if err != nil {
		return fmt.Errorf("daemon not running: %w", err)
	}
	defer c.Close()

	return c.BroadcastKeyRotation(ann)
}
