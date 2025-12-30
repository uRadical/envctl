package cli

import (
	"encoding/json"
	"fmt"

	"github.com/spf13/cobra"
	"uradical.io/go/envctl/internal/audit"
	"uradical.io/go/envctl/internal/client"
	"uradical.io/go/envctl/internal/config"
	"uradical.io/go/envctl/internal/crypto"
	"uradical.io/go/envctl/internal/tui"
)

func init() {
	rootCmd.AddCommand(verifyCmd)
}

var verifyCmd = &cobra.Command{
	Use:   "verify <peer>",
	Short: "Verify a peer's identity",
	Long: `Verify a peer's identity using Short Authentication Strings (SAS).

This command displays a series of emojis that both you and your peer
should see. Compare them out-of-band (e.g., video call, in person)
to verify there's no man-in-the-middle attack.

Example:
  envctl verify alice`,
	Args: cobra.ExactArgs(1),
	RunE: runVerify,
}

func runVerify(cmd *cobra.Command, args []string) error {
	peerName := args[0]

	// Check daemon is running
	if err := client.RequireDaemon(); err != nil {
		return fmt.Errorf("daemon not running. Start with: envctl daemon start")
	}

	paths, err := config.GetPaths()
	if err != nil {
		return fmt.Errorf("get paths: %w", err)
	}

	// Load our public identity
	ourPub, err := crypto.LoadPublic(paths.IdentityPubFile)
	if err != nil {
		return fmt.Errorf("load identity: %w", err)
	}

	c, err := client.Connect()
	if err != nil {
		return fmt.Errorf("connect to daemon: %w", err)
	}
	defer c.Close()

	fmt.Printf("Verifying peer: %s\n\n", peerName)
	fmt.Println("Looking up peer...")

	// Get peer's public key from daemon
	var peerInfo struct {
		Name        string   `json:"name"`
		Fingerprint string   `json:"fingerprint"`
		Connected   bool     `json:"connected"`
		Teams       []string `json:"teams"`
		Pubkey      []byte   `json:"pubkey"`
		MLKEMPub    []byte   `json:"mlkem_pub"`
	}

	result, err := c.Call("peers.info", map[string]string{"name": peerName})
	if err != nil {
		fmt.Println()
		fmt.Printf("Peer '%s' not found in connected peers.\n", peerName)
		fmt.Println("Make sure the peer is online and connected.")
		fmt.Println()
		fmt.Println("To see connected peers, run: envctl peers list")
		return nil
	}

	if err := json.Unmarshal(result, &peerInfo); err != nil {
		return fmt.Errorf("parse peer info: %w", err)
	}

	if len(peerInfo.Pubkey) == 0 {
		return fmt.Errorf("peer public key not available")
	}

	// Create a PublicIdentity from the peer info
	peerPub := &crypto.PublicIdentity{
		Name:       peerInfo.Name,
		SigningPub: peerInfo.Pubkey,
		MLKEMPub:   peerInfo.MLKEMPub,
	}

	// Perform verification
	return verifyWithPeer(ourPub, peerPub)
}

// verifyWithPeer performs the actual SAS verification
func verifyWithPeer(ourPub *crypto.PublicIdentity, peerPub *crypto.PublicIdentity) error {
	sas := crypto.ComputeSAS(ourPub.SigningPub, peerPub.SigningPub)

	fmt.Printf("Compare this code with %s:\n\n", peerPub.Name)
	fmt.Printf("  %s\n", sas.String())
	fmt.Printf("  (%s)\n", sas.WordString())
	fmt.Println()

	confirmed, err := tui.Confirm("Does it match?", false)
	if err != nil {
		return fmt.Errorf("read confirmation: %w", err)
	}

	if !confirmed {
		fmt.Println()
		fmt.Println("Verification FAILED!")
		fmt.Println("This could indicate a man-in-the-middle attack.")
		fmt.Println("Do NOT share sensitive data with this peer until verified.")
		return nil
	}

	fmt.Println()
	fmt.Println("Peer verified successfully!")

	// Log the verification
	paths, err := config.GetPaths()
	if err == nil {
		log, err := audit.Open(paths.AuditLogFile)
		if err == nil {
			log.LogVerified(peerPub.Name, peerPub.SigningPub, "sas")
		}
	}

	return nil
}
