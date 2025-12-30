package cli

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var (
	version    = "dev"
	cfgFile    string
	langFlag   string
	verboseLog bool
)

func SetVersion(v string) {
	version = v
}

// RootCmd is the root command, exported for documentation generation
var RootCmd = &cobra.Command{
	Use:   "envctl",
	Short: "Zero-infrastructure secrets management for dev projects",
	Long: `envctl - Zero-infrastructure secrets management for dev projects

Encrypted, peer-to-peer, no cloud. Control environment variables securely
with your project using post-quantum cryptography and cryptographic project
membership verification.`,
	SilenceUsage:  true,
	SilenceErrors: true,
}

// For internal use, keep an alias
var rootCmd = RootCmd

func Execute() error {
	return RootCmd.Execute()
}

func init() {
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default $HOME/.config/envctl/config.toml)")
	rootCmd.PersistentFlags().StringVar(&langFlag, "lang", "", "language for messages (default: auto-detect)")
	rootCmd.PersistentFlags().BoolVarP(&verboseLog, "verbose", "v", false, "verbose output")
}

func exitError(msg string, args ...any) {
	fmt.Fprintf(os.Stderr, "Error: "+msg+"\n", args...)
	os.Exit(1)
}
