package cli

import (
	"fmt"
	"runtime"
	"runtime/debug"

	"github.com/spf13/cobra"
)

var (
	// Set via ldflags
	commit    = "unknown"
	buildDate = "unknown"

	// Flags
	versionFull bool
)

// SetBuildInfo sets build information from ldflags
func SetBuildInfo(c, d string) {
	commit = c
	buildDate = d
}

func init() {
	rootCmd.AddCommand(versionCmd)
	versionCmd.Flags().BoolVar(&versionFull, "full", false, "print detailed version information")
}

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print version information",
	Long:  `Print version information. Use --full for detailed output including commit, build date, Go version, and dependencies.`,
	Run:   runVersion,
}

func runVersion(cmd *cobra.Command, args []string) {
	fmt.Printf("envctl version %s\n", version)

	if versionFull {
		fmt.Println()
		fmt.Printf("  Commit:     %s\n", getCommit())
		fmt.Printf("  Built:      %s\n", getBuildDate())
		fmt.Printf("  Go version: %s\n", runtime.Version())
		fmt.Printf("  OS/Arch:    %s/%s\n", runtime.GOOS, runtime.GOARCH)

		// Print module info if available
		if info, ok := debug.ReadBuildInfo(); ok {
			fmt.Println()
			fmt.Println("  Dependencies:")
			for _, dep := range info.Deps {
				if dep.Replace != nil {
					fmt.Printf("    %s => %s %s\n", dep.Path, dep.Replace.Path, dep.Replace.Version)
				} else {
					fmt.Printf("    %s %s\n", dep.Path, dep.Version)
				}
			}
		}
	}
}

func getCommit() string {
	if commit != "unknown" {
		return commit
	}

	// Try to get from build info
	if info, ok := debug.ReadBuildInfo(); ok {
		for _, setting := range info.Settings {
			if setting.Key == "vcs.revision" {
				if len(setting.Value) > 8 {
					return setting.Value[:8]
				}
				return setting.Value
			}
		}
	}
	return "unknown"
}

func getBuildDate() string {
	if buildDate != "unknown" {
		return buildDate
	}

	// Try to get from build info
	if info, ok := debug.ReadBuildInfo(); ok {
		for _, setting := range info.Settings {
			if setting.Key == "vcs.time" {
				return setting.Value
			}
		}
	}
	return "unknown"
}
