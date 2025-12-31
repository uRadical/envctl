package cli

import (
	"fmt"
	"os/exec"
	"runtime"

	"github.com/spf13/cobra"
	"envctl.dev/go/envctl/internal/client"
)

var uiNoOpen bool

func init() {
	rootCmd.AddCommand(uiCmd)

	uiCmd.Flags().BoolVar(&uiNoOpen, "no-open", false, "don't open browser, just print URL")
}

var uiCmd = &cobra.Command{
	Use:   "ui",
	Short: "Open the web UI",
	Long: `Open the envctl web UI in your default browser.

The web UI provides a visual interface for:
- Viewing project members and their access
- Managing incoming requests
- Viewing connected peers
- Reviewing the audit log`,
	RunE: runUI,
}

func runUI(cmd *cobra.Command, args []string) error {
	c, err := client.Connect()
	if err != nil {
		return fmt.Errorf("daemon not running: %w", err)
	}
	defer c.Close()

	// Get daemon status to find web port
	status, err := c.Status()
	if err != nil {
		return fmt.Errorf("get status: %w", err)
	}

	// Get port from daemon config
	var config struct {
		WebPort int `json:"web_port"`
	}
	port := 7835 // default
	if err := c.CallResult("config.get", nil, &config); err == nil {
		port = config.WebPort
	}

	url := fmt.Sprintf("http://localhost:%d", port)

	if uiNoOpen {
		fmt.Printf("Web UI: %s\n", url)
		fmt.Printf("Identity: %s\n", status.Identity)
		return nil
	}

	fmt.Printf("Opening %s in browser...\n", url)

	// Open browser
	if err := openBrowser(url); err != nil {
		fmt.Printf("Failed to open browser: %v\n", err)
		fmt.Printf("Open manually: %s\n", url)
	}

	return nil
}

// openBrowser opens the specified URL in the default browser
func openBrowser(url string) error {
	var cmd *exec.Cmd

	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", url)
	case "linux":
		// Try xdg-open first, then common browsers
		if _, err := exec.LookPath("xdg-open"); err == nil {
			cmd = exec.Command("xdg-open", url)
		} else if _, err := exec.LookPath("google-chrome"); err == nil {
			cmd = exec.Command("google-chrome", url)
		} else if _, err := exec.LookPath("firefox"); err == nil {
			cmd = exec.Command("firefox", url)
		} else {
			return fmt.Errorf("no browser found")
		}
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	default:
		return fmt.Errorf("unsupported platform: %s", runtime.GOOS)
	}

	return cmd.Start()
}
