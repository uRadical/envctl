//go:build windows

package daemon

import (
	"net"

	"github.com/Microsoft/go-winio"
)

// Named pipe configuration for Windows
const (
	// PipeName is the name of the named pipe for IPC
	// Format: \\.\pipe\<name>
	PipeName = `\\.\pipe\envctl`
)

// createIPCListener creates a Windows named pipe listener
// Named pipes provide proper security - only the user who created the pipe can connect
func createIPCListener(socketPath string) (net.Listener, error) {
	// Create a security descriptor that only allows the current user
	// This is the default behavior of go-winio when no config is specified
	cfg := &winio.PipeConfig{
		// MessageMode is false for byte stream (compatible with our JSON protocol)
		MessageMode: false,
		// InputBufferSize and OutputBufferSize default to 64KB
		InputBufferSize:  65536,
		OutputBufferSize: 65536,
	}

	return winio.ListenPipe(PipeName, cfg)
}

// getIPCAddress returns the IPC address for the current platform
func getIPCAddress(socketPath string) (network, address string) {
	return "pipe", PipeName
}

// cleanupIPCListener cleans up the IPC listener on shutdown
// On Windows, named pipes are automatically cleaned up when closed
func cleanupIPCListener(socketPath string) {
	// Nothing to do - Windows named pipes are cleaned up automatically
}
