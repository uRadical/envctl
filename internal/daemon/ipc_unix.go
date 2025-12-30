//go:build !windows

package daemon

import (
	"net"
	"os"
)

// createIPCListener creates a Unix domain socket listener
func createIPCListener(socketPath string) (net.Listener, error) {
	// Remove stale socket file
	os.Remove(socketPath)

	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		return nil, err
	}

	// Set socket permissions to owner only (0600)
	if err := os.Chmod(socketPath, 0600); err != nil {
		listener.Close()
		return nil, err
	}

	return listener, nil
}

// getIPCAddress returns the IPC address for the current platform
func getIPCAddress(socketPath string) (network, address string) {
	return "unix", socketPath
}

// cleanupIPCListener cleans up the IPC listener on shutdown
func cleanupIPCListener(socketPath string) {
	os.Remove(socketPath)
}
