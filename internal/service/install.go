package service

import (
	"time"
)

// ServiceStatus represents the status of the installed service
type ServiceStatus struct {
	Installed bool          `json:"installed"`
	Running   bool          `json:"running"`
	PID       int           `json:"pid,omitempty"`
	Uptime    time.Duration `json:"uptime,omitempty"`
	Error     string        `json:"error,omitempty"`
}

// Installer interface for platform-specific service installation
type Installer interface {
	// Install installs the service
	Install() error

	// Uninstall removes the service
	Uninstall() error

	// IsInstalled checks if the service is installed
	IsInstalled() bool

	// Start starts the service
	Start() error

	// Stop stops the service
	Stop() error

	// Status returns the service status
	Status() (ServiceStatus, error)

	// Enable enables the service to start on boot
	Enable() error

	// Disable disables the service from starting on boot
	Disable() error

	// Logs returns recent log output
	Logs(lines int) (string, error)
}

// ErrNotInstalled is returned when the service is not installed
type ErrNotInstalled struct{}

func (e ErrNotInstalled) Error() string {
	return "service not installed"
}

// ErrAlreadyInstalled is returned when trying to install an already installed service
type ErrAlreadyInstalled struct{}

func (e ErrAlreadyInstalled) Error() string {
	return "service already installed"
}

// ErrNotRunning is returned when the service is not running
type ErrNotRunning struct{}

func (e ErrNotRunning) Error() string {
	return "service not running"
}

// ErrAlreadyRunning is returned when the service is already running
type ErrAlreadyRunning struct{}

func (e ErrAlreadyRunning) Error() string {
	return "service already running"
}
