package config

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
)

// Paths holds all platform-specific file paths for envctl
type Paths struct {
	ConfigDir   string // ~/.config/envctl or equivalent
	ChainsDir   string // ~/.config/envctl/chains
	SecretsDir  string // ~/.config/envctl/secrets (cached secrets from peers)
	PendingDir  string // ~/.config/envctl/pending
	ProposalsDir string // ~/.config/envctl/pending/proposals
	RequestsDir string // ~/.config/envctl/pending/requests

	IdentityFile       string // ~/.config/envctl/identity.enc
	IdentityPubFile    string // ~/.config/envctl/identity.pub
	IdentityConfigFile string // ~/.config/envctl/identity.json
	ConfigFile         string // ~/.config/envctl/config.toml
	PeersFile       string // ~/.config/envctl/peers.json
	AuditLogFile    string // ~/.config/envctl/audit.log
	LeasesFile      string // ~/.config/envctl/leases.json
	PIDFile         string // ~/.config/envctl/daemon.pid (Linux/macOS)

	SocketPath string // /run/user/<uid>/envctl.sock or equivalent
	TempDir    string // /tmp/envctl-<uid>
	CacheFile  string // /tmp/envctl-<uid>/prompt-cache.json
}

// GetPaths returns platform-specific paths for envctl
func GetPaths() (*Paths, error) {
	var configDir string
	var socketPath string
	var tempDir string
	var pidFile string

	// Allow override via environment variable (useful for testing multiple instances)
	if envConfigDir := os.Getenv("ENVCTL_CONFIG_DIR"); envConfigDir != "" {
		configDir = envConfigDir
		socketPath = filepath.Join(configDir, "daemon.sock")
		tempDir = filepath.Join(configDir, "tmp")
		pidFile = filepath.Join(configDir, "daemon.pid")
	} else {
		switch runtime.GOOS {
		case "linux":
			home, err := os.UserHomeDir()
			if err != nil {
				return nil, fmt.Errorf("get home directory: %w", err)
			}
			configDir = filepath.Join(home, ".config", "envctl")

			// Socket in XDG_RUNTIME_DIR or /run/user/<uid>
			runtimeDir := os.Getenv("XDG_RUNTIME_DIR")
			if runtimeDir == "" {
				runtimeDir = fmt.Sprintf("/run/user/%d", os.Getuid())
			}
			socketPath = filepath.Join(runtimeDir, "envctl.sock")

			tempDir = fmt.Sprintf("/tmp/envctl-%d", os.Getuid())
			pidFile = filepath.Join(configDir, "daemon.pid")

		case "darwin":
			home, err := os.UserHomeDir()
			if err != nil {
				return nil, fmt.Errorf("get home directory: %w", err)
			}
			configDir = filepath.Join(home, ".config", "envctl")
			socketPath = filepath.Join(home, "Library", "Application Support", "envctl", "daemon.sock")

			tempDir = fmt.Sprintf("/tmp/envctl-%d", os.Getuid())
			pidFile = filepath.Join(configDir, "daemon.pid")

		case "windows":
			appData := os.Getenv("APPDATA")
			if appData == "" {
				return nil, fmt.Errorf("APPDATA environment variable not set")
			}
			configDir = filepath.Join(appData, "envctl")

			// Named pipe on Windows
			username := os.Getenv("USERNAME")
			if username == "" {
				username = "user"
			}
			socketPath = fmt.Sprintf(`\\.\pipe\envctl-%s`, username)

			tempDir = filepath.Join(os.TempDir(), "envctl")
			pidFile = "" // Windows uses different mechanism

		default:
			return nil, fmt.Errorf("unsupported platform: %s", runtime.GOOS)
		}
	}

	p := &Paths{
		ConfigDir:   configDir,
		ChainsDir:   filepath.Join(configDir, "chains"),
		SecretsDir:  filepath.Join(configDir, "secrets"),
		PendingDir:  filepath.Join(configDir, "pending"),
		ProposalsDir: filepath.Join(configDir, "pending", "proposals"),
		RequestsDir: filepath.Join(configDir, "pending", "requests"),

		IdentityFile:       filepath.Join(configDir, "identity.enc"),
		IdentityPubFile:    filepath.Join(configDir, "identity.pub"),
		IdentityConfigFile: filepath.Join(configDir, "identity.json"),
		ConfigFile:         filepath.Join(configDir, "config.toml"),
		PeersFile:       filepath.Join(configDir, "peers.json"),
		AuditLogFile:    filepath.Join(configDir, "audit.log"),
		LeasesFile:      filepath.Join(configDir, "leases.json"),
		PIDFile:         pidFile,

		SocketPath: socketPath,
		TempDir:    tempDir,
		CacheFile:  filepath.Join(tempDir, "prompt-cache.json"),
	}

	return p, nil
}

// EnsureDirectories creates all required directories with appropriate permissions
func (p *Paths) EnsureDirectories() error {
	dirs := []string{
		p.ConfigDir,
		p.ChainsDir,
		p.SecretsDir,
		p.PendingDir,
		p.ProposalsDir,
		p.RequestsDir,
		p.TempDir,
	}

	// On macOS, also ensure the socket parent directory
	if runtime.GOOS == "darwin" {
		socketDir := filepath.Dir(p.SocketPath)
		dirs = append(dirs, socketDir)
	}

	for _, dir := range dirs {
		if err := os.MkdirAll(dir, 0700); err != nil {
			return fmt.Errorf("create directory %s: %w", dir, err)
		}
	}

	return nil
}

// IdentityExists returns true if any identity exists (software, hybrid, or legacy YubiKey)
func (p *Paths) IdentityExists() bool {
	// Check for software identity
	if _, err := os.Stat(p.IdentityFile); err == nil {
		return true
	}
	// Check for hybrid identity
	if _, err := os.Stat(p.HybridIdentityFile()); err == nil {
		return true
	}
	// Check for legacy YubiKey identity config
	if _, err := os.Stat(p.IdentityConfigFile); err == nil {
		return true
	}
	return false
}

// SoftwareIdentityExists returns true if a software identity exists
func (p *Paths) SoftwareIdentityExists() bool {
	_, err := os.Stat(p.IdentityFile)
	return err == nil
}

// YubiKeyIdentityExists returns true if a YubiKey identity config exists
func (p *Paths) YubiKeyIdentityExists() bool {
	_, err := os.Stat(p.IdentityConfigFile)
	return err == nil
}

// HybridIdentityFile returns the path to the hybrid identity file
func (p *Paths) HybridIdentityFile() string {
	return filepath.Join(p.ConfigDir, "identity.hybrid")
}

// HybridIdentityExists returns true if a hybrid identity exists
func (p *Paths) HybridIdentityExists() bool {
	_, err := os.Stat(p.HybridIdentityFile())
	return err == nil
}

// ChainFile returns the path to a team's chain file
func (p *Paths) ChainFile(teamName string) string {
	return filepath.Join(p.ChainsDir, teamName+".chain")
}

// ChainBackupFile returns the path to a team's chain backup file
func (p *Paths) ChainBackupFile(teamName string) string {
	return filepath.Join(p.ChainsDir, teamName+".chain.1")
}

// TeamProposalsDir returns the path to a team's proposals directory
func (p *Paths) TeamProposalsDir(teamName string) string {
	return filepath.Join(p.ProposalsDir, teamName)
}

// LogFile returns the platform-specific log file path (Windows only)
func (p *Paths) LogFile() string {
	if runtime.GOOS == "windows" {
		return filepath.Join(p.ConfigDir, "daemon.log")
	}
	return "" // Linux/macOS use systemd journal / unified log
}

// Project-level paths (relative to project directory)

// EnvctlDir returns the .envctl directory path for a project
func EnvctlDir(projectDir string) string {
	return filepath.Join(projectDir, ".envctl")
}

// EnvctlConfigPath returns the config file path within .envctl
func EnvctlConfigPath(projectDir string) string {
	return filepath.Join(EnvctlDir(projectDir), "config")
}

// EncryptedEnvPath returns the path for an encrypted env file
func EncryptedEnvPath(projectDir, envName string) string {
	return filepath.Join(EnvctlDir(projectDir), envName+".enc")
}

// DotEnvPath returns the .env file path
func DotEnvPath(projectDir string) string {
	return filepath.Join(projectDir, ".env")
}

// SecretFile returns the path for a cached secret file (team/env.enc)
func (p *Paths) SecretFile(team, env string) string {
	return filepath.Join(p.SecretsDir, team, env+".enc")
}

// TeamSecretsDir returns the secrets directory for a team
func (p *Paths) TeamSecretsDir(team string) string {
	return filepath.Join(p.SecretsDir, team)
}

// OpsChainFile returns the path for a project/environment ops chain
func (p *Paths) OpsChainFile(project, environment string) string {
	return filepath.Join(p.ChainsDir, project, environment+".opschain.json")
}

// OpsChainDir returns the directory for a project's ops chains
func (p *Paths) OpsChainDir(project string) string {
	return filepath.Join(p.ChainsDir, project)
}
