package config

import (
	"fmt"
	"os"

	"github.com/BurntSushi/toml"
)

// Config represents the envctl configuration file
type Config struct {
	Identity      IdentityConfig      `toml:"identity"`
	Daemon        DaemonConfig        `toml:"daemon"`
	Discovery     DiscoveryConfig     `toml:"discovery"`
	Logging       LoggingConfig       `toml:"logging"`
	Notifications NotificationsConfig `toml:"notifications"`
	Defaults      DefaultsConfig      `toml:"defaults"`
}

// IdentityConfig contains identity-related settings
type IdentityConfig struct {
	Name string `toml:"name"`
}

// DaemonConfig contains daemon-related settings
type DaemonConfig struct {
	P2PPort    int  `toml:"p2p_port"`
	WebPort    int  `toml:"web_port"`
	WebEnabled bool `toml:"web_enabled"`
}

// DiscoveryConfig contains peer discovery settings
type DiscoveryConfig struct {
	MDNS        bool     `toml:"mdns"`
	ManualPeers []string `toml:"manual_peers"`
}

// LoggingConfig contains logging settings
type LoggingConfig struct {
	Level  string `toml:"level"`  // debug, info, warn, error
	Format string `toml:"format"` // text, json
}

// NotificationsConfig contains notification settings
type NotificationsConfig struct {
	Enabled bool `toml:"enabled"`
}

// DefaultsConfig contains default settings
type DefaultsConfig struct {
	Team string `toml:"team"`
}

// Default returns a config with sensible defaults
func Default() *Config {
	return &Config{
		Identity: IdentityConfig{
			Name: "",
		},
		Daemon: DaemonConfig{
			P2PPort:    7834,
			WebPort:    7835,
			WebEnabled: true,
		},
		Discovery: DiscoveryConfig{
			MDNS:        true,
			ManualPeers: []string{},
		},
		Logging: LoggingConfig{
			Level:  "info",
			Format: "text",
		},
		Notifications: NotificationsConfig{
			Enabled: true,
		},
		Defaults: DefaultsConfig{
			Team: "",
		},
	}
}

// Load loads the configuration from the default config file
func Load() (*Config, error) {
	paths, err := GetPaths()
	if err != nil {
		return nil, fmt.Errorf("get paths: %w", err)
	}

	return LoadFrom(paths.ConfigFile)
}

// LoadFrom loads the configuration from a specific file
func LoadFrom(path string) (*Config, error) {
	cfg := Default()

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			// Return defaults if no config file exists
			return cfg, nil
		}
		return nil, fmt.Errorf("read config: %w", err)
	}

	if _, err := toml.Decode(string(data), cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}

	return cfg, nil
}

// Save saves the configuration to the default config file
func (c *Config) Save() error {
	paths, err := GetPaths()
	if err != nil {
		return fmt.Errorf("get paths: %w", err)
	}

	return c.SaveTo(paths.ConfigFile)
}

// SaveTo saves the configuration to a specific file
func (c *Config) SaveTo(path string) error {
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("create config file: %w", err)
	}
	defer f.Close()

	encoder := toml.NewEncoder(f)
	if err := encoder.Encode(c); err != nil {
		return fmt.Errorf("encode config: %w", err)
	}

	return nil
}

// Validate validates the configuration
func (c *Config) Validate() error {
	if c.Daemon.P2PPort < 1 || c.Daemon.P2PPort > 65535 {
		return fmt.Errorf("invalid P2P port: %d", c.Daemon.P2PPort)
	}

	if c.Daemon.WebEnabled {
		if c.Daemon.WebPort < 1 || c.Daemon.WebPort > 65535 {
			return fmt.Errorf("invalid web port: %d", c.Daemon.WebPort)
		}
	}

	validLevels := map[string]bool{"debug": true, "info": true, "warn": true, "error": true}
	if !validLevels[c.Logging.Level] {
		return fmt.Errorf("invalid log level: %s", c.Logging.Level)
	}

	validFormats := map[string]bool{"text": true, "json": true}
	if !validFormats[c.Logging.Format] {
		return fmt.Errorf("invalid log format: %s", c.Logging.Format)
	}

	return nil
}
