package config

import (
	"encoding/json"
	"fmt"
	"os"
	"time"
)

// IdentityStorageType represents the type of identity storage
type IdentityStorageType string

const (
	IdentityTypeSoftware IdentityStorageType = "software"
	IdentityTypeYubiKey  IdentityStorageType = "yubikey"
)

// YubiKeyIdentityConfig stores YubiKey identity configuration and metadata
// This is stored in identity.json when using a YubiKey
type YubiKeyIdentityConfig struct {
	Type       IdentityStorageType `json:"type"`             // "software" or "yubikey"
	Name       string              `json:"name"`             // Identity name
	Serial     uint32              `json:"serial,omitempty"` // YubiKey serial
	SigningPub []byte              `json:"signing_pub"`      // Ed25519 public key
	ECDHPub    []byte              `json:"ecdh_pub"`         // P-256 ECDH public key
	CreatedAt  time.Time           `json:"created_at"`       // Creation timestamp
}

// LoadYubiKeyIdentityConfig loads the YubiKey identity configuration from the default path
func LoadYubiKeyIdentityConfig() (*YubiKeyIdentityConfig, error) {
	paths, err := GetPaths()
	if err != nil {
		return nil, err
	}
	return LoadYubiKeyIdentityConfigFrom(paths.IdentityConfigFile)
}

// LoadYubiKeyIdentityConfigFrom loads YubiKey identity configuration from a specific path
func LoadYubiKeyIdentityConfigFrom(path string) (*YubiKeyIdentityConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read identity config: %w", err)
	}

	var cfg YubiKeyIdentityConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse identity config: %w", err)
	}

	return &cfg, nil
}

// Save saves the YubiKey identity configuration to the default path
func (cfg *YubiKeyIdentityConfig) Save() error {
	paths, err := GetPaths()
	if err != nil {
		return err
	}
	return cfg.SaveTo(paths.IdentityConfigFile)
}

// SaveTo saves the YubiKey identity configuration to a specific path
func (cfg *YubiKeyIdentityConfig) SaveTo(path string) error {
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal identity config: %w", err)
	}

	if err := os.WriteFile(path, data, 0600); err != nil {
		return fmt.Errorf("write identity config: %w", err)
	}

	return nil
}

// IsYubiKey returns true if this is a YubiKey identity
func (cfg *YubiKeyIdentityConfig) IsYubiKey() bool {
	return cfg.Type == IdentityTypeYubiKey
}

// IsSoftware returns true if this is a software identity
func (cfg *YubiKeyIdentityConfig) IsSoftware() bool {
	return cfg.Type == IdentityTypeSoftware
}

// DeleteYubiKeyIdentityConfig removes the identity configuration file
func DeleteYubiKeyIdentityConfig() error {
	paths, err := GetPaths()
	if err != nil {
		return err
	}
	return os.Remove(paths.IdentityConfigFile)
}
