// Package testutil provides test utilities for envctl integration tests
package testutil

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"envctl.dev/go/envctl/internal/chain"
	"envctl.dev/go/envctl/internal/config"
	"envctl.dev/go/envctl/internal/crypto"
)

// TestIdentity wraps an identity with its test configuration
type TestIdentity struct {
	Identity  *crypto.Identity
	ConfigDir string
	Paths     *config.Paths
	Name      string
	t         *testing.T
}

// NewTestIdentity creates a new test identity with a temporary config directory
func NewTestIdentity(t *testing.T, name string) *TestIdentity {
	t.Helper()

	configDir := t.TempDir()

	identity, err := crypto.GenerateIdentity(name)
	if err != nil {
		t.Fatalf("generate identity: %v", err)
	}

	// Create paths structure
	paths := &config.Paths{
		ConfigDir:    configDir,
		ChainsDir:    filepath.Join(configDir, "chains"),
		SecretsDir:   filepath.Join(configDir, "secrets"),
		PendingDir:   filepath.Join(configDir, "pending"),
		ProposalsDir: filepath.Join(configDir, "pending", "proposals"),
		RequestsDir:  filepath.Join(configDir, "pending", "requests"),
		IdentityFile: filepath.Join(configDir, "identity.enc"),
		SocketPath:   filepath.Join(configDir, "daemon.sock"),
		TempDir:      filepath.Join(configDir, "tmp"),
	}

	// Ensure directories exist
	dirs := []string{
		paths.ChainsDir,
		paths.SecretsDir,
		paths.PendingDir,
		paths.ProposalsDir,
		paths.RequestsDir,
		paths.TempDir,
	}
	for _, dir := range dirs {
		if err := os.MkdirAll(dir, 0700); err != nil {
			t.Fatalf("create directory %s: %v", dir, err)
		}
	}

	return &TestIdentity{
		Identity:  identity,
		ConfigDir: configDir,
		Paths:     paths,
		Name:      name,
		t:         t,
	}
}

// Fingerprint returns the identity's fingerprint
func (ti *TestIdentity) Fingerprint() string {
	return ti.Identity.Fingerprint()
}

// SigningPublicKey returns the signing public key
func (ti *TestIdentity) SigningPublicKey() []byte {
	return ti.Identity.SigningPublicKey()
}

// CreateTeam creates a test team with this identity as founder
func (ti *TestIdentity) CreateTeam(name string) *chain.Chain {
	ti.t.Helper()

	teamChain, err := chain.CreateTeam(name, ti.Identity)
	if err != nil {
		ti.t.Fatalf("create team: %v", err)
	}

	// Save chain
	chainPath := filepath.Join(ti.Paths.ChainsDir, name+".chain")
	if err := teamChain.Save(chainPath); err != nil {
		ti.t.Fatalf("save chain: %v", err)
	}

	return teamChain
}

// LoadTeam loads a team chain from disk
func (ti *TestIdentity) LoadTeam(name string) *chain.Chain {
	ti.t.Helper()

	chainPath := filepath.Join(ti.Paths.ChainsDir, name+".chain")
	teamChain, err := chain.Load(chainPath)
	if err != nil {
		ti.t.Fatalf("load chain: %v", err)
	}

	return teamChain
}

// SaveTeam saves a team chain to disk
func (ti *TestIdentity) SaveTeam(name string, c *chain.Chain) {
	ti.t.Helper()

	chainPath := filepath.Join(ti.Paths.ChainsDir, name+".chain")
	if err := c.Save(chainPath); err != nil {
		ti.t.Fatalf("save chain: %v", err)
	}
}

// CreateSecrets creates encrypted secrets for a team/env
func (ti *TestIdentity) CreateSecrets(team, env string, secrets map[string]string) {
	ti.t.Helper()

	// Ensure team secrets dir exists
	teamDir := filepath.Join(ti.Paths.SecretsDir, team)
	if err := os.MkdirAll(teamDir, 0700); err != nil {
		ti.t.Fatalf("create team secrets dir: %v", err)
	}

	// Create encrypted env structure
	envData := struct {
		Version   int               `json:"version"`
		Variables map[string]string `json:"variables"`
	}{
		Version:   1,
		Variables: secrets,
	}

	plaintext, err := json.Marshal(envData)
	if err != nil {
		ti.t.Fatalf("marshal secrets: %v", err)
	}

	// Encrypt for self
	ciphertext, err := crypto.EncryptForIdentity(plaintext, ti.Identity.Public())
	if err != nil {
		ti.t.Fatalf("encrypt secrets: %v", err)
	}

	// Write to file
	secretPath := filepath.Join(teamDir, env+".enc")
	if err := os.WriteFile(secretPath, ciphertext, 0600); err != nil {
		ti.t.Fatalf("write secrets: %v", err)
	}
}

// LoadSecrets loads and decrypts secrets for a team/env
func (ti *TestIdentity) LoadSecrets(team, env string) map[string]string {
	ti.t.Helper()

	secretPath := filepath.Join(ti.Paths.SecretsDir, team, env+".enc")

	ciphertext, err := os.ReadFile(secretPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		ti.t.Fatalf("read secrets: %v", err)
	}

	plaintext, err := crypto.DecryptWithIdentity(ciphertext, ti.Identity)
	if err != nil {
		ti.t.Fatalf("decrypt secrets: %v", err)
	}

	var envData struct {
		Version   int               `json:"version"`
		Variables map[string]string `json:"variables"`
	}
	if err := json.Unmarshal(plaintext, &envData); err != nil {
		ti.t.Fatalf("unmarshal secrets: %v", err)
	}

	return envData.Variables
}

// GetSecret retrieves a single secret value
func (ti *TestIdentity) GetSecret(team, env, key string) string {
	ti.t.Helper()

	secrets := ti.LoadSecrets(team, env)
	if secrets == nil {
		ti.t.Fatalf("no secrets found for %s/%s", team, env)
	}

	value, ok := secrets[key]
	if !ok {
		ti.t.Fatalf("secret not found: %s", key)
	}

	return value
}

// WaitFor waits for a condition to be true
func WaitFor(t *testing.T, timeout time.Duration, condition func() bool, msg string) {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			t.Fatalf("timeout waiting for: %s", msg)
		case <-ticker.C:
			if condition() {
				return
			}
		}
	}
}

// FreePorts returns n ports starting from a base port
// In tests, we use high ports to avoid conflicts
func FreePorts(n int) []int {
	ports := make([]int, n)
	for i := 0; i < n; i++ {
		ports[i] = 18835 + i
	}
	return ports
}
