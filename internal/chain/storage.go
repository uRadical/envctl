package chain

import (
	"encoding/gob"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// StorageFormat determines how the chain is serialized
type StorageFormat int

const (
	// FormatJSON stores chain as JSON (for debugging)
	FormatJSON StorageFormat = iota
	// FormatGob stores chain as binary gob (for production)
	FormatGob
)

// DefaultFormat is the storage format used by default
// Use JSON during development for debugging, switch to Gob for release
var DefaultFormat = FormatJSON

// Save saves the chain to a file
func (c *Chain) Save(path string) error {
	return c.SaveFormat(path, DefaultFormat)
}

// SaveFormat saves the chain to a file with the specified format
func (c *Chain) SaveFormat(path string, format StorageFormat) error {
	c.mu.RLock()
	defer c.mu.RUnlock()

	// Create backup of existing file
	if _, err := os.Stat(path); err == nil {
		backupPath := path + ".1"
		if err := os.Rename(path, backupPath); err != nil {
			return fmt.Errorf("create backup: %w", err)
		}
	}

	// Ensure directory exists
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("create directory: %w", err)
	}

	// Create file
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("create file: %w", err)
	}
	defer f.Close()

	switch format {
	case FormatJSON:
		encoder := json.NewEncoder(f)
		encoder.SetIndent("", "  ")
		if err := encoder.Encode(c.blocks); err != nil {
			return fmt.Errorf("encode JSON: %w", err)
		}

	case FormatGob:
		encoder := gob.NewEncoder(f)
		if err := encoder.Encode(c.blocks); err != nil {
			return fmt.Errorf("encode gob: %w", err)
		}

	default:
		return fmt.Errorf("unknown format: %d", format)
	}

	return nil
}

// Load loads a chain from a file
func Load(path string) (*Chain, error) {
	return LoadFormat(path, DefaultFormat)
}

// LoadFormat loads a chain from a file with the specified format
func LoadFormat(path string, format StorageFormat) (*Chain, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open file: %w", err)
	}
	defer f.Close()

	var blocks []*Block

	switch format {
	case FormatJSON:
		decoder := json.NewDecoder(f)
		if err := decoder.Decode(&blocks); err != nil {
			return nil, fmt.Errorf("decode JSON: %w", err)
		}

	case FormatGob:
		decoder := gob.NewDecoder(f)
		if err := decoder.Decode(&blocks); err != nil {
			return nil, fmt.Errorf("decode gob: %w", err)
		}

	default:
		return nil, fmt.Errorf("unknown format: %d", format)
	}

	if len(blocks) == 0 {
		return nil, errors.New("empty chain file")
	}

	// Reconstruct chain by replaying blocks
	chain := New()
	for i, block := range blocks {
		if err := chain.AppendBlock(block); err != nil {
			return nil, fmt.Errorf("block %d: %w", i, err)
		}
	}

	return chain, nil
}

// LoadOrCreate loads a chain from file, or returns nil if it doesn't exist
func LoadOrCreate(path string) (*Chain, error) {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return nil, nil
	}
	return Load(path)
}

// RecoverFromBackup attempts to recover a chain from its backup file
func RecoverFromBackup(path string) (*Chain, error) {
	backupPath := path + ".1"

	chain, err := Load(backupPath)
	if err != nil {
		return nil, fmt.Errorf("load backup: %w", err)
	}

	// Verify the recovered chain
	if err := chain.Verify(); err != nil {
		return nil, fmt.Errorf("verify backup chain: %w", err)
	}

	return chain, nil
}

// TryLoadWithRecovery attempts to load a chain, falling back to backup if needed
func TryLoadWithRecovery(path string) (*Chain, bool, error) {
	// Try primary file first
	chain, err := Load(path)
	if err == nil {
		// Verify chain integrity
		if verifyErr := chain.Verify(); verifyErr == nil {
			return chain, false, nil
		}
		// Primary file corrupted, try backup
	}

	// Try backup
	chain, err = RecoverFromBackup(path)
	if err != nil {
		return nil, false, fmt.Errorf("recovery failed: primary and backup both invalid")
	}

	// Save recovered chain as primary
	if err := chain.Save(path); err != nil {
		return nil, false, fmt.Errorf("save recovered chain: %w", err)
	}

	return chain, true, nil
}

// Exists checks if a chain file exists
func Exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// Delete removes a chain file and its backup
func Delete(path string) error {
	os.Remove(path + ".1") // Ignore error for backup
	return os.Remove(path)
}

// Export exports the chain to a JSON file (always JSON, for sharing)
func (c *Chain) Export(path string) error {
	c.mu.RLock()
	defer c.mu.RUnlock()

	data, err := json.MarshalIndent(c.blocks, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}

	if err := os.WriteFile(path, data, 0644); err != nil {
		return fmt.Errorf("write file: %w", err)
	}

	return nil
}

// Import imports a chain from a JSON file
func Import(path string) (*Chain, error) {
	return LoadFormat(path, FormatJSON)
}

// ChainInfo contains summary information about a chain
type ChainInfo struct {
	TeamName    string
	BlockCount  int
	MemberCount int
	AdminCount  int
	HeadHash    []byte
}

// Info returns summary information about the chain
func (c *Chain) Info() *ChainInfo {
	c.mu.RLock()
	defer c.mu.RUnlock()

	adminCount := 0
	for _, m := range c.members {
		if m.Role == RoleAdmin {
			adminCount++
		}
	}

	var headHash []byte
	if len(c.blocks) > 0 {
		headHash = c.blocks[len(c.blocks)-1].Hash
	}

	teamName := ""
	if c.policy != nil {
		teamName = c.policy.TeamName
	}

	return &ChainInfo{
		TeamName:    teamName,
		BlockCount:  len(c.blocks),
		MemberCount: len(c.members),
		AdminCount:  adminCount,
		HeadHash:    headHash,
	}
}
