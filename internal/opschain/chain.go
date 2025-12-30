package opschain

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

// Chain represents an operations chain for a specific project/environment.
// Each environment has its own chain stored locally.
type Chain struct {
	// Project is the project name
	Project string `json:"project"`

	// Environment is the environment name (e.g., "dev", "prod")
	Environment string `json:"environment"`

	// Operations is the ordered list of operations
	Operations []*Operation `json:"operations"`

	// mu protects concurrent access
	mu sync.RWMutex
}

// NewChain creates a new empty chain
func NewChain(project, environment string) *Chain {
	return &Chain{
		Project:     project,
		Environment: environment,
		Operations:  make([]*Operation, 0),
	}
}

// Head returns the last operation in the chain, or nil if empty
func (c *Chain) Head() *Operation {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if len(c.Operations) == 0 {
		return nil
	}
	return c.Operations[len(c.Operations)-1]
}

// HeadHash returns the hash of the last operation, or nil if empty
func (c *Chain) HeadHash() []byte {
	head := c.Head()
	if head == nil {
		return nil
	}
	return head.Hash()
}

// Len returns the number of operations in the chain
func (c *Chain) Len() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.Operations)
}

// NextSeq returns the sequence number for the next operation
func (c *Chain) NextSeq() uint64 {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return uint64(len(c.Operations))
}

// Append adds a new operation to the chain after verification
func (c *Chain) Append(op *Operation, verifier *Verifier) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Get previous operation for verification
	var prevOp *Operation
	if len(c.Operations) > 0 {
		prevOp = c.Operations[len(c.Operations)-1]
	}

	// Verify the operation
	if verifier != nil {
		if err := verifier.VerifyOperation(op, prevOp); err != nil {
			return fmt.Errorf("verify operation: %w", err)
		}
	}

	// Check sequence number
	expectedSeq := uint64(len(c.Operations))
	if op.Seq != expectedSeq {
		return fmt.Errorf("sequence mismatch: expected %d, got %d", expectedSeq, op.Seq)
	}

	c.Operations = append(c.Operations, op)
	return nil
}

// AppendWithoutVerification adds an operation without verification.
// Use with caution - only for internal use when loading from trusted storage.
func (c *Chain) AppendWithoutVerification(op *Operation) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	expectedSeq := uint64(len(c.Operations))
	if op.Seq != expectedSeq {
		return fmt.Errorf("sequence mismatch: expected %d, got %d", expectedSeq, op.Seq)
	}

	c.Operations = append(c.Operations, op)
	return nil
}

// Get returns the operation at the given sequence number
func (c *Chain) Get(seq uint64) *Operation {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if seq >= uint64(len(c.Operations)) {
		return nil
	}
	return c.Operations[seq]
}

// Range returns operations from startSeq (inclusive) to the end
func (c *Chain) Range(startSeq uint64) []*Operation {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if startSeq >= uint64(len(c.Operations)) {
		return nil
	}
	return c.Operations[startSeq:]
}

// All returns all operations
func (c *Chain) All() []*Operation {
	c.mu.RLock()
	defer c.mu.RUnlock()

	result := make([]*Operation, len(c.Operations))
	copy(result, c.Operations)
	return result
}

// Verify verifies the entire chain
func (c *Chain) Verify(verifier *Verifier) error {
	c.mu.RLock()
	defer c.mu.RUnlock()

	return verifier.VerifyChain(c.Operations)
}

// chainFile is the storage format
type chainFile struct {
	Version     uint8        `json:"version"`
	Project     string       `json:"project"`
	Environment string       `json:"environment"`
	Operations  []*Operation `json:"operations"`
}

const chainFileVersion = 1

// Save saves the chain to a file
func (c *Chain) Save(path string) error {
	c.mu.RLock()
	defer c.mu.RUnlock()

	// Create backup of existing file
	if _, err := os.Stat(path); err == nil {
		backupPath := path + ".bak"
		if err := os.Rename(path, backupPath); err != nil {
			return fmt.Errorf("create backup: %w", err)
		}
	}

	// Ensure directory exists
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("create directory: %w", err)
	}

	file := chainFile{
		Version:     chainFileVersion,
		Project:     c.Project,
		Environment: c.Environment,
		Operations:  c.Operations,
	}

	data, err := json.MarshalIndent(file, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal chain: %w", err)
	}

	if err := os.WriteFile(path, data, 0600); err != nil {
		return fmt.Errorf("write file: %w", err)
	}

	return nil
}

// Load loads a chain from a file
func Load(path string) (*Chain, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read file: %w", err)
	}

	var file chainFile
	if err := json.Unmarshal(data, &file); err != nil {
		return nil, fmt.Errorf("unmarshal chain: %w", err)
	}

	if file.Version != chainFileVersion {
		return nil, fmt.Errorf("unsupported chain version: %d", file.Version)
	}

	chain := &Chain{
		Project:     file.Project,
		Environment: file.Environment,
		Operations:  file.Operations,
	}

	return chain, nil
}

// LoadOrCreate loads a chain from file, or creates a new one if it doesn't exist
func LoadOrCreate(path, project, environment string) (*Chain, error) {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return NewChain(project, environment), nil
	}

	return Load(path)
}

// Exists checks if a chain file exists
func Exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// Delete removes a chain file and its backup
func Delete(path string) error {
	os.Remove(path + ".bak") // Ignore error for backup
	return os.Remove(path)
}

// ChainPath returns the path for a project/environment chain file
func ChainPath(chainsDir, project, environment string) string {
	return filepath.Join(chainsDir, project, environment+".json")
}

// Merge attempts to merge operations from another chain.
// Returns the number of operations merged and any conflict.
func (c *Chain) Merge(other *Chain, verifier *Verifier) (int, *Conflict, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.Project != other.Project || c.Environment != other.Environment {
		return 0, nil, errors.New("project/environment mismatch")
	}

	ourLen := uint64(len(c.Operations))
	theirOps := other.All()

	// Find divergence point
	var divergeSeq uint64 = 0
	for i := uint64(0); i < ourLen && i < uint64(len(theirOps)); i++ {
		ourHash := c.Operations[i].Hash()
		theirHash := theirOps[i].Hash()
		if string(ourHash) != string(theirHash) {
			// Divergence at seq i
			return 0, &Conflict{
				Seq:     i,
				OurOp:   c.Operations[i],
				TheirOp: theirOps[i],
			}, nil
		}
		divergeSeq = i + 1
	}

	// If they have more ops than us, append them
	if uint64(len(theirOps)) > ourLen {
		var prevOp *Operation
		if len(c.Operations) > 0 {
			prevOp = c.Operations[len(c.Operations)-1]
		}

		merged := 0
		for i := ourLen; i < uint64(len(theirOps)); i++ {
			op := theirOps[i]

			// Verify each new operation
			if verifier != nil {
				if err := verifier.VerifyOperation(op, prevOp); err != nil {
					return merged, nil, fmt.Errorf("verify operation %d: %w", i, err)
				}
			}

			c.Operations = append(c.Operations, op)
			prevOp = op
			merged++
		}
		return merged, nil, nil
	}

	// If we have more ops, nothing to merge
	if ourLen > uint64(len(theirOps)) {
		return 0, nil, nil
	}

	// Chains are identical
	_ = divergeSeq // Used for conflict detection above
	return 0, nil, nil
}

// Conflict represents a conflict between two chains
type Conflict struct {
	// Seq is the sequence number where the conflict occurred
	Seq uint64

	// OurOp is our version of the operation
	OurOp *Operation

	// TheirOp is their version of the operation
	TheirOp *Operation
}

// String returns a human-readable description of the conflict
func (c *Conflict) String() string {
	return fmt.Sprintf("conflict at seq %d: %s (ours) vs %s (theirs)",
		c.Seq, c.OurOp.Key, c.TheirOp.Key)
}
