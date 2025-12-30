package opschain

import (
	"fmt"
	"os"
	"path/filepath"

	"uradical.io/go/envctl/internal/crypto"
)

// Manager coordinates operations chain management for a project/environment
type Manager struct {
	// ChainsDir is the base directory for chain storage
	ChainsDir string

	// CacheDir is the directory for state caches
	CacheDir string

	// identity is the user's identity for signing and decryption
	identity *crypto.Identity

	// stateCache handles state caching
	stateCache *StateCache

	// valueCache stores decrypted values for remote ops we can't decrypt
	valueCache *ValueCache

	// verifier is used to verify operations
	verifier *Verifier
}

// NewManager creates a new operations chain manager
func NewManager(chainsDir, cacheDir string, identity *crypto.Identity) *Manager {
	return &Manager{
		ChainsDir:  chainsDir,
		CacheDir:   cacheDir,
		identity:   identity,
		stateCache: NewStateCache(cacheDir),
		valueCache: NewValueCache(cacheDir, identity),
		verifier:   NewVerifier(),
	}
}

// chainPath returns the path for a project/environment chain
func (m *Manager) chainPath(project, environment string) string {
	return filepath.Join(m.ChainsDir, project, environment+".opschain.json")
}

// LoadChain loads or creates a chain for a project/environment
func (m *Manager) LoadChain(project, environment string) (*Chain, error) {
	path := m.chainPath(project, environment)
	return LoadOrCreate(path, project, environment)
}

// SaveChain saves a chain to disk
func (m *Manager) SaveChain(chain *Chain) error {
	path := m.chainPath(chain.Project, chain.Environment)
	return chain.Save(path)
}

// GetState returns the current state for a project/environment.
// Uses cache if available and valid.
func (m *Manager) GetState(project, environment string) (*State, error) {
	chain, err := m.LoadChain(project, environment)
	if err != nil {
		return nil, fmt.Errorf("load chain: %w", err)
	}

	// Load value cache for remote ops we can't decrypt ourselves
	if err := m.valueCache.Load(project, environment); err != nil {
		return nil, fmt.Errorf("load value cache: %w", err)
	}

	return m.stateCache.GetOrCompute(chain, m.identity, m.valueCache)
}

// Set sets a variable in the chain
func (m *Manager) Set(project, environment, key, value string) error {
	chain, err := m.LoadChain(project, environment)
	if err != nil {
		return fmt.Errorf("load chain: %w", err)
	}

	builder := NewBuilder(m.identity)

	op, err := builder.BuildSetOp(chain.NextSeq(), chain.HeadHash(), key, value)
	if err != nil {
		return fmt.Errorf("build set operation: %w", err)
	}

	if err := chain.Append(op, m.verifier); err != nil {
		return fmt.Errorf("append operation: %w", err)
	}

	if err := m.SaveChain(chain); err != nil {
		return fmt.Errorf("save chain: %w", err)
	}

	// Invalidate cache
	_ = m.stateCache.Invalidate(project, environment)

	return nil
}

// Delete removes a variable from the chain
func (m *Manager) Delete(project, environment, key string) error {
	chain, err := m.LoadChain(project, environment)
	if err != nil {
		return fmt.Errorf("load chain: %w", err)
	}

	builder := NewBuilder(m.identity)

	op, err := builder.BuildDeleteOp(chain.NextSeq(), chain.HeadHash(), key)
	if err != nil {
		return fmt.Errorf("build delete operation: %w", err)
	}

	if err := chain.Append(op, m.verifier); err != nil {
		return fmt.Errorf("append operation: %w", err)
	}

	if err := m.SaveChain(chain); err != nil {
		return fmt.Errorf("save chain: %w", err)
	}

	// Invalidate cache
	_ = m.stateCache.Invalidate(project, environment)

	return nil
}

// Get retrieves a variable's value
func (m *Manager) Get(project, environment, key string) (string, bool, error) {
	state, err := m.GetState(project, environment)
	if err != nil {
		return "", false, err
	}

	if !state.Has(key) {
		return "", false, nil
	}

	return state.Get(key), true, nil
}

// List returns all variables
func (m *Manager) List(project, environment string) (map[string]string, error) {
	state, err := m.GetState(project, environment)
	if err != nil {
		return nil, err
	}

	return state.ToMap(), nil
}

// Status returns information about the chain
func (m *Manager) Status(project, environment string) (*ChainStatus, error) {
	chain, err := m.LoadChain(project, environment)
	if err != nil {
		return nil, fmt.Errorf("load chain: %w", err)
	}

	// Load value cache for remote ops
	if err := m.valueCache.Load(project, environment); err != nil {
		return nil, fmt.Errorf("load value cache: %w", err)
	}

	state, err := m.stateCache.GetOrCompute(chain, m.identity, m.valueCache)
	if err != nil {
		return nil, fmt.Errorf("compute state: %w", err)
	}

	status := &ChainStatus{
		Project:     chain.Project,
		Environment: chain.Environment,
		OpCount:     chain.Len(),
		VarCount:    state.Len(),
	}

	if head := chain.Head(); head != nil {
		status.HeadSeq = head.Seq
		status.HeadHash = head.Hash()
		status.LastModified = head.Timestamp
	}

	return status, nil
}

// ChainStatus contains summary information about a chain
type ChainStatus struct {
	Project      string
	Environment  string
	OpCount      int
	VarCount     int
	HeadSeq      uint64
	HeadHash     []byte
	LastModified interface{} // time.Time but interface for nil check
}

// Log returns the operation log for a chain
func (m *Manager) Log(project, environment string, limit int) ([]*Operation, error) {
	chain, err := m.LoadChain(project, environment)
	if err != nil {
		return nil, fmt.Errorf("load chain: %w", err)
	}

	ops := chain.All()
	if limit > 0 && len(ops) > limit {
		ops = ops[len(ops)-limit:]
	}

	return ops, nil
}

// Merge merges operations from another chain
func (m *Manager) Merge(project, environment string, incoming *Chain) (int, *Conflict, error) {
	chain, err := m.LoadChain(project, environment)
	if err != nil {
		return 0, nil, fmt.Errorf("load chain: %w", err)
	}

	merged, conflict, err := chain.Merge(incoming, m.verifier)
	if err != nil {
		return 0, nil, fmt.Errorf("merge: %w", err)
	}

	if conflict != nil {
		return 0, conflict, nil
	}

	if merged > 0 {
		if err := m.SaveChain(chain); err != nil {
			return 0, nil, fmt.Errorf("save chain: %w", err)
		}
		_ = m.stateCache.Invalidate(project, environment)
	}

	return merged, nil, nil
}

// ExportForPeer exports operations for sending to a peer.
// Values are decrypted (will be sent over encrypted P2P channel).
type ExportedOp struct {
	Op             *Operation
	PlaintextValue string // Empty for delete operations
}

// ExportRange exports operations from startSeq onwards.
// For ops we created, decrypts using our identity.
// For ops from others, uses value cache.
func (m *Manager) ExportRange(project, environment string, startSeq uint64) ([]*ExportedOp, error) {
	chain, err := m.LoadChain(project, environment)
	if err != nil {
		return nil, fmt.Errorf("load chain: %w", err)
	}

	// Load value cache for remote ops
	if err := m.valueCache.Load(project, environment); err != nil {
		return nil, fmt.Errorf("load value cache: %w", err)
	}

	ops := chain.Range(startSeq)
	exported := make([]*ExportedOp, 0, len(ops))

	for _, op := range ops {
		exp := &ExportedOp{Op: op}
		if op.Op == OpSet {
			// Try our key first
			value, err := DecryptValue(op, m.identity)
			if err != nil {
				// Try value cache for remote ops
				var ok bool
				value, ok = m.valueCache.Get(op)
				if !ok {
					return nil, fmt.Errorf("decrypt op %d: %w (and not in cache)", op.Seq, err)
				}
			}
			exp.PlaintextValue = value
		}
		exported = append(exported, exp)
	}

	return exported, nil
}

// ImportOps imports operations from a peer.
// Operations are stored with original encryption and signatures intact.
// Plaintext values are cached separately for operations we can't decrypt ourselves.
// This preserves the cryptographic audit trail while still allowing value access.
func (m *Manager) ImportOps(project, environment string, incoming []*ExportedOp) (int, *Conflict, error) {
	chain, err := m.LoadChain(project, environment)
	if err != nil {
		return 0, nil, fmt.Errorf("load chain: %w", err)
	}

	// Load existing value cache
	if err := m.valueCache.Load(project, environment); err != nil {
		return 0, nil, fmt.Errorf("load value cache: %w", err)
	}

	// Build a temp chain with all ops (existing + incoming) for merge detection
	tempChain := NewChain(project, environment)

	// Copy our existing ops
	for _, op := range chain.All() {
		if err := tempChain.AppendWithoutVerification(op); err != nil {
			return 0, nil, fmt.Errorf("copy local op: %w", err)
		}
	}

	// Append incoming ops (with original encryption, will verify signatures)
	for _, exp := range incoming {
		// Store the original operation as-is (preserves signature)
		if err := tempChain.AppendWithoutVerification(exp.Op); err != nil {
			// Sequence mismatch - could be a conflict or duplicate
			break
		}
	}

	// Merge with full verification - signatures should now verify since we're
	// keeping original ops intact
	merged, conflict, err := chain.Merge(tempChain, m.verifier)
	if err != nil {
		return 0, nil, fmt.Errorf("merge: %w", err)
	}

	if conflict != nil {
		return 0, conflict, nil
	}

	// Cache plaintext values for ALL incoming ops we can't decrypt ourselves
	// This handles both new ops and re-syncing ops we already have but lack cached values for
	valueCached := false
	for _, exp := range incoming {
		if exp.Op.Op == OpSet && exp.PlaintextValue != "" {
			// Skip if already in cache
			if m.valueCache.Has(exp.Op) {
				continue
			}
			// Try to decrypt with our key first - if it works, we don't need to cache
			_, err := DecryptValue(exp.Op, m.identity)
			if err != nil {
				// Can't decrypt (not encrypted to us), cache the plaintext
				if err := m.valueCache.Put(exp.Op, exp.PlaintextValue); err != nil {
					return merged, nil, fmt.Errorf("cache value for op %d: %w", exp.Op.Seq, err)
				}
				valueCached = true
			}
		}
	}

	// Save chain if we merged new ops
	if merged > 0 {
		if err := m.SaveChain(chain); err != nil {
			return 0, nil, fmt.Errorf("save chain: %w", err)
		}
		_ = m.stateCache.Invalidate(project, environment)
	}

	// Save value cache if we added any values
	if valueCached {
		if err := m.valueCache.Save(project, environment); err != nil {
			return merged, nil, fmt.Errorf("save value cache: %w", err)
		}
	}

	return merged, nil, nil
}

// ListProjects returns all projects with chains
func (m *Manager) ListProjects() ([]string, error) {
	entries, err := os.ReadDir(m.ChainsDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}

	var projects []string
	for _, e := range entries {
		if e.IsDir() {
			projects = append(projects, e.Name())
		}
	}

	return projects, nil
}

// ListEnvironments returns all environments for a project
func (m *Manager) ListEnvironments(project string) ([]string, error) {
	dir := filepath.Join(m.ChainsDir, project)
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}

	var envs []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if len(name) > len(".opschain.json") && name[len(name)-len(".opschain.json"):] == ".opschain.json" {
			envs = append(envs, name[:len(name)-len(".opschain.json")])
		}
	}

	return envs, nil
}
