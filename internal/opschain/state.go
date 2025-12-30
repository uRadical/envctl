package opschain

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"uradical.io/go/envctl/internal/crypto"
)

// State represents the computed state of environment variables.
// Built by replaying the operations chain.
type State struct {
	// Variables maps key names to their values
	Variables map[string]string

	// Metadata maps key names to their metadata
	Metadata map[string]*VarMeta

	// HeadSeq is the sequence number of the last applied operation
	HeadSeq int64

	// HeadHash is the hash of the last applied operation
	HeadHash []byte

	// ComputedAt is when this state was computed
	ComputedAt time.Time
}

// VarMeta contains metadata about a variable
type VarMeta struct {
	// LastModified is when the variable was last set
	LastModified time.Time

	// Author is the fingerprint of who last modified it
	Author string

	// OpSeq is the sequence number of the last operation that affected this key
	OpSeq uint64
}

// NewState creates an empty state
func NewState() *State {
	return &State{
		Variables:  make(map[string]string),
		Metadata:   make(map[string]*VarMeta),
		HeadSeq:    -1,
		ComputedAt: time.Now().UTC(),
	}
}

// ComputeState computes the current state by replaying all operations.
// Each set/delete operation's encrypted value is decrypted using the identity.
// If valueCache is provided, it's used as fallback for ops we can't decrypt ourselves.
func ComputeState(chain *Chain, identity *crypto.Identity, valueCache *ValueCache) (*State, error) {
	state := NewState()

	ops := chain.All()
	for _, op := range ops {
		if err := state.Apply(op, identity, valueCache); err != nil {
			return nil, fmt.Errorf("apply op %d: %w", op.Seq, err)
		}
	}

	return state, nil
}

// Apply applies an operation to the state.
// For set operations, tries to decrypt with identity first, falls back to valueCache.
func (s *State) Apply(op *Operation, identity *crypto.Identity, valueCache *ValueCache) error {
	switch op.Op {
	case OpSet:
		// Try to decrypt the value with our identity first
		value, err := DecryptValue(op, identity)
		if err != nil {
			// Can't decrypt - try value cache (for remote ops)
			if valueCache != nil {
				var ok bool
				value, ok = valueCache.Get(op)
				if !ok {
					return fmt.Errorf("decrypt value for %s: %w (and not in value cache)", op.Key, err)
				}
			} else {
				return fmt.Errorf("decrypt value for %s: %w", op.Key, err)
			}
		}
		s.Variables[op.Key] = value
		s.Metadata[op.Key] = &VarMeta{
			LastModified: op.Timestamp,
			Author:       op.AuthorFingerprint(),
			OpSeq:        op.Seq,
		}

	case OpDelete:
		delete(s.Variables, op.Key)
		delete(s.Metadata, op.Key)

	default:
		return fmt.Errorf("unknown operation type: %s", op.Op)
	}

	s.HeadSeq = int64(op.Seq)
	s.HeadHash = op.Hash()
	s.ComputedAt = time.Now().UTC()

	return nil
}

// Get returns the value for a key, or empty string if not found
func (s *State) Get(key string) string {
	return s.Variables[key]
}

// Has returns true if the key exists
func (s *State) Has(key string) bool {
	_, ok := s.Variables[key]
	return ok
}

// Keys returns all keys in sorted order
func (s *State) Keys() []string {
	keys := make([]string, 0, len(s.Variables))
	for k := range s.Variables {
		keys = append(keys, k)
	}
	return keys
}

// Len returns the number of variables
func (s *State) Len() int {
	return len(s.Variables)
}

// ToMap returns a copy of the variables map
func (s *State) ToMap() map[string]string {
	result := make(map[string]string, len(s.Variables))
	for k, v := range s.Variables {
		result[k] = v
	}
	return result
}

// StateCache handles caching of computed state to disk.
// This avoids replaying the entire chain on every access.
type StateCache struct {
	cacheDir string
}

// cachedState is the format for cached state on disk
type cachedState struct {
	Project     string            `json:"project"`
	Environment string            `json:"environment"`
	HeadSeq     int64             `json:"head_seq"`
	HeadHash    []byte            `json:"head_hash"`
	Variables   map[string][]byte `json:"variables"` // Encrypted to self
	ComputedAt  time.Time         `json:"computed_at"`
}

// NewStateCache creates a new state cache
func NewStateCache(cacheDir string) *StateCache {
	return &StateCache{cacheDir: cacheDir}
}

// cachePath returns the path for a cached state file
func (sc *StateCache) cachePath(project, environment string) string {
	return filepath.Join(sc.cacheDir, project, environment+".cache.json")
}

// Load loads cached state if it matches the current chain head
func (sc *StateCache) Load(chain *Chain, identity *crypto.Identity) (*State, bool, error) {
	path := sc.cachePath(chain.Project, chain.Environment)

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, false, nil
		}
		return nil, false, fmt.Errorf("read cache: %w", err)
	}

	var cached cachedState
	if err := json.Unmarshal(data, &cached); err != nil {
		return nil, false, nil // Corrupted cache, ignore
	}

	// Check if cache matches current chain head
	head := chain.Head()
	if head == nil {
		// Chain is empty, cache is stale
		return nil, false, nil
	}

	if cached.HeadSeq != int64(head.Seq) {
		return nil, false, nil
	}

	if string(cached.HeadHash) != string(head.Hash()) {
		return nil, false, nil
	}

	// Decrypt cached variables
	state := NewState()
	state.HeadSeq = cached.HeadSeq
	state.HeadHash = cached.HeadHash
	state.ComputedAt = cached.ComputedAt

	for key, encValue := range cached.Variables {
		plaintext, err := crypto.DecryptWithIdentity(encValue, identity)
		if err != nil {
			return nil, false, nil // Can't decrypt, recompute
		}
		state.Variables[key] = string(plaintext)
	}

	return state, true, nil
}

// Save saves computed state to cache
func (sc *StateCache) Save(state *State, chain *Chain, identity *crypto.Identity) error {
	// Encrypt variables to self
	encVars := make(map[string][]byte, len(state.Variables))
	for key, value := range state.Variables {
		encValue, err := crypto.EncryptForIdentity([]byte(value), identity.Public())
		if err != nil {
			return fmt.Errorf("encrypt %s: %w", key, err)
		}
		encVars[key] = encValue
	}

	cached := cachedState{
		Project:     chain.Project,
		Environment: chain.Environment,
		HeadSeq:     state.HeadSeq,
		HeadHash:    state.HeadHash,
		Variables:   encVars,
		ComputedAt:  state.ComputedAt,
	}

	data, err := json.MarshalIndent(cached, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal cache: %w", err)
	}

	path := sc.cachePath(chain.Project, chain.Environment)
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return fmt.Errorf("create cache dir: %w", err)
	}

	if err := os.WriteFile(path, data, 0600); err != nil {
		return fmt.Errorf("write cache: %w", err)
	}

	return nil
}

// Invalidate removes the cached state
func (sc *StateCache) Invalidate(project, environment string) error {
	path := sc.cachePath(project, environment)
	err := os.Remove(path)
	if os.IsNotExist(err) {
		return nil
	}
	return err
}

// GetOrCompute returns cached state if valid, otherwise computes and caches it
func (sc *StateCache) GetOrCompute(chain *Chain, identity *crypto.Identity, valueCache *ValueCache) (*State, error) {
	// Try to load from cache
	state, hit, err := sc.Load(chain, identity)
	if err != nil {
		// Log error but continue to recompute
	}
	if hit && state != nil {
		return state, nil
	}

	// Compute state (using valueCache for remote ops we can't decrypt)
	state, err = ComputeState(chain, identity, valueCache)
	if err != nil {
		return nil, fmt.Errorf("compute state: %w", err)
	}

	// Save to cache (ignore error, cache is optional)
	_ = sc.Save(state, chain, identity)

	return state, nil
}
