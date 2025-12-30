package opschain

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"uradical.io/go/envctl/internal/crypto"
)

// ValueCache stores decrypted values for operations we can't decrypt ourselves.
// When receiving operations from peers, the values are encrypted to the original
// author's key. We store the plaintext values (received over encrypted P2P channel)
// in this cache, indexed by operation hash.
//
// This allows us to:
// 1. Store operations with original encryption and signatures intact
// 2. Still access the plaintext values when computing state
// 3. Maintain cryptographic proof of authorship (signatures verify)
type ValueCache struct {
	cacheDir string
	identity *crypto.Identity

	mu     sync.RWMutex
	values map[string][]byte // op hash (hex) -> encrypted value (to self)
	dirty  bool
}

// NewValueCache creates a new value cache
func NewValueCache(cacheDir string, identity *crypto.Identity) *ValueCache {
	return &ValueCache{
		cacheDir: cacheDir,
		identity: identity,
		values:   make(map[string][]byte),
	}
}

// cachePath returns the path for the value cache file
func (vc *ValueCache) cachePath(project, environment string) string {
	return filepath.Join(vc.cacheDir, project, environment+".values.json")
}

// cacheFile is the on-disk format
type valueCacheFile struct {
	Version uint8             `json:"version"`
	Values  map[string][]byte `json:"values"` // op hash (hex) -> encrypted value
}

const valueCacheVersion = 1

// Load loads the cache from disk
func (vc *ValueCache) Load(project, environment string) error {
	vc.mu.Lock()
	defer vc.mu.Unlock()

	path := vc.cachePath(project, environment)
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			vc.values = make(map[string][]byte)
			return nil
		}
		return fmt.Errorf("read cache: %w", err)
	}

	var file valueCacheFile
	if err := json.Unmarshal(data, &file); err != nil {
		// Corrupted, start fresh
		vc.values = make(map[string][]byte)
		return nil
	}

	if file.Version != valueCacheVersion {
		// Old version, start fresh
		vc.values = make(map[string][]byte)
		return nil
	}

	vc.values = file.Values
	if vc.values == nil {
		vc.values = make(map[string][]byte)
	}
	vc.dirty = false

	return nil
}

// Save saves the cache to disk
func (vc *ValueCache) Save(project, environment string) error {
	vc.mu.RLock()
	defer vc.mu.RUnlock()

	if !vc.dirty {
		return nil
	}

	file := valueCacheFile{
		Version: valueCacheVersion,
		Values:  vc.values,
	}

	data, err := json.MarshalIndent(file, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal cache: %w", err)
	}

	path := vc.cachePath(project, environment)
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return fmt.Errorf("create cache dir: %w", err)
	}

	if err := os.WriteFile(path, data, 0600); err != nil {
		return fmt.Errorf("write cache: %w", err)
	}

	return nil
}

// Put stores a plaintext value for an operation.
// The value is encrypted to our own key before storage.
func (vc *ValueCache) Put(op *Operation, plaintextValue string) error {
	vc.mu.Lock()
	defer vc.mu.Unlock()

	// Encrypt to self for storage
	encrypted, err := crypto.EncryptForIdentity([]byte(plaintextValue), vc.identity.Public())
	if err != nil {
		return fmt.Errorf("encrypt value: %w", err)
	}

	hashKey := hex.EncodeToString(op.Hash())
	vc.values[hashKey] = encrypted
	vc.dirty = true

	return nil
}

// Get retrieves the plaintext value for an operation.
// Returns empty string and false if not found.
func (vc *ValueCache) Get(op *Operation) (string, bool) {
	vc.mu.RLock()
	defer vc.mu.RUnlock()

	hashKey := hex.EncodeToString(op.Hash())
	encrypted, ok := vc.values[hashKey]
	if !ok {
		return "", false
	}

	plaintext, err := crypto.DecryptWithIdentity(encrypted, vc.identity)
	if err != nil {
		return "", false
	}

	return string(plaintext), true
}

// Has checks if we have a cached value for an operation
func (vc *ValueCache) Has(op *Operation) bool {
	vc.mu.RLock()
	defer vc.mu.RUnlock()

	hashKey := hex.EncodeToString(op.Hash())
	_, ok := vc.values[hashKey]
	return ok
}

// Len returns the number of cached values
func (vc *ValueCache) Len() int {
	vc.mu.RLock()
	defer vc.mu.RUnlock()
	return len(vc.values)
}
