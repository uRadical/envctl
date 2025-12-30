package crypto

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"time"
)

// RotationState tracks the state of a key rotation
type RotationState int

const (
	RotationPending RotationState = iota
	RotationCommitting
	RotationComplete
	RotationFailed
)

// KeyRotation manages the atomic rotation of identity keys
type KeyRotation struct {
	OldIdentity *Identity
	NewIdentity *Identity

	// Re-encrypted secrets: path -> ciphertext
	ReEncrypted map[string][]byte

	State     RotationState
	StartedAt time.Time
	Error     error
}

// RotateKeyOptions configures key rotation behaviour
type RotateKeyOptions struct {
	IdentityFile    string        // Path to identity file
	IdentityPubFile string        // Path to public identity file
	NewPassphrase   []byte        // New passphrase (nil = keep same)
	LocalOnly       bool          // Skip team announcement
	BackupRetention time.Duration // How long to keep backup (default 7 days)
	SecretsDirs     []string      // Directories to search for .envctl folders
}

// RotateKey performs a complete key rotation
func RotateKey(oldIdentity *Identity, currentPassphrase []byte, opts RotateKeyOptions) (*KeyRotation, error) {
	rotation := &KeyRotation{
		OldIdentity: oldIdentity,
		ReEncrypted: make(map[string][]byte),
		State:       RotationPending,
		StartedAt:   time.Now(),
	}

	// Determine new passphrase
	newPassphrase := opts.NewPassphrase
	if newPassphrase == nil {
		newPassphrase = currentPassphrase
	}
	defer func() {
		if opts.NewPassphrase != nil {
			ZeroBytes(opts.NewPassphrase)
		}
	}()

	// Step 1: Generate new key pair
	slog.Info("generating new key pair")
	newIdentity, err := GenerateIdentity(oldIdentity.Name)
	if err != nil {
		rotation.State = RotationFailed
		rotation.Error = fmt.Errorf("generating new key: %w", err)
		return rotation, rotation.Error
	}
	rotation.NewIdentity = newIdentity

	// Step 2: Find all secrets encrypted for this identity
	slog.Info("finding secrets to re-encrypt")
	secrets, err := findSecretsInDirs(opts.SecretsDirs)
	if err != nil {
		rotation.State = RotationFailed
		rotation.Error = fmt.Errorf("finding secrets: %w", err)
		return rotation, rotation.Error
	}

	// Step 3: Re-encrypt each secret
	slog.Info("re-encrypting secrets", "count", len(secrets))
	for path, ciphertext := range secrets {
		if err := rotation.reEncryptSecret(path, ciphertext); err != nil {
			rotation.State = RotationFailed
			rotation.Error = fmt.Errorf("re-encrypting %s: %w", path, err)
			return rotation, rotation.Error
		}
	}

	// Step 4: Atomic commit
	slog.Info("committing rotation")
	rotation.State = RotationCommitting
	if err := rotation.commit(opts.IdentityFile, opts.IdentityPubFile, newPassphrase); err != nil {
		slog.Error("commit failed, rolling back", "err", err)
		rotation.rollback(opts.IdentityFile)
		rotation.State = RotationFailed
		rotation.Error = fmt.Errorf("committing: %w", err)
		return rotation, rotation.Error
	}

	rotation.State = RotationComplete

	// Step 5: Schedule backup cleanup
	if opts.BackupRetention == 0 {
		opts.BackupRetention = 7 * 24 * time.Hour
	}
	go scheduleBackupCleanup(opts.IdentityFile, rotation.ReEncrypted, opts.BackupRetention)

	slog.Info("key rotation complete",
		"old_fingerprint", oldIdentity.Fingerprint(),
		"new_fingerprint", newIdentity.Fingerprint(),
	)

	return rotation, nil
}

// reEncryptSecret decrypts with old key and re-encrypts with new key
func (r *KeyRotation) reEncryptSecret(path string, ciphertext []byte) error {
	// Decrypt with old key
	plaintext, err := DecryptWithIdentity(ciphertext, r.OldIdentity)
	if err != nil {
		return fmt.Errorf("decrypting: %w", err)
	}

	// Wrap in protected buffer
	protected := NewProtectedBufferFromBytes(plaintext)
	defer protected.Destroy()

	// Re-encrypt with new key
	newCiphertext, err := EncryptForIdentity(protected.Copy(), r.NewIdentity.Public())
	if err != nil {
		return fmt.Errorf("re-encrypting: %w", err)
	}

	r.ReEncrypted[path] = newCiphertext
	return nil
}

// commit atomically swaps old identity/secrets with new
func (r *KeyRotation) commit(identityFile, identityPubFile string, passphrase []byte) error {
	// Write new identity to .new file
	newIdentityPath := identityFile + ".new"
	if err := r.NewIdentity.SaveEncrypted(newIdentityPath, passphrase); err != nil {
		return fmt.Errorf("writing new identity: %w", err)
	}

	// Write new public identity
	newPubPath := identityPubFile + ".new"
	if err := r.NewIdentity.SavePublic(newPubPath); err != nil {
		os.Remove(newIdentityPath)
		return fmt.Errorf("writing new public identity: %w", err)
	}

	// Write re-encrypted secrets to .new files
	for path, ciphertext := range r.ReEncrypted {
		newPath := path + ".new"
		if err := os.WriteFile(newPath, ciphertext, 0600); err != nil {
			return fmt.Errorf("writing secret %s: %w", path, err)
		}
	}

	// === POINT OF NO RETURN ===
	// From here, we do atomic renames. If power fails mid-way,
	// we may have .bak files to recover from.

	// Backup old identity
	if err := os.Rename(identityFile, identityFile+".bak"); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("backing up identity: %w", err)
	}

	// Backup old public identity
	if err := os.Rename(identityPubFile, identityPubFile+".bak"); err != nil && !os.IsNotExist(err) {
		// Try to restore identity backup
		os.Rename(identityFile+".bak", identityFile)
		return fmt.Errorf("backing up public identity: %w", err)
	}

	// Atomic rename new identity
	if err := os.Rename(newIdentityPath, identityFile); err != nil {
		// Try to restore backups
		os.Rename(identityFile+".bak", identityFile)
		os.Rename(identityPubFile+".bak", identityPubFile)
		return fmt.Errorf("swapping identity: %w", err)
	}

	// Atomic rename new public identity
	if err := os.Rename(newPubPath, identityPubFile); err != nil {
		// This is bad - identity is already swapped
		slog.Error("failed to swap public identity after swapping private", "err", err)
	}

	// Backup and swap secrets
	for path := range r.ReEncrypted {
		newPath := path + ".new"
		bakPath := path + ".bak"

		// Backup old
		os.Rename(path, bakPath)

		// Swap in new
		if err := os.Rename(newPath, path); err != nil {
			// Best effort restore
			os.Rename(bakPath, path)
			slog.Error("failed to swap secret", "path", path, "err", err)
		}
	}

	return nil
}

// rollback removes .new files and restores .bak files
func (r *KeyRotation) rollback(identityFile string) {
	// Remove new identity
	os.Remove(identityFile + ".new")
	os.Remove(identityFile + ".pub.new")

	// Restore identity backup if exists
	if _, err := os.Stat(identityFile + ".bak"); err == nil {
		os.Rename(identityFile+".bak", identityFile)
	}

	// Remove new secrets, restore backups
	for path := range r.ReEncrypted {
		os.Remove(path + ".new")
		if _, err := os.Stat(path + ".bak"); err == nil {
			os.Rename(path+".bak", path)
		}
	}

	slog.Info("rollback complete")
}

// findSecretsInDirs searches directories for .envctl folders with .enc files
func findSecretsInDirs(dirs []string) (map[string][]byte, error) {
	secrets := make(map[string][]byte)

	for _, dir := range dirs {
		if err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return nil // Skip inaccessible paths
			}

			// Skip hidden directories (except .envctl)
			if info.IsDir() && info.Name() != ".envctl" && info.Name()[0] == '.' {
				return filepath.SkipDir
			}

			// Look for .enc files in .envctl directories
			if !info.IsDir() && filepath.Ext(path) == ".enc" {
				parent := filepath.Base(filepath.Dir(path))
				if parent == ".envctl" {
					data, err := os.ReadFile(path)
					if err != nil {
						slog.Warn("failed to read secret file", "path", path, "err", err)
						return nil
					}
					secrets[path] = data
				}
			}

			return nil
		}); err != nil {
			return nil, fmt.Errorf("walking %s: %w", dir, err)
		}
	}

	return secrets, nil
}

// scheduleBackupCleanup removes backup files after retention period
func scheduleBackupCleanup(identityFile string, secrets map[string][]byte, retention time.Duration) {
	time.Sleep(retention)

	// Remove identity backup
	bakPath := identityFile + ".bak"
	if err := secureDelete(bakPath); err != nil {
		slog.Warn("failed to delete identity backup", "err", err)
	}

	// Remove public identity backup
	secureDelete(identityFile[:len(identityFile)-4] + ".pub.bak") // .enc -> .pub

	// Remove secret backups
	for path := range secrets {
		secureDelete(path + ".bak")
	}

	slog.Info("backup files cleaned up")
}

// secureDelete overwrites file with zeros before deleting
func secureDelete(path string) error {
	f, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}

	info, err := f.Stat()
	if err != nil {
		f.Close()
		return err
	}

	// Overwrite with zeros
	zeros := make([]byte, 4096)
	remaining := info.Size()
	for remaining > 0 {
		n := int64(len(zeros))
		if remaining < n {
			n = remaining
		}
		f.Write(zeros[:n])
		remaining -= n
	}

	f.Sync()
	f.Close()

	return os.Remove(path)
}

// KeyRotationAnnouncement is broadcast to team after key rotation
type KeyRotationAnnouncement struct {
	Type           string         `json:"type"` // "key_rotation"
	OldFingerprint string         `json:"old_fingerprint"`
	NewPublicKey   PublicIdentity `json:"new_public_key"`
	NewFingerprint string         `json:"new_fingerprint"`
	Timestamp      time.Time      `json:"timestamp"`
	Signature      []byte         `json:"signature"` // Signed with OLD key
}

// CreateRotationAnnouncement creates a signed announcement
func (r *KeyRotation) CreateAnnouncement() (*KeyRotationAnnouncement, error) {
	if r.OldIdentity == nil || r.NewIdentity == nil {
		return nil, errors.New("rotation not complete")
	}

	ann := &KeyRotationAnnouncement{
		Type:           "key_rotation",
		OldFingerprint: r.OldIdentity.Fingerprint(),
		NewPublicKey:   *r.NewIdentity.Public(),
		NewFingerprint: r.NewIdentity.Fingerprint(),
		Timestamp:      time.Now(),
	}

	// Sign with OLD key to prove continuity
	data, err := json.Marshal(map[string]any{
		"type":            ann.Type,
		"old_fingerprint": ann.OldFingerprint,
		"new_public_key":  ann.NewPublicKey,
		"new_fingerprint": ann.NewFingerprint,
		"timestamp":       ann.Timestamp,
	})
	if err != nil {
		return nil, err
	}

	ann.Signature = r.OldIdentity.Sign(data)
	return ann, nil
}

// VerifyRotationAnnouncement verifies the announcement is valid
func VerifyRotationAnnouncement(ann *KeyRotationAnnouncement, knownPublicKey []byte) error {
	// Reconstruct signed data
	data, err := json.Marshal(map[string]any{
		"type":            ann.Type,
		"old_fingerprint": ann.OldFingerprint,
		"new_public_key":  ann.NewPublicKey,
		"new_fingerprint": ann.NewFingerprint,
		"timestamp":       ann.Timestamp,
	})
	if err != nil {
		return err
	}

	// Verify signature with known public key
	valid, err := VerifySignature(AlgorithmEd25519, knownPublicKey, data, ann.Signature)
	if err != nil {
		return fmt.Errorf("verifying signature: %w", err)
	}
	if !valid {
		return errors.New("invalid signature on key rotation announcement")
	}

	// Check timestamp is reasonable (within last hour)
	if time.Since(ann.Timestamp) > time.Hour {
		return errors.New("key rotation announcement is too old")
	}

	return nil
}

// SecretCount returns the number of re-encrypted secrets
func (r *KeyRotation) SecretCount() int {
	return len(r.ReEncrypted)
}
