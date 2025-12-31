//go:build !cgo

package crypto

import (
	"errors"
)

// HybridIdentity stub for non-CGO builds
type HybridIdentity struct {
	name        string
	fingerprint string
}

// HybridIdentityFile is the on-disk format for hybrid identity
type HybridIdentityFile struct {
	Version       int    `json:"version"`
	Name          string `json:"name"`
	Fingerprint   string `json:"fingerprint"`
	YubiKeySerial uint32 `json:"yubikey_serial"`
}

// GenerateHybridIdentity returns an error in non-CGO builds
func GenerateHybridIdentity(name string, yk interface{}, pin string, touchCallback func(string)) (*HybridIdentity, error) {
	return nil, ErrYubiKeyNotSupported
}

// LoadHybridIdentity returns an error in non-CGO builds
func LoadHybridIdentity(path string) (*HybridIdentity, error) {
	return nil, ErrYubiKeyNotSupported
}

// Save returns an error in non-CGO builds
func (h *HybridIdentity) Save(path string) error {
	return ErrYubiKeyNotSupported
}

// ConnectYubiKey returns an error in non-CGO builds
func (h *HybridIdentity) ConnectYubiKey() error {
	return ErrYubiKeyNotSupported
}

// Unlock returns an error in non-CGO builds
func (h *HybridIdentity) Unlock(pin string, touchCallback func(string)) error {
	return ErrYubiKeyNotSupported
}

// Lock is a no-op in non-CGO builds
func (h *HybridIdentity) Lock() {}

// Close returns nil in non-CGO builds
func (h *HybridIdentity) Close() error {
	return nil
}

// Sign returns an error in non-CGO builds
func (h *HybridIdentity) Sign(data []byte, pin string, touchCallback func(string)) ([]byte, error) {
	return nil, ErrYubiKeyNotSupported
}

// Verify returns false in non-CGO builds
func (h *HybridIdentity) Verify(data, signature []byte) bool {
	return false
}

// VerifyHybridSignature returns false in non-CGO builds
func VerifyHybridSignature(hwPubKey, pqcPubKey, data, signature []byte) bool {
	return false
}

// Fingerprint returns the identity fingerprint
func (h *HybridIdentity) Fingerprint() string {
	return h.fingerprint
}

// Name returns the identity name
func (h *HybridIdentity) Name() string {
	return h.name
}

// MLKEMPublicKey returns nil in non-CGO builds
func (h *HybridIdentity) MLKEMPublicKey() []byte {
	return nil
}

// SigningPublicKey returns nil in non-CGO builds
func (h *HybridIdentity) SigningPublicKey() []byte {
	return nil
}

// HWPublicKey returns nil in non-CGO builds
func (h *HybridIdentity) HWPublicKey() []byte {
	return nil
}

// Decapsulate returns an error in non-CGO builds
func (h *HybridIdentity) Decapsulate(ciphertext []byte) ([]byte, error) {
	return nil, errors.New("hybrid identity not supported without CGO")
}

// IsUnlocked returns false in non-CGO builds
func (h *HybridIdentity) IsUnlocked() bool {
	return false
}

// Serial returns 0 in non-CGO builds
func (h *HybridIdentity) Serial() uint32 {
	return 0
}
