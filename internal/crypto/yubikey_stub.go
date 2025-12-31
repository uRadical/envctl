//go:build !cgo

package crypto

import (
	"crypto/ed25519"
	"errors"
	"time"
)

// ErrYubiKeyNotSupported is returned when YubiKey operations are called
// in a build without CGO support.
var ErrYubiKeyNotSupported = errors.New("YubiKey support not available (requires CGO)")

// YubiKey represents a connected YubiKey (stub for non-CGO builds)
type YubiKey struct {
	serial uint32
}

// YubiKeyIdentity represents an identity stored on YubiKey (stub for non-CGO builds)
type YubiKeyIdentity struct {
	Name       string    `json:"name"`
	Serial     uint32    `json:"serial"`
	SigningPub []byte    `json:"signing_pub"`
	ECDHPub    []byte    `json:"ecdh_pub"`
	CreatedAt  time.Time `json:"created_at"`
}

// FindYubiKeys returns an error in non-CGO builds
func FindYubiKeys() ([]*YubiKey, error) {
	return nil, ErrYubiKeyNotSupported
}

// OpenYubiKey returns an error in non-CGO builds
func OpenYubiKey(serial uint32) (*YubiKey, error) {
	return nil, ErrYubiKeyNotSupported
}

// Close is a no-op in non-CGO builds
func (yk *YubiKey) Close() error {
	return nil
}

// Serial returns the YubiKey serial number
func (yk *YubiKey) Serial() uint32 {
	return yk.serial
}

// Card returns nil in non-CGO builds
func (yk *YubiKey) Card() interface{} {
	return nil
}

// ChangePIN returns an error in non-CGO builds
func (yk *YubiKey) ChangePIN(oldPIN, newPIN string) error {
	return ErrYubiKeyNotSupported
}

// GenerateIdentityOnYubiKey returns an error in non-CGO builds
func GenerateIdentityOnYubiKey(yk *YubiKey, name string, pin string, touchCallback func(string)) (*YubiKeyIdentity, error) {
	return nil, ErrYubiKeyNotSupported
}

// Fingerprint returns a fingerprint of the identity
func (y *YubiKeyIdentity) Fingerprint() string {
	return ""
}

// Sign returns an error in non-CGO builds
func (yk *YubiKey) Sign(data []byte, pin string, touchCallback func(string)) ([]byte, error) {
	return nil, ErrYubiKeyNotSupported
}

// ECDH returns an error in non-CGO builds
func (yk *YubiKey) ECDH(peerPub []byte, pin string, touchCallback func(string)) ([]byte, error) {
	return nil, ErrYubiKeyNotSupported
}

// GetSigningPublicKey returns an error in non-CGO builds
func (yk *YubiKey) GetSigningPublicKey() ([]byte, error) {
	return nil, ErrYubiKeyNotSupported
}

// GetECDHPublicKey returns an error in non-CGO builds
func (yk *YubiKey) GetECDHPublicKey() ([]byte, error) {
	return nil, ErrYubiKeyNotSupported
}

// ImportSigningKey returns an error in non-CGO builds
func (yk *YubiKey) ImportSigningKey(privateKey ed25519.PrivateKey, touchCallback func(string)) error {
	return ErrYubiKeyNotSupported
}

// GenerateECDHKey returns an error in non-CGO builds
func (yk *YubiKey) GenerateECDHKey(touchCallback func(string)) ([]byte, error) {
	return nil, ErrYubiKeyNotSupported
}

// PINCache stubs for non-CGO builds
type PINCache struct{}

// GetCachedPIN returns empty in non-CGO builds
func GetCachedPIN() (string, bool) {
	return "", false
}

// CachePIN is a no-op in non-CGO builds
func CachePIN(pin string, duration time.Duration) {}

// ClearCachedPIN is a no-op in non-CGO builds
func ClearCachedPIN() {}

// EncryptForYubiKey returns an error in non-CGO builds
func EncryptForYubiKey(plaintext []byte, recipientECDHPub []byte) ([]byte, error) {
	return nil, ErrYubiKeyNotSupported
}

// DecryptWithYubiKey returns an error in non-CGO builds
func DecryptWithYubiKey(yk *YubiKey, data []byte, pin string, touchCallback func(string)) ([]byte, error) {
	return nil, ErrYubiKeyNotSupported
}

// HasYubiKeySupport returns false in non-CGO builds
func HasYubiKeySupport() bool {
	return false
}
