// Package keychain provides secure storage for the identity passphrase
// using the system keychain (macOS Keychain, Linux Secret Service, Windows Credential Manager).
package keychain

import (
	"errors"

	"github.com/zalando/go-keyring"
)

const (
	// ServiceName is the keychain service identifier
	ServiceName = "envctl"
	// AccountName is the keychain account identifier
	AccountName = "identity-passphrase"
)

var (
	// ErrNotFound is returned when no passphrase is stored in the keychain
	ErrNotFound = errors.New("passphrase not found in keychain")
)

// Store saves the passphrase to the system keychain.
// On macOS, this uses the Keychain.
// On Linux, this uses the Secret Service API (GNOME Keyring, KWallet, etc).
// On Windows, this uses Credential Manager.
func Store(passphrase string) error {
	return keyring.Set(ServiceName, AccountName, passphrase)
}

// Get retrieves the passphrase from the system keychain.
// Returns ErrNotFound if no passphrase is stored.
func Get() (string, error) {
	pass, err := keyring.Get(ServiceName, AccountName)
	if err != nil {
		if errors.Is(err, keyring.ErrNotFound) {
			return "", ErrNotFound
		}
		return "", err
	}
	return pass, nil
}

// Delete removes the passphrase from the system keychain.
func Delete() error {
	err := keyring.Delete(ServiceName, AccountName)
	if err != nil && errors.Is(err, keyring.ErrNotFound) {
		return nil // Already deleted, not an error
	}
	return err
}

// IsAvailable checks if the system keychain is available.
// This can fail on headless Linux systems without a secret service.
func IsAvailable() bool {
	// Try to get a non-existent key - if we get ErrNotFound, keychain works
	// If we get a different error, keychain may not be available
	_, err := keyring.Get(ServiceName, "test-availability")
	return err == nil || errors.Is(err, keyring.ErrNotFound)
}
