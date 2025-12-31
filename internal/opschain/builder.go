package opschain

import (
	"crypto/ed25519"
	"fmt"
	"time"

	"envctl.dev/go/envctl/internal/crypto"
)

// Builder creates new operations for a chain
type Builder struct {
	identity *crypto.Identity
}

// NewBuilder creates a new operation builder
func NewBuilder(identity *crypto.Identity) *Builder {
	return &Builder{
		identity: identity,
	}
}

// BuildSetOp creates a new set operation.
// The value is encrypted to self (the identity's own public key).
func (b *Builder) BuildSetOp(seq uint64, prevHash []byte, key, value string) (*Operation, error) {
	if key == "" {
		return nil, fmt.Errorf("key cannot be empty")
	}

	// Encrypt value to self
	encryptedValue, err := crypto.EncryptForIdentity([]byte(value), b.identity.Public())
	if err != nil {
		return nil, fmt.Errorf("encrypt value: %w", err)
	}

	op := &Operation{
		Seq:            seq,
		Timestamp:      time.Now().UTC(),
		Author:         b.identity.SigningPublicKey(),
		Op:             OpSet,
		Key:            key,
		EncryptedValue: encryptedValue,
		PrevHash:       prevHash,
	}

	// Sign the operation
	msg := op.SigningMessage()
	op.Signature = ed25519.Sign(b.identity.SigningPrivateKey(), msg)

	return op, nil
}

// BuildDeleteOp creates a new delete operation
func (b *Builder) BuildDeleteOp(seq uint64, prevHash []byte, key string) (*Operation, error) {
	if key == "" {
		return nil, fmt.Errorf("key cannot be empty")
	}

	op := &Operation{
		Seq:       seq,
		Timestamp: time.Now().UTC(),
		Author:    b.identity.SigningPublicKey(),
		Op:        OpDelete,
		Key:       key,
		PrevHash:  prevHash,
	}

	// Sign the operation
	msg := op.SigningMessage()
	op.Signature = ed25519.Sign(b.identity.SigningPrivateKey(), msg)

	return op, nil
}

// ReencryptOp re-encrypts an operation's value with a new identity.
// Used when receiving operations from peers - the peer sends plaintext over
// the encrypted P2P channel, and the recipient re-encrypts for their own storage.
func ReencryptOp(op *Operation, plaintextValue []byte, recipientIdentity *crypto.Identity) (*Operation, error) {
	if op.Op != OpSet {
		// Delete operations don't have values to re-encrypt
		return op.Clone(), nil
	}

	// Encrypt value to recipient's own key
	encryptedValue, err := crypto.EncryptForIdentity(plaintextValue, recipientIdentity.Public())
	if err != nil {
		return nil, fmt.Errorf("encrypt value for storage: %w", err)
	}

	// Clone the operation with new encrypted value
	// Note: We keep the original signature and author - this is the original op
	// We're just re-encrypting the value for local storage
	clone := op.Clone()
	clone.EncryptedValue = encryptedValue

	return clone, nil
}

// DecryptValue decrypts the operation's value using the provided identity
func DecryptValue(op *Operation, identity *crypto.Identity) (string, error) {
	if op.Op != OpSet {
		return "", fmt.Errorf("cannot decrypt delete operation")
	}

	if len(op.EncryptedValue) == 0 {
		return "", fmt.Errorf("no encrypted value")
	}

	plaintext, err := crypto.DecryptWithIdentity(op.EncryptedValue, identity)
	if err != nil {
		return "", fmt.Errorf("decrypt value: %w", err)
	}

	return string(plaintext), nil
}
