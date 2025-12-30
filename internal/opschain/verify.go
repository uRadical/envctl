package opschain

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"fmt"
)

// Verifier verifies operations and chains
type Verifier struct {
	// authorizedAuthors is a list of public keys that are allowed to create operations.
	// If empty, any author with a valid signature is accepted.
	authorizedAuthors map[string]bool
}

// NewVerifier creates a new verifier
func NewVerifier() *Verifier {
	return &Verifier{
		authorizedAuthors: make(map[string]bool),
	}
}

// AddAuthorizedAuthor adds a public key to the list of authorized authors
func (v *Verifier) AddAuthorizedAuthor(pubkey []byte) {
	v.authorizedAuthors[string(pubkey)] = true
}

// VerifySignature verifies the Ed25519 signature on an operation
func (v *Verifier) VerifySignature(op *Operation) error {
	if len(op.Author) != ed25519.PublicKeySize {
		return fmt.Errorf("invalid author public key size: %d", len(op.Author))
	}

	if len(op.Signature) != ed25519.SignatureSize {
		return fmt.Errorf("invalid signature size: %d", len(op.Signature))
	}

	msg := op.SigningMessage()
	if !ed25519.Verify(op.Author, msg, op.Signature) {
		return errors.New("signature verification failed")
	}

	return nil
}

// VerifyAuthor checks if the operation's author is authorized
func (v *Verifier) VerifyAuthor(op *Operation) error {
	if len(v.authorizedAuthors) == 0 {
		// No author restrictions
		return nil
	}

	if !v.authorizedAuthors[string(op.Author)] {
		return fmt.Errorf("unauthorized author: %s", op.AuthorFingerprint())
	}

	return nil
}

// VerifyChainLink verifies that this operation correctly links to the previous one
func (v *Verifier) VerifyChainLink(op *Operation, prevOp *Operation) error {
	if op.Seq == 0 {
		// First operation should not have a previous hash
		if len(op.PrevHash) != 0 {
			return errors.New("first operation should not have prev_hash")
		}
		if prevOp != nil {
			return errors.New("first operation should not have previous operation")
		}
		return nil
	}

	if prevOp == nil {
		return errors.New("previous operation is required for seq > 0")
	}

	// Check sequence numbers are consecutive
	if op.Seq != prevOp.Seq+1 {
		return fmt.Errorf("sequence gap: expected %d, got %d", prevOp.Seq+1, op.Seq)
	}

	// Verify prev_hash matches
	expectedHash := prevOp.Hash()
	if !bytes.Equal(op.PrevHash, expectedHash) {
		return fmt.Errorf("prev_hash mismatch at seq %d", op.Seq)
	}

	return nil
}

// VerifyOperation performs full verification of an operation
func (v *Verifier) VerifyOperation(op *Operation, prevOp *Operation) error {
	// Basic validation
	if err := op.Validate(); err != nil {
		return fmt.Errorf("validation failed: %w", err)
	}

	// Signature verification
	if err := v.VerifySignature(op); err != nil {
		return fmt.Errorf("signature failed: %w", err)
	}

	// Author authorization
	if err := v.VerifyAuthor(op); err != nil {
		return fmt.Errorf("author failed: %w", err)
	}

	// Chain linking
	if err := v.VerifyChainLink(op, prevOp); err != nil {
		return fmt.Errorf("chain link failed: %w", err)
	}

	return nil
}

// VerifyChain verifies an entire chain of operations
func (v *Verifier) VerifyChain(ops []*Operation) error {
	for i, op := range ops {
		var prevOp *Operation
		if i > 0 {
			prevOp = ops[i-1]
		}

		if err := v.VerifyOperation(op, prevOp); err != nil {
			return fmt.Errorf("operation %d: %w", i, err)
		}
	}

	return nil
}

// VerifySignatureOnly verifies just the signature without chain context.
// Useful for verifying incoming operations before full chain integration.
func VerifySignatureOnly(op *Operation) error {
	if len(op.Author) != ed25519.PublicKeySize {
		return fmt.Errorf("invalid author public key size: %d", len(op.Author))
	}

	if len(op.Signature) != ed25519.SignatureSize {
		return fmt.Errorf("invalid signature size: %d", len(op.Signature))
	}

	msg := op.SigningMessage()
	if !ed25519.Verify(op.Author, msg, op.Signature) {
		return errors.New("signature verification failed")
	}

	return nil
}
