package crypto

import (
	"crypto/ed25519"
	"errors"
	"fmt"
)

// Algorithm identifiers for signature schemes
const (
	AlgorithmEd25519 = "ed25519"
	AlgorithmMLDSA   = "mldsa" // Future: ML-DSA post-quantum signatures
)

// Signer is an interface for cryptographic signing operations.
// This abstraction allows for future migration to ML-DSA while
// maintaining backwards compatibility with Ed25519.
type Signer interface {
	// Sign produces a signature for the given message
	Sign(message []byte) ([]byte, error)

	// Verify checks if a signature is valid for a message and public key
	Verify(pubkey, message, signature []byte) bool

	// Algorithm returns the signature algorithm identifier
	Algorithm() string

	// PublicKey returns the public key bytes
	PublicKey() []byte
}

// Verifier is an interface for verifying signatures without signing capability
type Verifier interface {
	// Verify checks if a signature is valid for a message and public key
	Verify(pubkey, message, signature []byte) bool

	// Algorithm returns the signature algorithm identifier
	Algorithm() string
}

// Ed25519Signer implements the Signer interface using Ed25519
type Ed25519Signer struct {
	privateKey ed25519.PrivateKey
	publicKey  ed25519.PublicKey
}

// NewEd25519Signer creates a new Ed25519Signer from a private key
func NewEd25519Signer(privateKey ed25519.PrivateKey) *Ed25519Signer {
	return &Ed25519Signer{
		privateKey: privateKey,
		publicKey:  privateKey.Public().(ed25519.PublicKey),
	}
}

// Sign produces an Ed25519 signature for the given message
func (s *Ed25519Signer) Sign(message []byte) ([]byte, error) {
	if s.privateKey == nil {
		return nil, errors.New("no private key available")
	}
	return ed25519.Sign(s.privateKey, message), nil
}

// Verify checks if an Ed25519 signature is valid
func (s *Ed25519Signer) Verify(pubkey, message, signature []byte) bool {
	if len(pubkey) != ed25519.PublicKeySize {
		return false
	}
	if len(signature) != ed25519.SignatureSize {
		return false
	}
	return ed25519.Verify(pubkey, message, signature)
}

// Algorithm returns "ed25519"
func (s *Ed25519Signer) Algorithm() string {
	return AlgorithmEd25519
}

// PublicKey returns the public key bytes
func (s *Ed25519Signer) PublicKey() []byte {
	return []byte(s.publicKey)
}

// Ed25519Verifier implements verification-only operations
type Ed25519Verifier struct{}

// NewEd25519Verifier creates a new Ed25519Verifier
func NewEd25519Verifier() *Ed25519Verifier {
	return &Ed25519Verifier{}
}

// Verify checks if an Ed25519 signature is valid
func (v *Ed25519Verifier) Verify(pubkey, message, signature []byte) bool {
	if len(pubkey) != ed25519.PublicKeySize {
		return false
	}
	if len(signature) != ed25519.SignatureSize {
		return false
	}
	return ed25519.Verify(pubkey, message, signature)
}

// Algorithm returns "ed25519"
func (v *Ed25519Verifier) Algorithm() string {
	return AlgorithmEd25519
}

// VerifySignature verifies a signature using the appropriate algorithm
func VerifySignature(algorithm string, pubkey, message, signature []byte) (bool, error) {
	switch algorithm {
	case AlgorithmEd25519:
		return NewEd25519Verifier().Verify(pubkey, message, signature), nil
	case AlgorithmMLDSA:
		return NewMLDSA65Verifier().Verify(pubkey, message, signature), nil
	case AlgorithmHybrid:
		// Hybrid signatures require special handling - caller must provide both pubkeys
		return false, errors.New("use VerifyHybridSignature for hybrid signatures")
	default:
		return false, fmt.Errorf("unknown signature algorithm: %s", algorithm)
	}
}

// GetVerifier returns a Verifier for the given algorithm
func GetVerifier(algorithm string) (Verifier, error) {
	switch algorithm {
	case AlgorithmEd25519:
		return NewEd25519Verifier(), nil
	case AlgorithmMLDSA:
		return NewMLDSA65Verifier(), nil
	default:
		return nil, fmt.Errorf("unknown signature algorithm: %s", algorithm)
	}
}

// SignerFromIdentity creates a Signer from an Identity
func SignerFromIdentity(id *Identity) Signer {
	return NewEd25519Signer(id.signingKey)
}
