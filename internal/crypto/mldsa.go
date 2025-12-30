package crypto

import (
	"crypto/rand"
	"fmt"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
)

// ML-DSA-65 key and signature sizes
const (
	MLDSAPublicKeySize  = 1952  // ML-DSA-65 public key size
	MLDSAPrivateKeySize = 4032  // ML-DSA-65 private key size
	MLDSASignatureSize  = 3309  // ML-DSA-65 signature size
	MLDSASeedSize       = 32    // Seed size for deterministic key generation
)

// GenerateMLDSA65 generates an ML-DSA-65 keypair
func GenerateMLDSA65() (publicKey, privateKey []byte, err error) {
	pub, priv, err := mldsa65.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generate ML-DSA-65: %w", err)
	}

	pubBytes, err := pub.MarshalBinary()
	if err != nil {
		return nil, nil, fmt.Errorf("marshal public key: %w", err)
	}

	privBytes, err := priv.MarshalBinary()
	if err != nil {
		return nil, nil, fmt.Errorf("marshal private key: %w", err)
	}

	return pubBytes, privBytes, nil
}

// GenerateMLDSA65FromSeed generates an ML-DSA-65 keypair deterministically from a seed
func GenerateMLDSA65FromSeed(seed []byte) (publicKey, privateKey []byte, err error) {
	if len(seed) != MLDSASeedSize {
		return nil, nil, fmt.Errorf("seed must be %d bytes, got %d", MLDSASeedSize, len(seed))
	}

	var seedArr [MLDSASeedSize]byte
	copy(seedArr[:], seed)

	pub, priv := mldsa65.NewKeyFromSeed(&seedArr)

	pubBytes, err := pub.MarshalBinary()
	if err != nil {
		return nil, nil, fmt.Errorf("marshal public key: %w", err)
	}

	privBytes, err := priv.MarshalBinary()
	if err != nil {
		return nil, nil, fmt.Errorf("marshal private key: %w", err)
	}

	return pubBytes, privBytes, nil
}

// SignMLDSA65 signs data with ML-DSA-65
func SignMLDSA65(privateKey, data []byte) ([]byte, error) {
	var priv mldsa65.PrivateKey
	if err := priv.UnmarshalBinary(privateKey); err != nil {
		return nil, fmt.Errorf("unmarshal private key: %w", err)
	}

	sig := make([]byte, MLDSASignatureSize)
	// Sign with empty context (nil) and randomized=false for deterministic signatures
	if err := mldsa65.SignTo(&priv, data, nil, false, sig); err != nil {
		return nil, fmt.Errorf("sign: %w", err)
	}

	return sig, nil
}

// VerifyMLDSA65 verifies an ML-DSA-65 signature
func VerifyMLDSA65(publicKey, data, signature []byte) bool {
	var pub mldsa65.PublicKey
	if err := pub.UnmarshalBinary(publicKey); err != nil {
		return false
	}

	// Verify with empty context (nil)
	return mldsa65.Verify(&pub, data, nil, signature)
}

// MLDSA65Signer implements the Signer interface for ML-DSA-65
type MLDSA65Signer struct {
	privateKey []byte
	publicKey  []byte
}

// NewMLDSA65Signer creates a new ML-DSA-65 signer
func NewMLDSA65Signer(privateKey, publicKey []byte) *MLDSA65Signer {
	return &MLDSA65Signer{
		privateKey: privateKey,
		publicKey:  publicKey,
	}
}

// Sign produces an ML-DSA-65 signature for the given message
func (s *MLDSA65Signer) Sign(message []byte) ([]byte, error) {
	return SignMLDSA65(s.privateKey, message)
}

// Verify checks if an ML-DSA-65 signature is valid
func (s *MLDSA65Signer) Verify(pubkey, message, signature []byte) bool {
	return VerifyMLDSA65(pubkey, message, signature)
}

// Algorithm returns "mldsa"
func (s *MLDSA65Signer) Algorithm() string {
	return AlgorithmMLDSA
}

// PublicKey returns the public key bytes
func (s *MLDSA65Signer) PublicKey() []byte {
	return s.publicKey
}

// MLDSA65Verifier implements verification-only operations for ML-DSA-65
type MLDSA65Verifier struct{}

// NewMLDSA65Verifier creates a new ML-DSA-65 verifier
func NewMLDSA65Verifier() *MLDSA65Verifier {
	return &MLDSA65Verifier{}
}

// Verify checks if an ML-DSA-65 signature is valid
func (v *MLDSA65Verifier) Verify(pubkey, message, signature []byte) bool {
	return VerifyMLDSA65(pubkey, message, signature)
}

// Algorithm returns "mldsa"
func (v *MLDSA65Verifier) Algorithm() string {
	return AlgorithmMLDSA
}
