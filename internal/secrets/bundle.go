// Package secrets handles encrypted environment variable storage
package secrets

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/mlkem"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"

	"envctl.dev/go/envctl/internal/crypto"
)

// BundleVersion is the current CI bundle format version
const BundleVersion = 2

// CIBundle represents an encrypted secrets bundle for CI/CD
type CIBundle struct {
	Version             int            `json:"version"`
	Format              string         `json:"format"`
	Project             string         `json:"project"`
	Environment         string         `json:"environment"`
	ExportedAt          time.Time      `json:"exported_at"`
	ExporterFingerprint string         `json:"exporter_fingerprint"`
	Encryption          EncryptionMeta `json:"encryption"`
	Ciphertext          string         `json:"ciphertext"`
	Signature           string         `json:"signature,omitempty"`
}

// EncryptionMeta contains encryption parameters
type EncryptionMeta struct {
	Algorithm     string `json:"algorithm"`
	KEMCiphertext string `json:"kem_ciphertext"` // ML-KEM encapsulated key
	Nonce         string `json:"nonce"`
}

// BundleMeta contains metadata for bundle creation
type BundleMeta struct {
	Project             string
	Environment         string
	ExporterFingerprint string
}

// CIKeyPair represents a CI encryption keypair
type CIKeyPair struct {
	PublicKey  []byte // ML-KEM-768 encapsulation key (1184 bytes)
	PrivateKey []byte // ML-KEM-768 decapsulation key (2400 bytes)
}

// AES-256-GCM parameters
const (
	aesKeySize   = 32 // AES-256
	aesNonceSize = 12
)

// ML-KEM-768 key sizes
const (
	mlkemPublicKeySize  = 1184
	mlkemPrivateKeySize = 64   // Seed form "d || z"
	mlkemCiphertextSize = 1088
)

// Common errors
var (
	ErrInvalidKey       = errors.New("invalid CI key")
	ErrInvalidPublicKey = errors.New("invalid CI public key: must be 1184 bytes (ML-KEM-768)")
	ErrInvalidBundle    = errors.New("invalid bundle format")
	ErrDecryptFailed    = errors.New("decryption failed: invalid key or corrupted bundle")
	ErrSignatureInvalid = errors.New("bundle signature verification failed")
	ErrVersionMismatch  = errors.New("unsupported bundle version")
	ErrNoCIKey          = errors.New("no CI key found for this project")
	ErrCIKeyExists      = errors.New("CI key already exists for this project (use --force to replace)")
)

// GenerateCIKeyPair generates an ML-KEM-768 keypair for CI encryption
func GenerateCIKeyPair() (*CIKeyPair, error) {
	// Generate ML-KEM-768 key pair
	decapKey, err := mlkem.GenerateKey768()
	if err != nil {
		return nil, fmt.Errorf("generate ML-KEM keys: %w", err)
	}

	encapKey := decapKey.EncapsulationKey()

	return &CIKeyPair{
		PublicKey:  encapKey.Bytes(),
		PrivateKey: decapKey.Bytes(),
	}, nil
}

// EncodePrivateKey encodes the private key as base64 for storage in CI platform
func (kp *CIKeyPair) EncodePrivateKey() string {
	return base64.StdEncoding.EncodeToString(kp.PrivateKey)
}

// EncodePublicKey encodes the public key as base64 for storage in opschain
func (kp *CIKeyPair) EncodePublicKey() string {
	return base64.StdEncoding.EncodeToString(kp.PublicKey)
}

// ParseCIPrivateKey parses a base64-encoded ML-KEM-768 private key
func ParseCIPrivateKey(encoded string) ([]byte, error) {
	key, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("decode private key: %w", err)
	}

	if len(key) != mlkemPrivateKeySize {
		return nil, fmt.Errorf("%w: got %d bytes, expected %d", ErrInvalidKey, len(key), mlkemPrivateKeySize)
	}

	return key, nil
}

// ParseCIPublicKey parses a base64-encoded ML-KEM-768 public key
func ParseCIPublicKey(encoded string) ([]byte, error) {
	key, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("decode public key: %w", err)
	}

	if len(key) != mlkemPublicKeySize {
		return nil, fmt.Errorf("%w: got %d bytes, expected %d", ErrInvalidPublicKey, len(key), mlkemPublicKeySize)
	}

	return key, nil
}

// EncryptBundle encrypts variables into a CI bundle using ML-KEM-768 + AES-256-GCM
// This uses the KEM/DEM hybrid pattern: ML-KEM establishes a shared secret,
// AES-GCM encrypts the actual data.
func EncryptBundle(vars map[string]string, publicKey []byte, meta BundleMeta) (*CIBundle, error) {
	// Validate public key length
	if len(publicKey) != mlkemPublicKeySize {
		return nil, ErrInvalidPublicKey
	}

	// Reconstruct ML-KEM encapsulation key from bytes
	encapKey, err := mlkem.NewEncapsulationKey768(publicKey)
	if err != nil {
		return nil, fmt.Errorf("parse public key: %w", err)
	}

	// Encapsulate: generates shared secret and ciphertext
	// The shared secret can only be recovered by the holder of the private key
	sharedSecret, kemCiphertext := encapKey.Encapsulate()
	defer crypto.ZeroBytes(sharedSecret)

	// Serialize variables to JSON
	plaintext, err := json.Marshal(vars)
	if err != nil {
		return nil, fmt.Errorf("marshal variables: %w", err)
	}
	defer crypto.ZeroBytes(plaintext)

	// Create AES-256-GCM cipher using the shared secret as key
	block, err := aes.NewCipher(sharedSecret)
	if err != nil {
		return nil, fmt.Errorf("create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create GCM: %w", err)
	}

	// Generate random nonce
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("generate nonce: %w", err)
	}

	// Use project/environment as Additional Authenticated Data (AAD)
	// This binds the ciphertext to these values - prevents bundle reuse
	aad := []byte(fmt.Sprintf("%s/%s", meta.Project, meta.Environment))

	// Encrypt with AEAD
	ciphertext := gcm.Seal(nil, nonce, plaintext, aad)

	return &CIBundle{
		Version:             BundleVersion,
		Format:              "ci-bundle",
		Project:             meta.Project,
		Environment:         meta.Environment,
		ExportedAt:          time.Now().UTC(),
		ExporterFingerprint: meta.ExporterFingerprint,
		Encryption: EncryptionMeta{
			Algorithm:     "ML-KEM-768+AES-256-GCM",
			KEMCiphertext: base64.StdEncoding.EncodeToString(kemCiphertext),
			Nonce:         base64.StdEncoding.EncodeToString(nonce),
		},
		Ciphertext: base64.StdEncoding.EncodeToString(ciphertext),
	}, nil
}

// DecryptBundle decrypts a CI bundle and returns the variables
func DecryptBundle(bundle *CIBundle, privateKey []byte) (map[string]string, error) {
	// Validate version
	if bundle.Version != BundleVersion {
		return nil, fmt.Errorf("%w: got %d, expected %d", ErrVersionMismatch, bundle.Version, BundleVersion)
	}

	// Validate private key length
	if len(privateKey) != mlkemPrivateKeySize {
		return nil, fmt.Errorf("%w: got %d bytes, expected %d", ErrInvalidKey, len(privateKey), mlkemPrivateKeySize)
	}

	// Reconstruct ML-KEM decapsulation key from bytes
	decapKey, err := mlkem.NewDecapsulationKey768(privateKey)
	if err != nil {
		return nil, fmt.Errorf("parse private key: %w", err)
	}

	// Decode KEM ciphertext
	kemCiphertext, err := base64.StdEncoding.DecodeString(bundle.Encryption.KEMCiphertext)
	if err != nil {
		return nil, fmt.Errorf("decode KEM ciphertext: %w", err)
	}

	// Decapsulate: recover the shared secret
	sharedSecret, err := decapKey.Decapsulate(kemCiphertext)
	if err != nil {
		return nil, ErrDecryptFailed
	}
	defer crypto.ZeroBytes(sharedSecret)

	// Decode nonce
	nonce, err := base64.StdEncoding.DecodeString(bundle.Encryption.Nonce)
	if err != nil {
		return nil, fmt.Errorf("decode nonce: %w", err)
	}

	// Decode ciphertext
	ciphertext, err := base64.StdEncoding.DecodeString(bundle.Ciphertext)
	if err != nil {
		return nil, fmt.Errorf("decode ciphertext: %w", err)
	}

	// Create AES-256-GCM cipher using the shared secret
	block, err := aes.NewCipher(sharedSecret)
	if err != nil {
		return nil, fmt.Errorf("create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create GCM: %w", err)
	}

	// Reconstruct AAD from bundle metadata
	aad := []byte(fmt.Sprintf("%s/%s", bundle.Project, bundle.Environment))

	// Decrypt with AEAD
	plaintext, err := gcm.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		return nil, ErrDecryptFailed
	}
	defer crypto.ZeroBytes(plaintext)

	// Unmarshal variables
	var vars map[string]string
	if err := json.Unmarshal(plaintext, &vars); err != nil {
		return nil, fmt.Errorf("unmarshal variables: %w", err)
	}

	return vars, nil
}

// SignBundle signs a bundle using the exporter's identity
// The signature covers all metadata plus the ciphertext
func SignBundle(bundle *CIBundle, identity *crypto.Identity) error {
	// Create canonical representation for signing
	sigData := bundleSignatureData(bundle)

	// Sign with Ed25519
	signature := identity.Sign(sigData)
	bundle.Signature = base64.StdEncoding.EncodeToString(signature)

	return nil
}

// VerifyBundle verifies a bundle's signature against a public key
func VerifyBundle(bundle *CIBundle, pubKey []byte) error {
	if bundle.Signature == "" {
		return errors.New("bundle has no signature")
	}

	// Decode signature
	signature, err := base64.StdEncoding.DecodeString(bundle.Signature)
	if err != nil {
		return fmt.Errorf("decode signature: %w", err)
	}

	// Create canonical representation for verification
	sigData := bundleSignatureData(bundle)

	// Verify Ed25519 signature
	if !ed25519.Verify(pubKey, sigData, signature) {
		return ErrSignatureInvalid
	}

	return nil
}

// bundleSignatureData creates a canonical byte representation for signing
func bundleSignatureData(bundle *CIBundle) []byte {
	// Hash the canonical representation to create a fixed-size message
	h := sha256.New()
	h.Write([]byte(fmt.Sprintf("ci-bundle-v%d\n", bundle.Version)))
	h.Write([]byte(bundle.Project + "\n"))
	h.Write([]byte(bundle.Environment + "\n"))
	h.Write([]byte(bundle.ExportedAt.Format(time.RFC3339Nano) + "\n"))
	h.Write([]byte(bundle.ExporterFingerprint + "\n"))
	h.Write([]byte(bundle.Encryption.Algorithm + "\n"))
	h.Write([]byte(bundle.Encryption.KEMCiphertext + "\n"))
	h.Write([]byte(bundle.Encryption.Nonce + "\n"))
	h.Write([]byte(bundle.Ciphertext))
	return h.Sum(nil)
}

// SerializeBundle serializes a bundle to JSON
func SerializeBundle(bundle *CIBundle) ([]byte, error) {
	return json.MarshalIndent(bundle, "", "  ")
}

// ParseBundle parses a bundle from JSON
func ParseBundle(data []byte) (*CIBundle, error) {
	var bundle CIBundle
	if err := json.Unmarshal(data, &bundle); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidBundle, err)
	}

	if bundle.Format != "ci-bundle" {
		return nil, fmt.Errorf("%w: expected format 'ci-bundle', got '%s'", ErrInvalidBundle, bundle.Format)
	}

	return &bundle, nil
}
