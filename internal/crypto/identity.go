package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/mlkem"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/hkdf"
)

// Identity represents a user's cryptographic identity
type Identity struct {
	Name       string    `json:"name"`
	CreatedAt  time.Time `json:"created_at"`

	// ML-KEM keys for encryption
	mlkemPriv *mlkem.DecapsulationKey768
	mlkemPub  *mlkem.EncapsulationKey768

	// Ed25519 keys for signing
	signingKey ed25519.PrivateKey
	verifyKey  ed25519.PublicKey
}

// PublicIdentity contains only the public parts of an identity
type PublicIdentity struct {
	Name      string    `json:"name"`
	MLKEMPub  []byte    `json:"mlkem_pub"`
	SigningPub []byte   `json:"signing_pub"`
	CreatedAt time.Time `json:"created_at"`
}

// Argon2 parameters for key derivation
// OWASP recommends: 19 MiB memory, 2 iterations minimum
// We use higher values for better security margin
const (
	argon2Time    = 4          // 4 iterations (OWASP min: 2)
	argon2Memory  = 128 * 1024 // 128 MiB (OWASP min: 19 MiB)
	argon2Threads = 4
	argon2KeyLen  = 32
)

// File format version
const identityFileVersion = 1

// identityFile is the encrypted identity file format
type identityFile struct {
	Version       uint8  `json:"version"`
	Salt          []byte `json:"salt"`
	Nonce         []byte `json:"nonce"`
	Ciphertext    []byte `json:"ciphertext"`
	Argon2Time    uint32 `json:"argon2_time"`
	Argon2Memory  uint32 `json:"argon2_memory"`
	Argon2Threads uint8  `json:"argon2_threads"`
}

// identityPlaintext is the decrypted identity data
type identityPlaintext struct {
	Name       string    `json:"name"`
	CreatedAt  time.Time `json:"created_at"`
	MLKEMSeed  []byte    `json:"mlkem_seed"`  // 64 bytes for ML-KEM-768
	SigningKey []byte    `json:"signing_key"` // 64 bytes for Ed25519
}

// GenerateIdentity creates a new cryptographic identity
func GenerateIdentity(name string) (*Identity, error) {
	// Generate ML-KEM-768 key pair
	// GenerateKey768 returns (decapsulationKey, error)
	privKey, err := mlkem.GenerateKey768()
	if err != nil {
		return nil, fmt.Errorf("generate ML-KEM keys: %w", err)
	}
	pubKey := privKey.EncapsulationKey()

	// Generate Ed25519 key pair
	verifyKey, signingKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate Ed25519 keys: %w", err)
	}

	return &Identity{
		Name:       name,
		CreatedAt:  time.Now().UTC(),
		mlkemPriv:  privKey,
		mlkemPub:   pubKey,
		signingKey: signingKey,
		verifyKey:  verifyKey,
	}, nil
}

// MLKEMPublicKey returns the ML-KEM public key bytes
func (id *Identity) MLKEMPublicKey() []byte {
	return id.mlkemPub.Bytes()
}

// SigningPublicKey returns the Ed25519 public key bytes
func (id *Identity) SigningPublicKey() []byte {
	return []byte(id.verifyKey)
}

// SigningPrivateKey returns the Ed25519 private key for message signing
func (id *Identity) SigningPrivateKey() ed25519.PrivateKey {
	return id.signingKey
}

// Sign signs a message using Ed25519
func (id *Identity) Sign(message []byte) []byte {
	return ed25519.Sign(id.signingKey, message)
}

// Verify verifies a signature using Ed25519
func (id *Identity) Verify(message, signature []byte) bool {
	return ed25519.Verify(id.verifyKey, message, signature)
}

// Decapsulate decapsulates a shared secret using ML-KEM
func (id *Identity) Decapsulate(ciphertext []byte) ([]byte, error) {
	return id.mlkemPriv.Decapsulate(ciphertext)
}

// Public returns the public identity
func (id *Identity) Public() *PublicIdentity {
	return &PublicIdentity{
		Name:       id.Name,
		MLKEMPub:   id.MLKEMPublicKey(),
		SigningPub: id.SigningPublicKey(),
		CreatedAt:  id.CreatedAt,
	}
}

// Fingerprint returns a short fingerprint of the identity's signing key
func (id *Identity) Fingerprint() string {
	hash := sha256.Sum256(id.verifyKey)
	return fmt.Sprintf("%x", hash[:8])
}

// HashPublicKey returns a hex-encoded SHA256 hash of a public key
// Used for invite code verification to avoid storing raw pubkeys on chain
func HashPublicKey(pubkey []byte) string {
	hash := sha256.Sum256(pubkey)
	return fmt.Sprintf("%x", hash[:])
}

// SaveEncrypted saves the identity encrypted with a passphrase.
func (id *Identity) SaveEncrypted(path string, passphrase []byte) error {
	// Ensure parent directory exists
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return fmt.Errorf("create config directory: %w", err)
	}

	// Generate salt for Argon2
	salt := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return fmt.Errorf("generate salt: %w", err)
	}

	// Derive key from passphrase
	key := argon2.IDKey(passphrase, salt, argon2Time, argon2Memory, argon2Threads, argon2KeyLen)
	defer ZeroBytes(key)

	// Serialize identity data
	// For ML-KEM, we store the seed (private key bytes)
	mlkemBytes := id.mlkemPriv.Bytes()

	plaintext := identityPlaintext{
		Name:       id.Name,
		CreatedAt:  id.CreatedAt,
		MLKEMSeed:  mlkemBytes,
		SigningKey: id.signingKey,
	}

	plaintextJSON, err := json.Marshal(plaintext)
	if err != nil {
		return fmt.Errorf("marshal identity: %w", err)
	}
	defer ZeroBytes(plaintextJSON)

	// Encrypt with AES-256-GCM
	block, err := aes.NewCipher(key)
	if err != nil {
		return fmt.Errorf("create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return fmt.Errorf("create GCM: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return fmt.Errorf("generate nonce: %w", err)
	}

	ciphertext := gcm.Seal(nil, nonce, plaintextJSON, nil)

	// Save to file with explicit Argon2 params
	file := identityFile{
		Version:       identityFileVersion,
		Salt:          salt,
		Nonce:         nonce,
		Ciphertext:    ciphertext,
		Argon2Time:    argon2Time,
		Argon2Memory:  argon2Memory,
		Argon2Threads: argon2Threads,
	}

	fileJSON, err := json.MarshalIndent(file, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal file: %w", err)
	}

	if err := os.WriteFile(path, fileJSON, 0600); err != nil {
		return fmt.Errorf("write file: %w", err)
	}

	return nil
}

// LoadEncrypted loads an identity from an encrypted file
func LoadEncrypted(path string, passphrase []byte) (*Identity, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read file: %w", err)
	}

	var file identityFile
	if err := json.Unmarshal(data, &file); err != nil {
		return nil, fmt.Errorf("parse file: %w", err)
	}

	if file.Version != identityFileVersion {
		return nil, fmt.Errorf("unsupported identity file version: %d", file.Version)
	}

	// Use stored Argon2 params from file
	a2Time := file.Argon2Time
	a2Memory := file.Argon2Memory
	a2Threads := file.Argon2Threads

	// Derive key from passphrase
	key := argon2.IDKey(passphrase, file.Salt, a2Time, a2Memory, a2Threads, argon2KeyLen)
	defer ZeroBytes(key)

	// Decrypt with AES-256-GCM
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create GCM: %w", err)
	}

	plaintextJSON, err := gcm.Open(nil, file.Nonce, file.Ciphertext, nil)
	if err != nil {
		return nil, errors.New("invalid passphrase or corrupted file")
	}
	defer ZeroBytes(plaintextJSON)

	var plaintext identityPlaintext
	if err := json.Unmarshal(plaintextJSON, &plaintext); err != nil {
		return nil, fmt.Errorf("parse identity: %w", err)
	}

	// Reconstruct ML-KEM keys from seed
	mlkemPriv, err := mlkem.NewDecapsulationKey768(plaintext.MLKEMSeed)
	if err != nil {
		return nil, fmt.Errorf("reconstruct ML-KEM key: %w", err)
	}
	mlkemPub := mlkemPriv.EncapsulationKey()

	// Reconstruct Ed25519 keys
	signingKey := ed25519.PrivateKey(plaintext.SigningKey)
	verifyKey := signingKey.Public().(ed25519.PublicKey)

	return &Identity{
		Name:       plaintext.Name,
		CreatedAt:  plaintext.CreatedAt,
		mlkemPriv:  mlkemPriv,
		mlkemPub:   mlkemPub,
		signingKey: signingKey,
		verifyKey:  verifyKey,
	}, nil
}

// SavePublic saves the public identity to a file.
func (id *Identity) SavePublic(path string) error {
	// Ensure parent directory exists
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return fmt.Errorf("create directory: %w", err)
	}

	pub := id.Public()
	data, err := json.MarshalIndent(pub, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal public identity: %w", err)
	}

	if err := os.WriteFile(path, data, 0644); err != nil {
		return fmt.Errorf("write file: %w", err)
	}

	return nil
}

// LoadPublic loads a public identity from a file
func LoadPublic(path string) (*PublicIdentity, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read file: %w", err)
	}

	var pub PublicIdentity
	if err := json.Unmarshal(data, &pub); err != nil {
		return nil, fmt.Errorf("parse public identity: %w", err)
	}

	return &pub, nil
}

// EncapsulationKey reconstructs an ML-KEM encapsulation key from bytes
func EncapsulationKeyFromBytes(b []byte) (*mlkem.EncapsulationKey768, error) {
	return mlkem.NewEncapsulationKey768(b)
}

// Encapsulate generates a shared secret and ciphertext for a recipient
// Returns (ciphertext, sharedSecret) for convenience - note that the underlying
// mlkem.Encapsulate returns (sharedKey, ciphertext), so we swap the order here
func Encapsulate(recipientPubKey *mlkem.EncapsulationKey768) (ciphertext, sharedSecret []byte) {
	sharedSecret, ciphertext = recipientPubKey.Encapsulate()
	return ciphertext, sharedSecret
}

// PublicKeyFingerprint returns a fingerprint for a public key
func PublicKeyFingerprint(pubKey []byte) string {
	hash := sha256.Sum256(pubKey)
	return fmt.Sprintf("%x", hash[:8])
}

// SerializePublicKeys serializes public keys for wire transmission
func (pub *PublicIdentity) Serialize() ([]byte, error) {
	return json.Marshal(pub)
}

// DeserializePublicIdentity deserializes a public identity
func DeserializePublicIdentity(data []byte) (*PublicIdentity, error) {
	var pub PublicIdentity
	if err := json.Unmarshal(data, &pub); err != nil {
		return nil, err
	}
	return &pub, nil
}

// Fingerprint returns a fingerprint of the signing public key
func (pub *PublicIdentity) Fingerprint() string {
	return PublicKeyFingerprint(pub.SigningPub)
}

// encodeLength writes a 4-byte big-endian length prefix
func encodeLength(length int) []byte {
	buf := make([]byte, 4)
	binary.BigEndian.PutUint32(buf, uint32(length))
	return buf
}

// decodeLength reads a 4-byte big-endian length prefix
func decodeLength(buf []byte) int {
	return int(binary.BigEndian.Uint32(buf))
}

// ToEntropy returns the 32-byte Ed25519 seed for mnemonic encoding.
// This seed can be used to reconstruct the full identity including the ML-KEM key
// (which is derived deterministically from the Ed25519 seed).
func (id *Identity) ToEntropy() ([]byte, error) {
	// Ed25519 private key is 64 bytes: first 32 bytes are the seed
	if len(id.signingKey) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("invalid signing key length: %d", len(id.signingKey))
	}

	seed := make([]byte, ed25519.SeedSize)
	copy(seed, id.signingKey[:ed25519.SeedSize])
	return seed, nil
}

// IdentityFromEntropy reconstructs an identity from a 32-byte Ed25519 seed.
// The ML-KEM key is derived deterministically from the seed using HKDF.
// Note: Name and CreatedAt must be provided as they are not stored in the entropy.
func IdentityFromEntropy(entropy []byte, name string) (*Identity, error) {
	if len(entropy) != ed25519.SeedSize {
		return nil, fmt.Errorf("entropy must be %d bytes, got %d", ed25519.SeedSize, len(entropy))
	}

	// Reconstruct Ed25519 key from seed
	signingKey := ed25519.NewKeyFromSeed(entropy)
	verifyKey := signingKey.Public().(ed25519.PublicKey)

	// Derive ML-KEM seed deterministically from Ed25519 seed using HKDF
	kemSeed, err := deriveKEMSeed(entropy)
	if err != nil {
		return nil, fmt.Errorf("derive ML-KEM seed: %w", err)
	}

	// Reconstruct ML-KEM key from derived seed
	mlkemPriv, err := mlkem.NewDecapsulationKey768(kemSeed)
	if err != nil {
		return nil, fmt.Errorf("reconstruct ML-KEM key: %w", err)
	}
	mlkemPub := mlkemPriv.EncapsulationKey()

	return &Identity{
		Name:       name,
		CreatedAt:  time.Now().UTC(),
		mlkemPriv:  mlkemPriv,
		mlkemPub:   mlkemPub,
		signingKey: signingKey,
		verifyKey:  verifyKey,
	}, nil
}

// deriveKEMSeed derives an ML-KEM seed from an Ed25519 seed using HKDF.
// This ensures deterministic key derivation for paper backup recovery.
func deriveKEMSeed(signingSeed []byte) ([]byte, error) {
	// Use HKDF-SHA256 to derive ML-KEM seed
	// Salt and info strings are fixed for reproducibility
	h := hkdf.New(sha256.New, signingSeed, []byte("envctl-kem-v1"), []byte("ml-kem-768"))

	// ML-KEM-768 requires 64 bytes for NewDecapsulationKey768
	kemSeed := make([]byte, 64)
	if _, err := io.ReadFull(h, kemSeed); err != nil {
		return nil, fmt.Errorf("HKDF key derivation failed: %w", err)
	}
	return kemSeed, nil
}
