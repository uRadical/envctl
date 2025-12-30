package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/mlkem"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/hkdf"
)

// Encrypted message format:
// [ML-KEM ciphertext (1088 bytes)][nonce (12 bytes)][AES ciphertext][tag (16 bytes)]
//
// ML-KEM-768 ciphertext size is 1088 bytes
const (
	mlkemCiphertextSize = 1088
	aesNonceSize        = 12
	aesKeySize          = 32 // AES-256
)

// Encrypt encrypts a message for a recipient using ML-KEM and AES-256-GCM
//
// The encryption flow:
// 1. Generate ephemeral shared secret using ML-KEM encapsulation
// 2. Derive AES key from shared secret using HKDF
// 3. Encrypt payload with AES-256-GCM
// 4. Package: [ML-KEM ciphertext][nonce][AES ciphertext][tag]
func Encrypt(plaintext []byte, recipientPubKey *mlkem.EncapsulationKey768) ([]byte, error) {
	// Encapsulate to get shared secret and ciphertext
	// ML-KEM Encapsulate returns (sharedKey, ciphertext)
	sharedSecret, kemCiphertext := recipientPubKey.Encapsulate()
	defer ZeroBytes(sharedSecret)

	// Derive AES key from shared secret using HKDF
	aesKey := make([]byte, aesKeySize)
	hkdfReader := hkdf.New(sha256.New, sharedSecret, nil, []byte("envctl-aes-key"))
	if _, err := io.ReadFull(hkdfReader, aesKey); err != nil {
		return nil, fmt.Errorf("derive AES key: %w", err)
	}
	defer ZeroBytes(aesKey)

	// Create AES-GCM cipher
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, fmt.Errorf("create AES cipher: %w", err)
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

	// Encrypt with AES-GCM
	aesCiphertext := gcm.Seal(nil, nonce, plaintext, nil)

	// Package: [ML-KEM ciphertext][nonce][AES ciphertext]
	result := make([]byte, 0, len(kemCiphertext)+len(nonce)+len(aesCiphertext))
	result = append(result, kemCiphertext...)
	result = append(result, nonce...)
	result = append(result, aesCiphertext...)

	return result, nil
}

// Decrypt decrypts a message using ML-KEM and AES-256-GCM
func Decrypt(ciphertext []byte, privKey *mlkem.DecapsulationKey768) ([]byte, error) {
	// Validate minimum length
	minLen := mlkemCiphertextSize + aesNonceSize + 16 // minimum 16 bytes for tag
	if len(ciphertext) < minLen {
		return nil, errors.New("ciphertext too short")
	}

	// Extract components
	kemCiphertext := ciphertext[:mlkemCiphertextSize]
	nonce := ciphertext[mlkemCiphertextSize : mlkemCiphertextSize+aesNonceSize]
	aesCiphertext := ciphertext[mlkemCiphertextSize+aesNonceSize:]

	// Decapsulate to get shared secret
	sharedSecret, err := privKey.Decapsulate(kemCiphertext)
	if err != nil {
		return nil, fmt.Errorf("ML-KEM decapsulate: %w", err)
	}
	defer ZeroBytes(sharedSecret)

	// Derive AES key from shared secret using HKDF
	aesKey := make([]byte, aesKeySize)
	hkdfReader := hkdf.New(sha256.New, sharedSecret, nil, []byte("envctl-aes-key"))
	if _, err := io.ReadFull(hkdfReader, aesKey); err != nil {
		return nil, fmt.Errorf("derive AES key: %w", err)
	}
	defer ZeroBytes(aesKey)

	// Create AES-GCM cipher
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, fmt.Errorf("create AES cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create GCM: %w", err)
	}

	// Decrypt with AES-GCM
	plaintext, err := gcm.Open(nil, nonce, aesCiphertext, nil)
	if err != nil {
		return nil, errors.New("decryption failed: invalid ciphertext or key")
	}

	return plaintext, nil
}

// EncryptForIdentity encrypts a message for a recipient's public identity
func EncryptForIdentity(plaintext []byte, recipient *PublicIdentity) ([]byte, error) {
	pubKey, err := EncapsulationKeyFromBytes(recipient.MLKEMPub)
	if err != nil {
		return nil, fmt.Errorf("parse recipient public key: %w", err)
	}
	return Encrypt(plaintext, pubKey)
}

// DecryptWithIdentity decrypts a message using an identity's private key
func DecryptWithIdentity(ciphertext []byte, identity *Identity) ([]byte, error) {
	return Decrypt(ciphertext, identity.mlkemPriv)
}

// DeriveKey derives a key from shared secret for a specific purpose
func DeriveKey(sharedSecret []byte, purpose string, keyLen int) ([]byte, error) {
	key := make([]byte, keyLen)
	hkdfReader := hkdf.New(sha256.New, sharedSecret, nil, []byte(purpose))
	if _, err := io.ReadFull(hkdfReader, key); err != nil {
		return nil, fmt.Errorf("derive key: %w", err)
	}
	return key, nil
}
