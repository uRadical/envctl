package crypto

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math/big"
	"sync"
	"time"

	"github.com/go-piv/piv-go/piv"
	"golang.org/x/crypto/hkdf"
)

// YubiKey represents a connected YubiKey
type YubiKey struct {
	card   *piv.YubiKey
	serial uint32
}

// YubiKeyIdentity represents an identity stored on YubiKey
type YubiKeyIdentity struct {
	Name       string    `json:"name"`
	Serial     uint32    `json:"serial"`
	SigningPub []byte    `json:"signing_pub"`
	ECDHPub    []byte    `json:"ecdh_pub"` // P-256 ECDH public key (uncompressed)
	CreatedAt  time.Time `json:"created_at"`
}

// FindYubiKeys returns all connected YubiKeys
func FindYubiKeys() ([]*YubiKey, error) {
	cards, err := piv.Cards()
	if err != nil {
		return nil, fmt.Errorf("listing smart cards: %w", err)
	}

	var keys []*YubiKey

	for _, card := range cards {
		yk, err := piv.Open(card)
		if err != nil {
			continue // Not a YubiKey or busy
		}

		serial, err := yk.Serial()
		if err != nil {
			yk.Close()
			continue
		}

		keys = append(keys, &YubiKey{
			card:   yk,
			serial: serial,
		})
	}

	return keys, nil
}

// OpenYubiKey opens a specific YubiKey by serial number
func OpenYubiKey(serial uint32) (*YubiKey, error) {
	cards, err := piv.Cards()
	if err != nil {
		return nil, err
	}

	for _, card := range cards {
		yk, err := piv.Open(card)
		if err != nil {
			continue
		}

		s, err := yk.Serial()
		if err != nil {
			yk.Close()
			continue
		}

		if s == serial {
			return &YubiKey{card: yk, serial: s}, nil
		}

		yk.Close()
	}

	return nil, fmt.Errorf("YubiKey with serial %d not found", serial)
}

// Close closes the YubiKey connection
func (yk *YubiKey) Close() error {
	if yk.card != nil {
		return yk.card.Close()
	}
	return nil
}

// Serial returns the YubiKey serial number
func (yk *YubiKey) Serial() uint32 {
	return yk.serial
}

// Card returns the underlying piv.YubiKey for direct access
func (yk *YubiKey) Card() *piv.YubiKey {
	return yk.card
}

// ChangePIN changes the PIV PIN
func (yk *YubiKey) ChangePIN(oldPIN, newPIN string) error {
	return yk.card.SetPIN(oldPIN, newPIN)
}

// GenerateIdentityOnYubiKey creates a new identity on the YubiKey
// Uses Ed25519 for signing (slot 9a) and P-256 for ECDH (slot 9d)
func GenerateIdentityOnYubiKey(yk *YubiKey, name string, pin string, touchCallback func(string)) (*YubiKeyIdentity, error) {
	// Verify PIN first
	if err := yk.card.VerifyPIN(pin); err != nil {
		return nil, fmt.Errorf("invalid PIN: %w", err)
	}

	// Generate signing key in slot 9a (Authentication) - Ed25519
	if touchCallback != nil {
		touchCallback("Touch YubiKey to generate signing key...")
	}

	signingKey, err := yk.card.GenerateKey(
		piv.DefaultManagementKey,
		piv.SlotAuthentication, // 9a
		piv.Key{
			Algorithm:   piv.AlgorithmEd25519,
			TouchPolicy: piv.TouchPolicyAlways,
			PINPolicy:   piv.PINPolicyOnce,
		},
	)
	if err != nil {
		return nil, fmt.Errorf("generating signing key: %w", err)
	}

	// Generate key exchange key in slot 9d (Key Management) - P-256
	if touchCallback != nil {
		touchCallback("Touch YubiKey to generate key exchange key...")
	}

	ecdhKey, err := yk.card.GenerateKey(
		piv.DefaultManagementKey,
		piv.SlotKeyManagement, // 9d
		piv.Key{
			Algorithm:   piv.AlgorithmEC256,
			TouchPolicy: piv.TouchPolicyAlways,
			PINPolicy:   piv.PINPolicyOnce,
		},
	)
	if err != nil {
		return nil, fmt.Errorf("generating key exchange key: %w", err)
	}

	// Extract public keys
	signingPub, ok := signingKey.(ed25519.PublicKey)
	if !ok {
		return nil, errors.New("unexpected signing key type")
	}

	ecdsaPub, ok := ecdhKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, errors.New("unexpected key exchange key type")
	}

	// Marshal P-256 public key to uncompressed format (65 bytes: 0x04 || X || Y)
	ecdhPubBytes := elliptic.Marshal(ecdsaPub.Curve, ecdsaPub.X, ecdsaPub.Y)

	identity := &YubiKeyIdentity{
		Name:       name,
		Serial:     yk.serial,
		SigningPub: signingPub,
		ECDHPub:    ecdhPubBytes,
		CreatedAt:  time.Now().UTC(),
	}

	return identity, nil
}

// Fingerprint returns a short fingerprint of the identity's signing key
func (y *YubiKeyIdentity) Fingerprint() string {
	hash := sha256.Sum256(y.SigningPub)
	return hex.EncodeToString(hash[:8])
}

// Sign signs data using the YubiKey
func (yk *YubiKey) Sign(data []byte, pin string, touchCallback func(string)) ([]byte, error) {
	// Get certificate to get the public key type
	cert, err := yk.card.Certificate(piv.SlotAuthentication)
	if err != nil {
		// No certificate, try to get attestation instead
		cert, err = yk.card.Attest(piv.SlotAuthentication)
		if err != nil {
			return nil, fmt.Errorf("getting key info: %w", err)
		}
	}

	// Get private key handle for signing slot
	priv, err := yk.card.PrivateKey(
		piv.SlotAuthentication,
		cert.PublicKey,
		piv.KeyAuth{PIN: pin},
	)
	if err != nil {
		return nil, fmt.Errorf("accessing private key: %w", err)
	}

	signer, ok := priv.(crypto.Signer)
	if !ok {
		return nil, errors.New("key does not support signing")
	}

	// Sign - this will require touch
	if touchCallback != nil {
		touchCallback("Touch YubiKey to sign...")
	}

	sig, err := signer.Sign(rand.Reader, data, crypto.Hash(0))
	if err != nil {
		return nil, fmt.Errorf("signing: %w", err)
	}

	return sig, nil
}

// ECDH performs P-256 ECDH key exchange using the YubiKey
func (yk *YubiKey) ECDH(peerPub []byte, pin string, touchCallback func(string)) ([]byte, error) {
	// Get certificate to get the public key type
	cert, err := yk.card.Certificate(piv.SlotKeyManagement)
	if err != nil {
		// No certificate, try to get attestation instead
		cert, err = yk.card.Attest(piv.SlotKeyManagement)
		if err != nil {
			return nil, fmt.Errorf("getting key info: %w", err)
		}
	}

	// Get private key handle for key management slot
	priv, err := yk.card.PrivateKey(
		piv.SlotKeyManagement,
		cert.PublicKey,
		piv.KeyAuth{PIN: pin},
	)
	if err != nil {
		return nil, fmt.Errorf("accessing private key: %w", err)
	}

	// Type assert to ECDSAPrivateKey to get SharedKey method
	ecdsaPriv, ok := priv.(*piv.ECDSAPrivateKey)
	if !ok {
		return nil, errors.New("key is not an ECDSA key")
	}

	// Parse peer public key from uncompressed format
	x, y := elliptic.Unmarshal(elliptic.P256(), peerPub)
	if x == nil {
		return nil, errors.New("invalid peer public key format")
	}

	peerPubKey := &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     x,
		Y:     y,
	}

	// Perform ECDH - this will require touch
	if touchCallback != nil {
		touchCallback("Touch YubiKey to decrypt...")
	}

	// Use piv-go's SharedKey method for ECDH
	shared, err := ecdsaPriv.SharedKey(peerPubKey)
	if err != nil {
		return nil, fmt.Errorf("ECDH: %w", err)
	}

	return shared, nil
}

// GetSigningPublicKey retrieves the signing public key from the YubiKey
func (yk *YubiKey) GetSigningPublicKey() ([]byte, error) {
	cert, err := yk.card.Certificate(piv.SlotAuthentication)
	if err != nil {
		cert, err = yk.card.Attest(piv.SlotAuthentication)
		if err != nil {
			return nil, fmt.Errorf("getting signing key: %w", err)
		}
	}

	pub, ok := cert.PublicKey.(ed25519.PublicKey)
	if !ok {
		return nil, errors.New("unexpected signing key type")
	}

	return pub, nil
}

// GetECDHPublicKey retrieves the P-256 ECDH public key from the YubiKey
func (yk *YubiKey) GetECDHPublicKey() ([]byte, error) {
	cert, err := yk.card.Certificate(piv.SlotKeyManagement)
	if err != nil {
		cert, err = yk.card.Attest(piv.SlotKeyManagement)
		if err != nil {
			return nil, fmt.Errorf("getting ECDH key: %w", err)
		}
	}

	pub, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, errors.New("unexpected key exchange key type")
	}

	return elliptic.Marshal(pub.Curve, pub.X, pub.Y), nil
}

// ImportSigningKey imports an Ed25519 private key to the YubiKey
// Note: Requires YubiKey firmware 5.2.3+ for Ed25519 import
func (yk *YubiKey) ImportSigningKey(privateKey ed25519.PrivateKey, touchCallback func(string)) error {
	if touchCallback != nil {
		touchCallback("Touch YubiKey to import signing key...")
	}

	return yk.card.SetPrivateKeyInsecure(
		piv.DefaultManagementKey,
		piv.SlotAuthentication,
		privateKey,
		piv.Key{
			Algorithm:   piv.AlgorithmEd25519,
			TouchPolicy: piv.TouchPolicyAlways,
			PINPolicy:   piv.PINPolicyOnce,
		},
	)
}

// GenerateECDHKey generates a new P-256 ECDH key on the YubiKey
func (yk *YubiKey) GenerateECDHKey(touchCallback func(string)) ([]byte, error) {
	if touchCallback != nil {
		touchCallback("Touch YubiKey to generate key exchange key...")
	}

	pub, err := yk.card.GenerateKey(
		piv.DefaultManagementKey,
		piv.SlotKeyManagement,
		piv.Key{
			Algorithm:   piv.AlgorithmEC256,
			TouchPolicy: piv.TouchPolicyAlways,
			PINPolicy:   piv.PINPolicyOnce,
		},
	)
	if err != nil {
		return nil, err
	}

	ecdsaPub, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		return nil, errors.New("unexpected key type")
	}

	return elliptic.Marshal(ecdsaPub.Curve, ecdsaPub.X, ecdsaPub.Y), nil
}

// PINCache caches the PIN for a session using protected memory
type PINCache struct {
	pin       *ProtectedBuffer
	expiresAt time.Time
	mu        sync.RWMutex
}

var globalPINCache = &PINCache{}

// GetCachedPIN returns the cached PIN if still valid
func GetCachedPIN() (string, bool) {
	return globalPINCache.Get()
}

// CachePIN caches the PIN for the specified duration
func CachePIN(pin string, duration time.Duration) {
	globalPINCache.Set(pin, duration)
}

// ClearCachedPIN clears the cached PIN
func ClearCachedPIN() {
	globalPINCache.Clear()
}

func (c *PINCache) Get() (string, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.pin == nil || time.Now().After(c.expiresAt) {
		return "", false
	}

	// Return a copy of the PIN
	pinBytes := c.pin.Copy()
	if pinBytes == nil {
		return "", false
	}
	pin := string(pinBytes)
	ZeroBytes(pinBytes)
	return pin, true
}

func (c *PINCache) Set(pin string, duration time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Clear existing PIN if any
	if c.pin != nil {
		c.pin.Destroy()
	}

	// Store PIN in protected memory
	c.pin = NewProtectedBufferFromBytes([]byte(pin))
	c.expiresAt = time.Now().Add(duration)
}

func (c *PINCache) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.pin != nil {
		c.pin.Destroy()
		c.pin = nil
	}
	c.expiresAt = time.Time{}
}

// EncryptForYubiKey encrypts data for a YubiKey recipient using P-256 ECDH + AES-GCM
func EncryptForYubiKey(plaintext []byte, recipientECDHPub []byte) ([]byte, error) {
	// Parse recipient public key from uncompressed format
	x, y := elliptic.Unmarshal(elliptic.P256(), recipientECDHPub)
	if x == nil {
		return nil, errors.New("invalid recipient public key format")
	}

	recipientPub := &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     x,
		Y:     y,
	}

	// Generate ephemeral P-256 key pair
	ephemeralPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generating ephemeral key: %w", err)
	}

	ephemeralPubBytes := elliptic.Marshal(elliptic.P256(), ephemeralPriv.X, ephemeralPriv.Y)

	// ECDH to get shared secret
	sharedX, _ := elliptic.P256().ScalarMult(recipientPub.X, recipientPub.Y, ephemeralPriv.D.Bytes())
	shared := sharedX.Bytes()

	// Pad shared secret to 32 bytes
	if len(shared) < 32 {
		padded := make([]byte, 32)
		copy(padded[32-len(shared):], shared)
		shared = padded
	}

	// Derive symmetric key using HKDF
	kdf := hkdf.New(sha256.New, shared, ephemeralPubBytes, []byte("envctl-p256-v1"))
	key := make([]byte, 32)
	if _, err := io.ReadFull(kdf, key); err != nil {
		return nil, fmt.Errorf("deriving key: %w", err)
	}

	// Encrypt with AES-256-GCM
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("creating cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("creating GCM: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("generating nonce: %w", err)
	}

	ciphertext := gcm.Seal(nil, nonce, plaintext, nil)

	// Format: ephemeral_pub (65) || nonce (12) || ciphertext
	result := make([]byte, 65+len(nonce)+len(ciphertext))
	copy(result[0:65], ephemeralPubBytes)
	copy(result[65:65+len(nonce)], nonce)
	copy(result[65+len(nonce):], ciphertext)

	return result, nil
}

// DecryptWithYubiKey decrypts data using the YubiKey's P-256 ECDH key
func DecryptWithYubiKey(yk *YubiKey, data []byte, pin string, touchCallback func(string)) ([]byte, error) {
	if len(data) < 77 { // 65 (ephemeral pub) + 12 (nonce) minimum
		return nil, errors.New("ciphertext too short")
	}

	// Parse components
	ephemeralPub := data[0:65]
	nonce := data[65:77]
	ciphertext := data[77:]

	// ECDH on YubiKey (requires touch)
	shared, err := yk.ECDH(ephemeralPub, pin, touchCallback)
	if err != nil {
		return nil, fmt.Errorf("ECDH: %w", err)
	}

	// Pad shared secret to 32 bytes
	if len(shared) < 32 {
		padded := make([]byte, 32)
		copy(padded[32-len(shared):], shared)
		shared = padded
	}

	// Derive symmetric key
	kdf := hkdf.New(sha256.New, shared, ephemeralPub, []byte("envctl-p256-v1"))
	key := make([]byte, 32)
	if _, err := io.ReadFull(kdf, key); err != nil {
		return nil, fmt.Errorf("deriving key: %w", err)
	}

	// Decrypt
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("creating cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("creating GCM: %w", err)
	}

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("decrypting: %w", err)
	}

	return plaintext, nil
}

// HasYubiKeySupport checks if YubiKey support is available on this system
func HasYubiKeySupport() bool {
	cards, err := piv.Cards()
	if err != nil {
		return false
	}
	// We can list cards, so PC/SC is available
	_ = cards
	return true
}

// Helper to compute ECDH shared secret X coordinate bytes, padded to curve size
func ecdhSharedSecret(priv *ecdsa.PrivateKey, pub *ecdsa.PublicKey) []byte {
	x, _ := priv.Curve.ScalarMult(pub.X, pub.Y, priv.D.Bytes())
	byteLen := (priv.Curve.Params().BitSize + 7) / 8
	shared := x.Bytes()
	if len(shared) < byteLen {
		padded := make([]byte, byteLen)
		copy(padded[byteLen-len(shared):], shared)
		return padded
	}
	return shared
}

// Unused but satisfies imports
var _ = big.NewInt(0)
