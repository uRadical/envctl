//go:build cgo

package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/mlkem"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/go-piv/piv-go/piv"
	"golang.org/x/crypto/hkdf"
)

// HybridIdentity combines YubiKey hardware protection with post-quantum signatures.
// It provides both extraction resistance (via YubiKey P-256) and post-quantum
// security (via ML-DSA-65), requiring both signatures for all operations.
type HybridIdentity struct {
	name        string
	fingerprint string
	serial      uint32

	// YubiKey components
	yubikey     *piv.YubiKey
	pivSlot     piv.Slot
	hwPublicKey []byte // P-256 ECDSA public key (uncompressed)

	// PQC signing components (ML-DSA-65)
	pqcPrivateKey []byte // Decrypted in memory, wiped on close
	pqcPublicKey  []byte

	// Key exchange (ML-KEM-768)
	kemPrivateKey *mlkem.DecapsulationKey768
	kemPublicKey  *mlkem.EncapsulationKey768

	// For unlocking PQC key with YubiKey
	ephemeralPubKey []byte // Stored, used with YubiKey ECDH to derive decryption key
	encryptedBundle []byte // PQC private keys (ML-DSA + ML-KEM), encrypted
	salt            []byte

	// State
	unlocked bool
	mu       sync.RWMutex
}

// HybridIdentityFile is the on-disk format for hybrid identity
type HybridIdentityFile struct {
	Version         int       `json:"version"`
	Name            string    `json:"name"`
	Fingerprint     string    `json:"fingerprint"`
	CreatedAt       time.Time `json:"created_at"`

	// YubiKey reference
	YubiKeySerial uint32 `json:"yubikey_serial"`
	PIVSlot       string `json:"piv_slot"`
	HWPublicKey   []byte `json:"hw_public_key"`

	// PQC public keys (not secret)
	PQCPublicKey []byte `json:"pqc_public_key"`
	KEMPublicKey []byte `json:"kem_public_key"`

	// Encrypted PQC private keys
	EphemeralPubKey []byte `json:"ephemeral_pub_key"`
	EncryptedBundle []byte `json:"encrypted_bundle"`
	Salt            []byte `json:"salt"`
}

// pqcBundle contains the encrypted PQC private keys
type pqcBundle struct {
	MLDSAPriv []byte `json:"mldsa_priv"`
	KEMSeed   []byte `json:"kem_seed"` // ML-KEM seed for deterministic reconstruction
}

// GenerateHybridIdentity creates a new hybrid identity with YubiKey
func GenerateHybridIdentity(name string, yk *piv.YubiKey, pin string, touchCallback func(string)) (*HybridIdentity, error) {
	// Verify PIN first
	if err := yk.VerifyPIN(pin); err != nil {
		return nil, fmt.Errorf("invalid PIN: %w", err)
	}

	serial, err := yk.Serial()
	if err != nil {
		return nil, fmt.Errorf("get serial: %w", err)
	}

	// Step 1: Generate P-256 key on YubiKey for ECDH (slot 9d - Key Management)
	if touchCallback != nil {
		touchCallback("Touch YubiKey to generate P-256 key...")
	}

	pivSlot := piv.SlotKeyManagement // 9d
	hwPubKey, err := yk.GenerateKey(
		piv.DefaultManagementKey,
		pivSlot,
		piv.Key{
			Algorithm:   piv.AlgorithmEC256,
			TouchPolicy: piv.TouchPolicyAlways,
			PINPolicy:   piv.PINPolicyOnce,
		},
	)
	if err != nil {
		return nil, fmt.Errorf("generate YubiKey key: %w", err)
	}

	ecdsaPub, ok := hwPubKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, errors.New("unexpected key type from YubiKey")
	}

	hwPubBytes := elliptic.Marshal(ecdsaPub.Curve, ecdsaPub.X, ecdsaPub.Y)

	// Step 2: Generate ephemeral P-256 keypair for key wrapping
	ephemeralPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate ephemeral key: %w", err)
	}
	ephemeralPubBytes := elliptic.Marshal(ephemeralPriv.Curve, ephemeralPriv.X, ephemeralPriv.Y)

	// Step 3: Perform ECDH between ephemeral private and YubiKey public
	sharedX, _ := elliptic.P256().ScalarMult(ecdsaPub.X, ecdsaPub.Y, ephemeralPriv.D.Bytes())
	sharedSecret := padToSize(sharedX.Bytes(), 32)
	defer ZeroBytes(sharedSecret)

	// Step 4: Generate ML-DSA-65 keypair for post-quantum signing
	pqcPub, pqcPriv, err := GenerateMLDSA65()
	if err != nil {
		return nil, fmt.Errorf("generate ML-DSA-65: %w", err)
	}

	// Step 5: Generate ML-KEM-768 keypair for post-quantum key exchange
	kemPriv, err := mlkem.GenerateKey768()
	if err != nil {
		return nil, fmt.Errorf("generate ML-KEM-768: %w", err)
	}
	kemPub := kemPriv.EncapsulationKey()
	kemSeed := kemPriv.Bytes()

	// Step 6: Encrypt PQC private keys with YubiKey-derived secret
	salt := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, fmt.Errorf("generate salt: %w", err)
	}

	wrapKey, err := deriveWrapKey(sharedSecret, salt)
	if err != nil {
		return nil, fmt.Errorf("derive wrap key: %w", err)
	}
	defer ZeroBytes(wrapKey)

	bundle := pqcBundle{
		MLDSAPriv: pqcPriv,
		KEMSeed:   kemSeed,
	}
	bundleBytes, err := json.Marshal(bundle)
	if err != nil {
		return nil, fmt.Errorf("marshal bundle: %w", err)
	}
	defer ZeroBytes(bundleBytes)

	encryptedBundle, err := encryptAESGCM(wrapKey, bundleBytes)
	if err != nil {
		return nil, fmt.Errorf("encrypt bundle: %w", err)
	}

	// Step 7: Compute fingerprint from combined public keys
	fingerprint := computeHybridFingerprint(hwPubBytes, pqcPub, kemPub.Bytes())

	h := &HybridIdentity{
		name:            name,
		fingerprint:     fingerprint,
		serial:          serial,
		yubikey:         yk,
		pivSlot:         pivSlot,
		hwPublicKey:     hwPubBytes,
		pqcPublicKey:    pqcPub,
		kemPublicKey:    kemPub,
		ephemeralPubKey: ephemeralPubBytes,
		encryptedBundle: encryptedBundle,
		salt:            salt,
		// Unlocked immediately since we just created it
		pqcPrivateKey: pqcPriv,
		kemPrivateKey: kemPriv,
		unlocked:      true,
	}

	return h, nil
}

// LoadHybridIdentity loads a hybrid identity from disk
func LoadHybridIdentity(path string) (*HybridIdentity, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read file: %w", err)
	}

	var file HybridIdentityFile
	if err := json.Unmarshal(data, &file); err != nil {
		return nil, fmt.Errorf("unmarshal: %w", err)
	}

	if file.Version != 1 {
		return nil, fmt.Errorf("unsupported hybrid identity version: %d", file.Version)
	}

	// Parse slot
	slot, err := parseSlot(file.PIVSlot)
	if err != nil {
		return nil, fmt.Errorf("parse slot: %w", err)
	}

	// Parse KEM public key
	kemPub, err := mlkem.NewEncapsulationKey768(file.KEMPublicKey)
	if err != nil {
		return nil, fmt.Errorf("parse KEM public key: %w", err)
	}

	return &HybridIdentity{
		name:            file.Name,
		fingerprint:     file.Fingerprint,
		serial:          file.YubiKeySerial,
		pivSlot:         slot,
		hwPublicKey:     file.HWPublicKey,
		pqcPublicKey:    file.PQCPublicKey,
		kemPublicKey:    kemPub,
		ephemeralPubKey: file.EphemeralPubKey,
		encryptedBundle: file.EncryptedBundle,
		salt:            file.Salt,
		unlocked:        false,
	}, nil
}

// Save saves the hybrid identity to disk
func (h *HybridIdentity) Save(path string) error {
	// Ensure parent directory exists
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return fmt.Errorf("create directory: %w", err)
	}

	file := &HybridIdentityFile{
		Version:         1,
		Name:            h.name,
		Fingerprint:     h.fingerprint,
		CreatedAt:       time.Now().UTC(),
		YubiKeySerial:   h.serial,
		PIVSlot:         slotToString(h.pivSlot),
		HWPublicKey:     h.hwPublicKey,
		PQCPublicKey:    h.pqcPublicKey,
		KEMPublicKey:    h.kemPublicKey.Bytes(),
		EphemeralPubKey: h.ephemeralPubKey,
		EncryptedBundle: h.encryptedBundle,
		Salt:            h.salt,
	}

	data, err := json.MarshalIndent(file, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}

	return os.WriteFile(path, data, 0600)
}

// ConnectYubiKey connects to the YubiKey for this identity
func (h *HybridIdentity) ConnectYubiKey() error {
	h.mu.Lock()
	defer h.mu.Unlock()

	if h.yubikey != nil {
		return nil // Already connected
	}

	yk, err := OpenYubiKey(h.serial)
	if err != nil {
		return fmt.Errorf("YubiKey with serial %d not found - please insert it", h.serial)
	}

	h.yubikey = yk.card
	return nil
}

// Unlock decrypts the PQC private keys using the YubiKey
func (h *HybridIdentity) Unlock(pin string, touchCallback func(string)) error {
	h.mu.Lock()
	defer h.mu.Unlock()

	if h.unlocked {
		return nil
	}

	if h.yubikey == nil {
		return errors.New("YubiKey not connected - call ConnectYubiKey first")
	}

	// Verify PIN
	if err := h.yubikey.VerifyPIN(pin); err != nil {
		return fmt.Errorf("invalid PIN: %w", err)
	}

	// Reconstruct ephemeral public key
	x, y := elliptic.Unmarshal(elliptic.P256(), h.ephemeralPubKey)
	if x == nil {
		return errors.New("invalid ephemeral public key")
	}
	ephemeralPub := &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     x,
		Y:     y,
	}

	// Get attestation or certificate to access private key
	cert, err := h.yubikey.Attest(h.pivSlot)
	if err != nil {
		cert, err = h.yubikey.Certificate(h.pivSlot)
		if err != nil {
			return fmt.Errorf("get key info: %w", err)
		}
	}

	// Get private key handle for ECDH
	priv, err := h.yubikey.PrivateKey(h.pivSlot, cert.PublicKey, piv.KeyAuth{PIN: pin})
	if err != nil {
		return fmt.Errorf("access private key: %w", err)
	}

	// Perform ECDH on YubiKey
	ecdsaPriv, ok := priv.(*piv.ECDSAPrivateKey)
	if !ok {
		return errors.New("key does not support ECDH")
	}

	if touchCallback != nil {
		touchCallback("Touch YubiKey to unlock identity...")
	}

	sharedSecret, err := ecdsaPriv.SharedKey(ephemeralPub)
	if err != nil {
		return fmt.Errorf("ECDH: %w", err)
	}
	defer ZeroBytes(sharedSecret)

	// Pad shared secret to 32 bytes
	sharedSecret = padToSize(sharedSecret, 32)

	// Derive decryption key
	wrapKey, err := deriveWrapKey(sharedSecret, h.salt)
	if err != nil {
		return fmt.Errorf("derive wrap key: %w", err)
	}
	defer ZeroBytes(wrapKey)

	// Decrypt PQC bundle
	bundleBytes, err := decryptAESGCM(wrapKey, h.encryptedBundle)
	if err != nil {
		return fmt.Errorf("decrypt bundle: %w", err)
	}
	defer ZeroBytes(bundleBytes)

	var bundle pqcBundle
	if err := json.Unmarshal(bundleBytes, &bundle); err != nil {
		return fmt.Errorf("unmarshal bundle: %w", err)
	}

	// Reconstruct ML-KEM key from seed
	kemPriv, err := mlkem.NewDecapsulationKey768(bundle.KEMSeed)
	if err != nil {
		ZeroBytes(bundle.MLDSAPriv)
		ZeroBytes(bundle.KEMSeed)
		return fmt.Errorf("reconstruct KEM key: %w", err)
	}

	h.pqcPrivateKey = bundle.MLDSAPriv
	h.kemPrivateKey = kemPriv
	h.unlocked = true

	return nil
}

// Lock wipes the PQC private keys from memory
func (h *HybridIdentity) Lock() {
	h.mu.Lock()
	defer h.mu.Unlock()

	if h.pqcPrivateKey != nil {
		ZeroBytes(h.pqcPrivateKey)
		h.pqcPrivateKey = nil
	}
	h.kemPrivateKey = nil
	h.unlocked = false
}

// Close releases YubiKey and wipes keys
func (h *HybridIdentity) Close() error {
	h.Lock()

	h.mu.Lock()
	defer h.mu.Unlock()

	if h.yubikey != nil {
		err := h.yubikey.Close()
		h.yubikey = nil
		return err
	}
	return nil
}

// Sign creates a hybrid signature (P-256 ECDSA + ML-DSA-65)
func (h *HybridIdentity) Sign(data []byte, pin string, touchCallback func(string)) ([]byte, error) {
	h.mu.RLock()
	defer h.mu.RUnlock()

	if !h.unlocked {
		return nil, errors.New("identity is locked - call Unlock first")
	}

	if h.yubikey == nil {
		return nil, errors.New("YubiKey not connected - call ConnectYubiKey first")
	}

	// Hash data for ECDSA signing
	digest := sha256.Sum256(data)

	// Get attestation or certificate to access private key
	cert, err := h.yubikey.Attest(h.pivSlot)
	if err != nil {
		cert, err = h.yubikey.Certificate(h.pivSlot)
		if err != nil {
			return nil, fmt.Errorf("get key info: %w", err)
		}
	}

	// Get private key handle
	priv, err := h.yubikey.PrivateKey(h.pivSlot, cert.PublicKey, piv.KeyAuth{PIN: pin})
	if err != nil {
		return nil, fmt.Errorf("access private key: %w", err)
	}

	ecdsaPriv, ok := priv.(*piv.ECDSAPrivateKey)
	if !ok {
		return nil, errors.New("key does not support ECDSA signing")
	}

	if touchCallback != nil {
		touchCallback("Touch YubiKey to sign...")
	}

	// Sign with YubiKey (P-256 ECDSA)
	hwSig, err := ecdsaPriv.Sign(rand.Reader, digest[:], nil)
	if err != nil {
		return nil, fmt.Errorf("hardware sign: %w", err)
	}

	// Sign with ML-DSA-65
	pqcSig, err := SignMLDSA65(h.pqcPrivateKey, data)
	if err != nil {
		return nil, fmt.Errorf("PQC sign: %w", err)
	}

	// Encode hybrid signature
	return EncodeHybridSignature(hwSig, pqcSig), nil
}

// Verify checks both signature components
func (h *HybridIdentity) Verify(data, signature []byte) bool {
	return VerifyHybridSignature(h.hwPublicKey, h.pqcPublicKey, data, signature)
}

// VerifyHybridSignature verifies a hybrid signature against P-256 and ML-DSA public keys
func VerifyHybridSignature(hwPubKey, pqcPubKey, data, signature []byte) bool {
	hwSig, pqcSig, err := DecodeHybridSignature(signature)
	if err != nil {
		return false
	}

	// Verify P-256 ECDSA signature
	digest := sha256.Sum256(data)
	x, y := elliptic.Unmarshal(elliptic.P256(), hwPubKey)
	if x == nil {
		return false
	}
	ecdsaPub := &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     x,
		Y:     y,
	}
	if !ecdsa.VerifyASN1(ecdsaPub, digest[:], hwSig) {
		return false
	}

	// Verify ML-DSA-65 signature
	if !VerifyMLDSA65(pqcPubKey, data, pqcSig) {
		return false
	}

	return true
}

// Fingerprint returns the identity fingerprint
func (h *HybridIdentity) Fingerprint() string {
	return h.fingerprint
}

// Name returns the identity name
func (h *HybridIdentity) Name() string {
	return h.name
}

// MLKEMPublicKey returns the ML-KEM public key bytes for encryption
func (h *HybridIdentity) MLKEMPublicKey() []byte {
	return h.kemPublicKey.Bytes()
}

// SigningPublicKey returns the ML-DSA public key bytes
func (h *HybridIdentity) SigningPublicKey() []byte {
	return h.pqcPublicKey
}

// HWPublicKey returns the P-256 ECDSA public key bytes
func (h *HybridIdentity) HWPublicKey() []byte {
	return h.hwPublicKey
}

// Decapsulate decapsulates a shared secret using ML-KEM
func (h *HybridIdentity) Decapsulate(ciphertext []byte) ([]byte, error) {
	h.mu.RLock()
	defer h.mu.RUnlock()

	if !h.unlocked {
		return nil, errors.New("identity is locked")
	}

	return h.kemPrivateKey.Decapsulate(ciphertext)
}

// IsUnlocked returns true if the identity is unlocked
func (h *HybridIdentity) IsUnlocked() bool {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.unlocked
}

// Serial returns the YubiKey serial number
func (h *HybridIdentity) Serial() uint32 {
	return h.serial
}

// Helper functions

func computeHybridFingerprint(hwPub, pqcPub, kemPub []byte) string {
	h := sha256.New()
	h.Write([]byte("envctl-hybrid-v1"))
	h.Write(hwPub)
	h.Write(pqcPub)
	h.Write(kemPub)
	hash := h.Sum(nil)
	return hex.EncodeToString(hash[:8])
}

func deriveWrapKey(sharedSecret, salt []byte) ([]byte, error) {
	kdf := hkdf.New(sha256.New, sharedSecret, salt, []byte("envctl-pqc-wrap-v1"))
	key := make([]byte, 32)
	if _, err := io.ReadFull(kdf, key); err != nil {
		return nil, err
	}
	return key, nil
}

func encryptAESGCM(key, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	ciphertext := gcm.Seal(nil, nonce, plaintext, nil)

	// Return nonce || ciphertext
	result := make([]byte, len(nonce)+len(ciphertext))
	copy(result, nonce)
	copy(result[len(nonce):], ciphertext)

	return result, nil
}

func decryptAESGCM(key, data []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return nil, errors.New("ciphertext too short")
	}

	nonce := data[:nonceSize]
	ciphertext := data[nonceSize:]

	return gcm.Open(nil, nonce, ciphertext, nil)
}

func padToSize(data []byte, size int) []byte {
	if len(data) >= size {
		return data
	}
	padded := make([]byte, size)
	copy(padded[size-len(data):], data)
	return padded
}

func parseSlot(s string) (piv.Slot, error) {
	switch s {
	case "9a":
		return piv.SlotAuthentication, nil
	case "9c":
		return piv.SlotSignature, nil
	case "9d":
		return piv.SlotKeyManagement, nil
	case "9e":
		return piv.SlotCardAuthentication, nil
	default:
		return piv.Slot{}, fmt.Errorf("unknown slot: %s", s)
	}
}

func slotToString(slot piv.Slot) string {
	switch slot {
	case piv.SlotAuthentication:
		return "9a"
	case piv.SlotSignature:
		return "9c"
	case piv.SlotKeyManagement:
		return "9d"
	case piv.SlotCardAuthentication:
		return "9e"
	default:
		return "9d"
	}
}
