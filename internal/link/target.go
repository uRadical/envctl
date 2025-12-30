package link

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/json"
	"fmt"
	"net"
	"time"

	"uradical.io/go/envctl/internal/crypto"
)

// TargetOptions configures the target side of device linking
type TargetOptions struct {
	Code       string
	SourceAddr string // Optional: direct address if mDNS fails
	OnStatus   StatusFunc
	OnConfirm  func(fingerprint string) bool
}

// RunTarget runs the target side of device linking
func RunTarget(opts TargetOptions) (*crypto.Identity, error) {
	code, err := ParseCode(opts.Code)
	if err != nil {
		return nil, err
	}

	opts.OnStatus("Discovering source device...")

	var addr string

	// Try mDNS discovery first
	addr, err = DiscoverLinkSession(code)
	if err != nil {
		if opts.SourceAddr != "" {
			// Use provided address
			addr = opts.SourceAddr
		} else {
			// Fall back to local network scan
			addr, err = FindLinkSessionOnNetwork()
			if err != nil {
				return nil, fmt.Errorf("could not find source device: %w", err)
			}
		}
	}

	opts.OnStatus(fmt.Sprintf("Connecting to %s...", addr))

	// Connect to source
	conn, err := net.DialTimeout("tcp", addr, 10*time.Second)
	if err != nil {
		return nil, fmt.Errorf("connecting to source: %w", err)
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(2 * time.Minute))

	// SPAKE2 key exchange
	exchange := NewSPAKE2Target(code)

	// Receive their message first (source sends first)
	theirMsg, err := readFrame(conn)
	if err != nil {
		return nil, fmt.Errorf("receiving SPAKE2 message: %w", err)
	}

	// Send our message
	ourMsg := exchange.Start()
	if err := writeFrame(conn, ourMsg); err != nil {
		return nil, fmt.Errorf("sending SPAKE2 message: %w", err)
	}

	// Derive shared key
	sharedKey, err := exchange.Finish(theirMsg)
	if err != nil {
		return nil, fmt.Errorf("key exchange failed (wrong code?): %w", err)
	}

	opts.OnStatus("Key exchange complete, receiving identity...")

	// Receive encrypted identity
	encrypted, err := readFrame(conn)
	if err != nil {
		return nil, fmt.Errorf("receiving identity: %w", err)
	}

	// Decrypt payload
	payloadBytes, err := decryptPayload(sharedKey, encrypted)
	if err != nil {
		return nil, fmt.Errorf("decrypting identity (wrong code?): %w", err)
	}

	// Parse payload
	var payload IdentityPayload
	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		crypto.ZeroBytes(payloadBytes)
		return nil, fmt.Errorf("parsing identity: %w", err)
	}
	crypto.ZeroBytes(payloadBytes)

	// Reconstruct identity
	identity, err := crypto.IdentityFromEntropy(payload.SigningSeed, payload.Name)
	if err != nil {
		crypto.ZeroBytes(payload.SigningSeed)
		return nil, fmt.Errorf("reconstructing identity: %w", err)
	}
	crypto.ZeroBytes(payload.SigningSeed)

	// Restore original creation time
	identity.CreatedAt = payload.CreatedAt

	// Confirm fingerprint with user
	if opts.OnConfirm != nil {
		if !opts.OnConfirm(identity.Fingerprint()) {
			writeFrame(conn, []byte("REJECTED"))
			return nil, fmt.Errorf("fingerprint rejected by user")
		}
	}

	// Send confirmation
	if err := writeFrame(conn, []byte("OK")); err != nil {
		return nil, fmt.Errorf("sending confirmation: %w", err)
	}

	opts.OnStatus("Identity received successfully.")
	return identity, nil
}

// decryptPayload decrypts data with AES-256-GCM
func decryptPayload(key, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	if len(ciphertext) < gcm.NonceSize() {
		return nil, fmt.Errorf("ciphertext too short")
	}

	nonce := ciphertext[:gcm.NonceSize()]
	ciphertext = ciphertext[gcm.NonceSize():]

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}
