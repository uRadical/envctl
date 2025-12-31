package link

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"time"

	"envctl.dev/go/envctl/internal/crypto"
)

// IdentityPayload is the encrypted data sent to target
type IdentityPayload struct {
	Name        string    `json:"name"`
	SigningSeed []byte    `json:"signing_seed"`
	CreatedAt   time.Time `json:"created_at"`
}

// StatusFunc is called to report status updates
type StatusFunc func(string)

// RunSource runs the source side of device linking
func RunSource(session *Session, onStatus StatusFunc) error {
	defer session.Close()

	// Start mDNS advertisement
	mdns, err := AdvertiseLinkSession(session.Code)
	if err != nil {
		slog.Warn("mDNS advertisement failed, using direct IP", "err", err)
	}
	if mdns != nil {
		defer mdns.Stop()
	}

	// Accept connection with timeout
	if tcpListener, ok := session.Listener().(*net.TCPListener); ok {
		tcpListener.SetDeadline(session.ExpiresAt)
	}

	onStatus("Waiting for connection...")

	conn, err := session.Listener().Accept()
	if err != nil {
		if isTimeout(err) {
			return fmt.Errorf("linking expired (no connection)")
		}
		return fmt.Errorf("accepting connection: %w", err)
	}
	defer conn.Close()

	onStatus(fmt.Sprintf("Connection from %s...", conn.RemoteAddr()))

	// Set connection deadline
	conn.SetDeadline(time.Now().Add(2 * time.Minute))

	// SPAKE2 key exchange
	exchange := NewSPAKE2Source(session.Code)

	// Send our message
	ourMsg := exchange.Start()
	if err := writeFrame(conn, ourMsg); err != nil {
		return fmt.Errorf("sending SPAKE2 message: %w", err)
	}

	// Receive their message
	theirMsg, err := readFrame(conn)
	if err != nil {
		session.IncrementAttempts()
		if session.Attempts >= MaxAttempts {
			return fmt.Errorf("too many failed attempts")
		}
		return fmt.Errorf("receiving SPAKE2 message: %w", err)
	}

	// Derive shared key
	sharedKey, err := exchange.Finish(theirMsg)
	if err != nil {
		session.IncrementAttempts()
		return fmt.Errorf("SPAKE2 failed (wrong code?): %w", err)
	}

	onStatus("Key exchange complete, sending identity...")

	// Get identity entropy
	entropy, err := session.Identity.ToEntropy()
	if err != nil {
		return fmt.Errorf("getting identity entropy: %w", err)
	}

	// Create payload
	payload := IdentityPayload{
		Name:        session.Identity.Name,
		SigningSeed: entropy,
		CreatedAt:   session.Identity.CreatedAt,
	}

	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshaling payload: %w", err)
	}

	// Encrypt payload with shared key
	encrypted, err := encryptPayload(sharedKey, payloadBytes)
	if err != nil {
		return fmt.Errorf("encrypting payload: %w", err)
	}

	// Zero sensitive data
	crypto.ZeroBytes(payloadBytes)
	crypto.ZeroBytes(entropy)

	// Send encrypted identity
	if err := writeFrame(conn, encrypted); err != nil {
		return fmt.Errorf("sending identity: %w", err)
	}

	// Wait for confirmation
	confirm, err := readFrame(conn)
	if err != nil {
		return fmt.Errorf("reading confirmation: %w", err)
	}

	if string(confirm) != "OK" {
		return fmt.Errorf("target rejected transfer: %s", string(confirm))
	}

	onStatus("Done. New device linked successfully.")
	return nil
}

// encryptPayload encrypts data with AES-256-GCM
func encryptPayload(key, plaintext []byte) ([]byte, error) {
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

	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
	return ciphertext, nil
}

// writeFrame writes a length-prefixed frame
func writeFrame(conn net.Conn, data []byte) error {
	// Write 4-byte length (big endian)
	length := uint32(len(data))
	header := []byte{
		byte(length >> 24),
		byte(length >> 16),
		byte(length >> 8),
		byte(length),
	}

	if _, err := conn.Write(header); err != nil {
		return err
	}

	_, err := conn.Write(data)
	return err
}

// readFrame reads a length-prefixed frame
func readFrame(conn net.Conn) ([]byte, error) {
	// Read 4-byte length
	header := make([]byte, 4)
	if _, err := io.ReadFull(conn, header); err != nil {
		return nil, err
	}

	length := uint32(header[0])<<24 | uint32(header[1])<<16 | uint32(header[2])<<8 | uint32(header[3])

	// Sanity check
	if length > 10*1024*1024 { // 10MB max
		return nil, fmt.Errorf("frame too large: %d", length)
	}

	data := make([]byte, length)
	if _, err := io.ReadFull(conn, data); err != nil {
		return nil, err
	}

	return data, nil
}

// isTimeout checks if an error is a timeout
func isTimeout(err error) bool {
	if netErr, ok := err.(net.Error); ok {
		return netErr.Timeout()
	}
	return false
}
