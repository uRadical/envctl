// Package relay provides a client for the envctl relay server.
// The relay acts as a store-and-forward mailbox for encrypted messages
// between peers that aren't directly connected.
package relay

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"
)

// Client is a relay server client.
type Client struct {
	url         string
	conn        *websocket.Conn
	fingerprint string
	signingKey  ed25519.PrivateKey
	publicKey   ed25519.PublicKey

	sendCh chan *Envelope
	done   chan struct{}

	mu        sync.Mutex
	connected atomic.Bool
	lastError error

	// Callback when connection drops (for reconnection)
	onDisconnect func()

	// For request/response correlation
	pendingMu sync.Mutex
	pending   map[string]chan *Envelope
	reqID     atomic.Uint64
}

// Envelope is the wire format for relay messages.
type Envelope struct {
	Type    string          `json:"type"`
	Payload json.RawMessage `json:"payload"`
}

// Message represents a message received from the relay.
type Message struct {
	ID        string    `json:"id"`
	From      string    `json:"from"`
	Payload   []byte    `json:"-"` // Decoded from base64
	RawB64    string    `json:"payload"`
	CreatedAt time.Time `json:"created_at"`
}

// Status represents the relay connection status.
type Status struct {
	Connected      bool      `json:"connected"`
	URL            string    `json:"url"`
	Fingerprint    string    `json:"fingerprint"`
	PendingCount   int       `json:"pending_count"`
	LastError      string    `json:"last_error,omitempty"`
	ConnectedSince time.Time `json:"connected_since,omitempty"`
}

// Connect establishes a connection to the relay server and authenticates.
// The onDisconnect callback is called when the connection drops unexpectedly.
func Connect(ctx context.Context, url string, fingerprint string, signingKey ed25519.PrivateKey, publicKey ed25519.PublicKey, onDisconnect func()) (*Client, error) {
	c := &Client{
		url:          url,
		fingerprint:  fingerprint,
		signingKey:   signingKey,
		publicKey:    publicKey,
		sendCh:       make(chan *Envelope, 100),
		done:         make(chan struct{}),
		pending:      make(map[string]chan *Envelope),
		onDisconnect: onDisconnect,
	}

	if err := c.connect(ctx); err != nil {
		return nil, err
	}

	return c, nil
}

func (c *Client) connect(ctx context.Context) error {
	dialer := websocket.Dialer{
		HandshakeTimeout: 10 * time.Second,
	}

	conn, _, err := dialer.DialContext(ctx, c.url, nil)
	if err != nil {
		return fmt.Errorf("dial relay: %w", err)
	}

	c.conn = conn

	// Authenticate
	if err := c.authenticate(ctx); err != nil {
		conn.Close()
		return fmt.Errorf("authenticate: %w", err)
	}

	c.connected.Store(true)

	// Start send/receive loops
	go c.sendLoop()
	go c.receiveLoop()

	return nil
}

func (c *Client) authenticate(ctx context.Context) error {
	// Step 1: Request challenge
	challengeReq := map[string]string{
		"fingerprint": c.fingerprint,
	}
	if err := c.writeEnvelope("challenge", challengeReq); err != nil {
		return fmt.Errorf("send challenge request: %w", err)
	}

	// Step 2: Read challenge response with nonce
	env, err := c.readEnvelope()
	if err != nil {
		return fmt.Errorf("read challenge: %w", err)
	}

	if env.Type == "error" {
		var errResp struct {
			Message string `json:"message"`
		}
		json.Unmarshal(env.Payload, &errResp)
		return fmt.Errorf("challenge failed: %s", errResp.Message)
	}

	if env.Type != "challenge" {
		return fmt.Errorf("expected challenge response, got %s", env.Type)
	}

	var challengeResp struct {
		Nonce string `json:"nonce"`
	}
	if err := json.Unmarshal(env.Payload, &challengeResp); err != nil {
		return fmt.Errorf("parse challenge: %w", err)
	}

	// Step 3: Sign nonce
	nonce, err := hex.DecodeString(challengeResp.Nonce)
	if err != nil {
		return fmt.Errorf("decode nonce: %w", err)
	}

	signature := ed25519.Sign(c.signingKey, nonce)

	// Step 4: Send auth
	authReq := map[string]string{
		"fingerprint": c.fingerprint,
		"public_key":  hex.EncodeToString(c.publicKey),
		"signature":   hex.EncodeToString(signature),
	}
	if err := c.writeEnvelope("auth", authReq); err != nil {
		return fmt.Errorf("send auth: %w", err)
	}

	// Step 5: Read auth response
	env, err = c.readEnvelope()
	if err != nil {
		return fmt.Errorf("read auth response: %w", err)
	}

	if env.Type == "error" {
		var errResp struct {
			Message string `json:"message"`
		}
		json.Unmarshal(env.Payload, &errResp)
		return fmt.Errorf("auth failed: %s", errResp.Message)
	}

	if env.Type != "auth" {
		return fmt.Errorf("expected auth response, got %s", env.Type)
	}

	var authResp struct {
		Success bool   `json:"success"`
		Error   string `json:"error,omitempty"`
	}
	if err := json.Unmarshal(env.Payload, &authResp); err != nil {
		return fmt.Errorf("parse auth response: %w", err)
	}

	if !authResp.Success {
		return fmt.Errorf("auth rejected: %s", authResp.Error)
	}

	slog.Debug("relay authenticated", "url", c.url, "fingerprint", c.fingerprint[:8])
	return nil
}

func (c *Client) writeEnvelope(msgType string, payload any) error {
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	env := Envelope{
		Type:    msgType,
		Payload: payloadBytes,
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	c.conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
	return c.conn.WriteJSON(env)
}

func (c *Client) readEnvelope() (*Envelope, error) {
	c.conn.SetReadDeadline(time.Now().Add(60 * time.Second))
	var env Envelope
	if err := c.conn.ReadJSON(&env); err != nil {
		return nil, err
	}
	return &env, nil
}

func (c *Client) sendLoop() {
	for {
		select {
		case <-c.done:
			return
		case env := <-c.sendCh:
			c.mu.Lock()
			c.conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
			err := c.conn.WriteJSON(env)
			c.mu.Unlock()

			if err != nil {
				slog.Debug("relay send error", "error", err)
				c.lastError = err
				return
			}
		}
	}
}

func (c *Client) receiveLoop() {
	defer func() {
		wasConnected := c.connected.Swap(false)
		// Only call onDisconnect if we were connected (not a graceful close)
		if wasConnected && c.onDisconnect != nil {
			c.onDisconnect()
		}
	}()

	for {
		select {
		case <-c.done:
			return
		default:
		}

		env, err := c.readEnvelope()
		if err != nil {
			slog.Debug("relay receive error", "error", err)
			c.lastError = err
			return
		}

		c.handleEnvelope(env)
	}
}

func (c *Client) handleEnvelope(env *Envelope) {
	// Check if this is a response to a pending request
	c.pendingMu.Lock()
	// For fetch responses, we use a simple correlation
	if ch, ok := c.pending["fetch"]; ok && env.Type == "fetch" {
		delete(c.pending, "fetch")
		c.pendingMu.Unlock()
		ch <- env
		return
	}
	if ch, ok := c.pending["send"]; ok && env.Type == "send" {
		delete(c.pending, "send")
		c.pendingMu.Unlock()
		ch <- env
		return
	}
	if ch, ok := c.pending["ack"]; ok && env.Type == "ack" {
		delete(c.pending, "ack")
		c.pendingMu.Unlock()
		ch <- env
		return
	}
	c.pendingMu.Unlock()

	// Handle real-time message push
	if env.Type == "message" {
		slog.Debug("relay received pushed message")
		// TODO: Handle real-time message push
	}
}

// Send delivers an encrypted message to a recipient via the relay.
// Returns the message ID assigned by the relay.
func (c *Client) Send(to string, payload []byte) (string, error) {
	if !c.connected.Load() {
		return "", fmt.Errorf("not connected to relay")
	}

	// Create response channel
	respCh := make(chan *Envelope, 1)
	c.pendingMu.Lock()
	c.pending["send"] = respCh
	c.pendingMu.Unlock()

	// Send message
	sendReq := map[string]string{
		"to":      to,
		"payload": base64.StdEncoding.EncodeToString(payload),
	}

	if err := c.writeEnvelope("send", sendReq); err != nil {
		c.pendingMu.Lock()
		delete(c.pending, "send")
		c.pendingMu.Unlock()
		return "", fmt.Errorf("send message: %w", err)
	}

	// Wait for response
	select {
	case resp := <-respCh:
		if resp.Type == "error" {
			var errResp struct {
				Message string `json:"message"`
			}
			json.Unmarshal(resp.Payload, &errResp)
			return "", fmt.Errorf("send failed: %s", errResp.Message)
		}

		var sendResp struct {
			ID string `json:"id"`
		}
		if err := json.Unmarshal(resp.Payload, &sendResp); err != nil {
			return "", fmt.Errorf("parse send response: %w", err)
		}
		return sendResp.ID, nil

	case <-time.After(30 * time.Second):
		c.pendingMu.Lock()
		delete(c.pending, "send")
		c.pendingMu.Unlock()
		return "", fmt.Errorf("send timeout")
	}
}

// Fetch retrieves pending messages from the relay.
func (c *Client) Fetch(limit int) ([]*Message, error) {
	if !c.connected.Load() {
		return nil, fmt.Errorf("not connected to relay")
	}

	// Create response channel
	respCh := make(chan *Envelope, 1)
	c.pendingMu.Lock()
	c.pending["fetch"] = respCh
	c.pendingMu.Unlock()

	// Send fetch request
	fetchReq := map[string]int{
		"limit": limit,
	}

	if err := c.writeEnvelope("fetch", fetchReq); err != nil {
		c.pendingMu.Lock()
		delete(c.pending, "fetch")
		c.pendingMu.Unlock()
		return nil, fmt.Errorf("fetch messages: %w", err)
	}

	// Wait for response
	select {
	case resp := <-respCh:
		if resp.Type == "error" {
			var errResp struct {
				Message string `json:"message"`
			}
			json.Unmarshal(resp.Payload, &errResp)
			return nil, fmt.Errorf("fetch failed: %s", errResp.Message)
		}

		var fetchResp struct {
			Messages []struct {
				ID        string `json:"id"`
				From      string `json:"from"`
				Payload   string `json:"payload"`
				CreatedAt string `json:"created_at"`
			} `json:"messages"`
		}
		if err := json.Unmarshal(resp.Payload, &fetchResp); err != nil {
			return nil, fmt.Errorf("parse fetch response: %w", err)
		}

		messages := make([]*Message, 0, len(fetchResp.Messages))
		for _, m := range fetchResp.Messages {
			payload, err := base64.StdEncoding.DecodeString(m.Payload)
			if err != nil {
				slog.Warn("failed to decode message payload", "id", m.ID, "error", err)
				continue
			}

			createdAt, _ := time.Parse(time.RFC3339, m.CreatedAt)
			messages = append(messages, &Message{
				ID:        m.ID,
				From:      m.From,
				Payload:   payload,
				CreatedAt: createdAt,
			})
		}

		return messages, nil

	case <-time.After(30 * time.Second):
		c.pendingMu.Lock()
		delete(c.pending, "fetch")
		c.pendingMu.Unlock()
		return nil, fmt.Errorf("fetch timeout")
	}
}

// Acknowledge marks messages as received and deletes them from the relay.
func (c *Client) Acknowledge(ids []string) error {
	if !c.connected.Load() {
		return fmt.Errorf("not connected to relay")
	}

	if len(ids) == 0 {
		return nil
	}

	// Create response channel
	respCh := make(chan *Envelope, 1)
	c.pendingMu.Lock()
	c.pending["ack"] = respCh
	c.pendingMu.Unlock()

	// Send ack request
	ackReq := map[string][]string{
		"ids": ids,
	}

	if err := c.writeEnvelope("ack", ackReq); err != nil {
		c.pendingMu.Lock()
		delete(c.pending, "ack")
		c.pendingMu.Unlock()
		return fmt.Errorf("acknowledge messages: %w", err)
	}

	// Wait for response
	select {
	case resp := <-respCh:
		if resp.Type == "error" {
			var errResp struct {
				Message string `json:"message"`
			}
			json.Unmarshal(resp.Payload, &errResp)
			return fmt.Errorf("ack failed: %s", errResp.Message)
		}
		return nil

	case <-time.After(30 * time.Second):
		c.pendingMu.Lock()
		delete(c.pending, "ack")
		c.pendingMu.Unlock()
		return fmt.Errorf("ack timeout")
	}
}

// Close disconnects from the relay.
func (c *Client) Close() error {
	c.connected.Store(false)
	close(c.done)

	c.mu.Lock()
	defer c.mu.Unlock()

	if c.conn != nil {
		// Send close frame
		c.conn.WriteControl(
			websocket.CloseMessage,
			websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""),
			time.Now().Add(time.Second),
		)
		return c.conn.Close()
	}
	return nil
}

// Connected returns whether the client is connected to the relay.
func (c *Client) Connected() bool {
	return c.connected.Load()
}

// URL returns the relay URL.
func (c *Client) URL() string {
	return c.url
}

// LastError returns the last error encountered.
func (c *Client) LastError() error {
	return c.lastError
}
