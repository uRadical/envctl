// Package relay provides a client for the envctl relay server.
package relay

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"log/slog"
	"math/rand"
	"sync"
	"time"

	"envctl.dev/go/envctl/internal/config"
	"envctl.dev/go/envctl/internal/crypto"
	"envctl.dev/go/envctl/internal/protocol"
)

// Reconnection backoff constants
const (
	initialBackoff = 2 * time.Second
	maxBackoff     = 60 * time.Second
	backoffFactor  = 2.0
	jitterFactor   = 0.2 // ±20%
)

// projectConn tracks a relay connection and its reconnection state.
type projectConn struct {
	client       *Client
	relayURL     string
	backoff      time.Duration
	reconnecting bool
}

// Manager manages relay connections for multiple projects.
// Each project can have its own relay URL configured in its chain.
type Manager struct {
	mu sync.RWMutex

	identity *crypto.Identity
	config   *config.RelayConfig

	// Per-project relay connections with reconnection state
	projects map[string]*projectConn

	// Callback for processing received messages
	onMessage func(project string, msg *protocol.Message) error

	// For lifecycle management
	ctx    context.Context
	cancel context.CancelFunc
}

// Status represents the status of relay connections.
type RelayStatus struct {
	ProjectStatuses map[string]*ProjectRelayStatus `json:"project_statuses"`
}

// ProjectRelayStatus represents the relay status for a single project.
type ProjectRelayStatus struct {
	Project        string    `json:"project"`
	URL            string    `json:"url"`
	Connected      bool      `json:"connected"`
	LastError      string    `json:"last_error,omitempty"`
	ConnectedSince time.Time `json:"connected_since,omitempty"`
	PendingCount   int       `json:"pending_count,omitempty"`
}

// NewManager creates a new relay manager.
func NewManager(identity *crypto.Identity, cfg *config.RelayConfig) *Manager {
	ctx, cancel := context.WithCancel(context.Background())
	return &Manager{
		identity: identity,
		config:   cfg,
		projects: make(map[string]*projectConn),
		ctx:      ctx,
		cancel:   cancel,
	}
}

// SetMessageHandler sets the callback for processing received messages.
func (m *Manager) SetMessageHandler(handler func(project string, msg *protocol.Message) error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.onMessage = handler
}

// ConnectProject connects to the relay for a specific project.
func (m *Manager) ConnectProject(project, relayURL string) error {
	if relayURL == "" {
		return fmt.Errorf("relay URL not configured for project %s", project)
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	// Check if already connected
	if pc, ok := m.projects[project]; ok && pc.client != nil && pc.client.Connected() {
		return nil
	}

	return m.connectProjectLocked(project, relayURL)
}

// connectProjectLocked connects to a project's relay. Must be called with mu held.
func (m *Manager) connectProjectLocked(project, relayURL string) error {
	signingKey := m.identity.SigningPrivateKey()
	publicKey := signingKey.Public().(ed25519.PublicKey)

	// Create disconnect callback that triggers reconnection
	onDisconnect := func() {
		go m.reconnectProject(project)
	}

	client, err := Connect(
		m.ctx,
		relayURL,
		m.identity.Fingerprint(),
		signingKey,
		publicKey,
		onDisconnect,
	)
	if err != nil {
		return fmt.Errorf("connect to relay: %w", err)
	}

	// Create or update project connection
	pc := m.projects[project]
	if pc == nil {
		pc = &projectConn{
			relayURL: relayURL,
			backoff:  initialBackoff,
		}
		m.projects[project] = pc
	}
	pc.client = client
	pc.relayURL = relayURL

	// Start message polling goroutine
	go m.pollMessages(project, client)

	slog.Info("connected to relay", "project", project, "url", relayURL)
	return nil
}

// reconnectProject attempts to reconnect to a project's relay with exponential backoff.
func (m *Manager) reconnectProject(project string) {
	m.mu.Lock()
	pc := m.projects[project]
	if pc == nil || pc.reconnecting {
		m.mu.Unlock()
		return
	}
	pc.reconnecting = true
	m.mu.Unlock()

	defer func() {
		m.mu.Lock()
		if pc := m.projects[project]; pc != nil {
			pc.reconnecting = false
		}
		m.mu.Unlock()
	}()

	for {
		// Wait with backoff before attempting reconnection
		m.mu.RLock()
		backoff := pc.backoff
		relayURL := pc.relayURL
		m.mu.RUnlock()

		backoffWithJitter := addJitter(backoff)
		slog.Debug("relay reconnecting", "project", project, "backoff", backoffWithJitter)

		select {
		case <-m.ctx.Done():
			return
		case <-time.After(backoffWithJitter):
		}

		// Attempt reconnection
		m.mu.Lock()
		err := m.connectProjectLocked(project, relayURL)
		if err == nil {
			// Success - reset backoff
			pc.backoff = initialBackoff
			m.mu.Unlock()
			slog.Info("relay reconnected", "project", project)
			return
		}

		// Failed - increase backoff
		pc.backoff = time.Duration(float64(pc.backoff) * backoffFactor)
		if pc.backoff > maxBackoff {
			pc.backoff = maxBackoff
		}
		m.mu.Unlock()

		slog.Debug("relay reconnect failed",
			"project", project,
			"error", err,
			"next_backoff", pc.backoff)
	}
}

// addJitter adds ±20% random jitter to a duration.
func addJitter(d time.Duration) time.Duration {
	jitter := time.Duration(float64(d) * jitterFactor * (rand.Float64()*2 - 1))
	return d + jitter
}

// DisconnectProject disconnects from the relay for a specific project.
func (m *Manager) DisconnectProject(project string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	pc, ok := m.projects[project]
	if !ok || pc.client == nil {
		return nil
	}

	delete(m.projects, project)
	return pc.client.Close()
}

// pollMessages periodically fetches messages from the relay.
func (m *Manager) pollMessages(project string, client *Client) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	// Initial fetch
	m.fetchAndProcess(project, client)

	for {
		select {
		case <-m.ctx.Done():
			return
		case <-ticker.C:
			if !client.Connected() {
				slog.Debug("relay disconnected, stopping poll", "project", project)
				return
			}
			m.fetchAndProcess(project, client)
		}
	}
}

// fetchAndProcess fetches messages from the relay and processes them.
func (m *Manager) fetchAndProcess(project string, client *Client) {
	messages, err := client.Fetch(100)
	if err != nil {
		slog.Debug("failed to fetch relay messages", "project", project, "error", err)
		return
	}

	if len(messages) == 0 {
		return
	}

	slog.Debug("fetched relay messages", "project", project, "count", len(messages))

	var ackIDs []string
	for _, msg := range messages {
		// Decrypt the message payload
		plaintext, err := crypto.DecryptWithIdentity(msg.Payload, m.identity)
		if err != nil {
			slog.Warn("failed to decrypt relay message", "project", project, "id", msg.ID, "error", err)
			// Acknowledge even if we can't decrypt, to remove it from the relay
			ackIDs = append(ackIDs, msg.ID)
			continue
		}

		// Parse as protocol message
		var protoMsg protocol.Message
		if err := json.Unmarshal(plaintext, &protoMsg); err != nil {
			slog.Warn("failed to parse relay message", "project", project, "id", msg.ID, "error", err)
			ackIDs = append(ackIDs, msg.ID)
			continue
		}

		// Process the message
		m.mu.RLock()
		handler := m.onMessage
		m.mu.RUnlock()

		if handler != nil {
			if err := handler(project, &protoMsg); err != nil {
				slog.Warn("failed to process relay message", "project", project, "id", msg.ID, "error", err)
			}
		}

		ackIDs = append(ackIDs, msg.ID)
	}

	// Acknowledge processed messages
	if len(ackIDs) > 0 {
		if err := client.Acknowledge(ackIDs); err != nil {
			slog.Warn("failed to acknowledge relay messages", "project", project, "error", err)
		}
	}
}

// SendToOfflinePeer sends a message to an offline peer via the relay.
// The message is encrypted using the recipient's ML-KEM public key.
func (m *Manager) SendToOfflinePeer(project, recipientFingerprint string, recipientPubKey *crypto.PublicIdentity, msg *protocol.Message) error {
	m.mu.RLock()
	pc, ok := m.projects[project]
	m.mu.RUnlock()

	if !ok || pc.client == nil || !pc.client.Connected() {
		return fmt.Errorf("not connected to relay for project %s", project)
	}
	client := pc.client

	// Serialize the message
	payload, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("marshal message: %w", err)
	}

	// Encrypt for the recipient
	encrypted, err := crypto.EncryptForIdentity(payload, recipientPubKey)
	if err != nil {
		return fmt.Errorf("encrypt message: %w", err)
	}

	// Send via relay
	msgID, err := client.Send(recipientFingerprint, encrypted)
	if err != nil {
		return fmt.Errorf("send via relay: %w", err)
	}

	slog.Debug("sent message via relay",
		"project", project,
		"to", recipientFingerprint[:8],
		"type", msg.Type,
		"relay_id", msgID)

	return nil
}

// Status returns the current status of all relay connections.
func (m *Manager) Status() *RelayStatus {
	m.mu.RLock()
	defer m.mu.RUnlock()

	status := &RelayStatus{
		ProjectStatuses: make(map[string]*ProjectRelayStatus),
	}

	for project, pc := range m.projects {
		if pc.client == nil {
			continue
		}
		ps := &ProjectRelayStatus{
			Project:   project,
			URL:       pc.client.URL(),
			Connected: pc.client.Connected(),
		}

		if lastErr := pc.client.LastError(); lastErr != nil {
			ps.LastError = lastErr.Error()
		}

		status.ProjectStatuses[project] = ps
	}

	return status
}

// ProjectStatus returns the relay status for a specific project.
func (m *Manager) ProjectStatus(project string) *ProjectRelayStatus {
	m.mu.RLock()
	defer m.mu.RUnlock()

	pc, ok := m.projects[project]
	if !ok || pc.client == nil {
		return &ProjectRelayStatus{
			Project:   project,
			Connected: false,
		}
	}

	ps := &ProjectRelayStatus{
		Project:   project,
		URL:       pc.client.URL(),
		Connected: pc.client.Connected(),
	}

	if lastErr := pc.client.LastError(); lastErr != nil {
		ps.LastError = lastErr.Error()
	}

	return ps
}

// IsProjectConnected returns whether we're connected to the relay for a project.
func (m *Manager) IsProjectConnected(project string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()

	pc, ok := m.projects[project]
	return ok && pc.client != nil && pc.client.Connected()
}

// Stop stops the manager and disconnects all relay connections.
func (m *Manager) Stop() error {
	m.cancel() // Signals all reconnect loops to exit

	m.mu.Lock()
	defer m.mu.Unlock()

	var lastErr error
	for project, pc := range m.projects {
		if pc.client != nil {
			if err := pc.client.Close(); err != nil {
				slog.Warn("failed to close relay client", "project", project, "error", err)
				lastErr = err
			}
		}
	}

	m.projects = make(map[string]*projectConn)
	return lastErr
}
