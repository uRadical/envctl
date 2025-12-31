package daemon

import (
	"errors"
	"log/slog"
	"sync"
	"time"

	"envctl.dev/go/envctl/internal/crypto"
)

var (
	// ErrAgentLocked is returned when the agent is locked and crypto operations are requested
	ErrAgentLocked = errors.New("agent is locked")
)

// Agent holds the unlocked identity in memory with auto-expiry
type Agent struct {
	mu sync.RWMutex

	identity     *crypto.Identity
	unlockedAt   time.Time
	expiresAt    time.Time
	lastActivity time.Time

	timeout     time.Duration
	idleTimeout time.Duration

	expireTimer *time.Timer
	idleTimer   *time.Timer

	onLock   func()
	onUnlock func()
}

// AgentConfig holds agent configuration
type AgentConfig struct {
	Timeout     time.Duration
	IdleTimeout time.Duration
	LockOnSleep bool
}

// DefaultAgentConfig returns sensible defaults
func DefaultAgentConfig() AgentConfig {
	return AgentConfig{
		Timeout:     1 * time.Hour,
		IdleTimeout: 30 * time.Minute,
		LockOnSleep: true,
	}
}

// NewAgent creates a new agent
func NewAgent(cfg AgentConfig) *Agent {
	return &Agent{
		timeout:     cfg.Timeout,
		idleTimeout: cfg.IdleTimeout,
	}
}

// SetCallbacks sets the lock/unlock callbacks
func (a *Agent) SetCallbacks(onLock, onUnlock func()) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.onLock = onLock
	a.onUnlock = onUnlock
}

// Unlock loads and caches the identity
func (a *Agent) Unlock(identity *crypto.Identity, timeout time.Duration) error {
	var callback func()

	a.mu.Lock()
	a.clearTimersLocked()

	a.identity = identity
	a.unlockedAt = time.Now()
	a.lastActivity = time.Now()

	if timeout == 0 {
		timeout = a.timeout
	}
	if timeout > 0 {
		a.expiresAt = time.Now().Add(timeout)
		a.expireTimer = time.AfterFunc(timeout, a.lock)
	} else {
		a.expiresAt = time.Time{} // Never expires
	}

	if a.idleTimeout > 0 {
		a.idleTimer = time.AfterFunc(a.idleTimeout, a.checkIdle)
	}

	slog.Info("agent unlocked",
		"name", identity.Name,
		"fingerprint", identity.Fingerprint(),
		"expires_in", timeout,
	)

	callback = a.onUnlock
	a.mu.Unlock()

	// Run callback outside lock so it can call agent methods like Decrypt
	if callback != nil {
		callback()
	}

	return nil
}

// Lock clears the cached identity
func (a *Agent) Lock() {
	a.lock()
}

func (a *Agent) lock() {
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.identity == nil {
		return
	}

	name := a.identity.Name

	a.identity = nil
	a.unlockedAt = time.Time{}
	a.expiresAt = time.Time{}
	a.lastActivity = time.Time{}

	a.clearTimersLocked()

	slog.Info("agent locked", "name", name)

	if a.onLock != nil {
		go a.onLock()
	}
}

func (a *Agent) clearTimersLocked() {
	if a.expireTimer != nil {
		a.expireTimer.Stop()
		a.expireTimer = nil
	}
	if a.idleTimer != nil {
		a.idleTimer.Stop()
		a.idleTimer = nil
	}
}

func (a *Agent) checkIdle() {
	a.mu.RLock()
	if a.identity == nil {
		a.mu.RUnlock()
		return
	}

	idleDuration := time.Since(a.lastActivity)
	a.mu.RUnlock()

	if idleDuration >= a.idleTimeout {
		slog.Info("agent idle timeout", "idle", idleDuration)
		a.lock()
		return
	}

	a.mu.Lock()
	remaining := a.idleTimeout - idleDuration
	a.idleTimer = time.AfterFunc(remaining, a.checkIdle)
	a.mu.Unlock()
}

func (a *Agent) touch() {
	a.mu.Lock()
	defer a.mu.Unlock()

	a.lastActivity = time.Now()

	if a.idleTimer != nil && a.idleTimeout > 0 {
		a.idleTimer.Stop()
		a.idleTimer = time.AfterFunc(a.idleTimeout, a.checkIdle)
	}
}

// IsUnlocked returns whether the agent has an unlocked identity
func (a *Agent) IsUnlocked() bool {
	a.mu.RLock()
	defer a.mu.RUnlock()

	return a.identity != nil && (a.expiresAt.IsZero() || time.Now().Before(a.expiresAt))
}

// AgentStatus represents the current agent status
type AgentStatus struct {
	Running      bool          `json:"running"`
	Unlocked     bool          `json:"unlocked"`
	Name         string        `json:"name,omitempty"`
	Fingerprint  string        `json:"fingerprint,omitempty"`
	UnlockedAt   time.Time     `json:"unlocked_at,omitempty"`
	ExpiresAt    time.Time     `json:"expires_at,omitempty"`
	ExpiresIn    time.Duration `json:"expires_in,omitempty"`
	LastActivity time.Time     `json:"last_activity,omitempty"`
	IdleFor      time.Duration `json:"idle_for,omitempty"`
	PendingCount int           `json:"pending_count,omitempty"`
}

// Status returns the current agent status
func (a *Agent) Status() AgentStatus {
	a.mu.RLock()
	defer a.mu.RUnlock()

	status := AgentStatus{Running: true}

	if a.identity != nil {
		status.Unlocked = true
		status.Name = a.identity.Name
		status.Fingerprint = a.identity.Fingerprint()
		status.UnlockedAt = a.unlockedAt
		status.ExpiresAt = a.expiresAt
		status.LastActivity = a.lastActivity

		if !a.expiresAt.IsZero() {
			status.ExpiresIn = time.Until(a.expiresAt)
		}
		status.IdleFor = time.Since(a.lastActivity)
	}

	return status
}

// Sign signs data using the cached identity
func (a *Agent) Sign(data []byte) ([]byte, error) {
	a.mu.RLock()
	identity := a.identity
	expiresAt := a.expiresAt
	a.mu.RUnlock()

	if identity == nil {
		return nil, ErrAgentLocked
	}

	if !expiresAt.IsZero() && time.Now().After(expiresAt) {
		a.lock()
		return nil, ErrAgentLocked
	}

	a.touch()
	return identity.Sign(data), nil
}

// Decrypt decrypts data using the cached identity
func (a *Agent) Decrypt(ciphertext []byte) ([]byte, error) {
	a.mu.RLock()
	identity := a.identity
	expiresAt := a.expiresAt
	a.mu.RUnlock()

	if identity == nil {
		return nil, ErrAgentLocked
	}

	if !expiresAt.IsZero() && time.Now().After(expiresAt) {
		a.lock()
		return nil, ErrAgentLocked
	}

	a.touch()
	return crypto.DecryptWithIdentity(ciphertext, identity)
}

// GetIdentity returns the cached identity if unlocked
func (a *Agent) GetIdentity() (*crypto.Identity, error) {
	a.mu.RLock()
	defer a.mu.RUnlock()

	if a.identity == nil {
		return nil, ErrAgentLocked
	}

	if !a.expiresAt.IsZero() && time.Now().After(a.expiresAt) {
		return nil, ErrAgentLocked
	}

	a.touch()
	return a.identity, nil
}

// ExtendTimeout extends the expiry time
func (a *Agent) ExtendTimeout(duration time.Duration) {
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.identity == nil {
		return
	}

	if a.expireTimer != nil {
		a.expireTimer.Stop()
	}

	a.expiresAt = time.Now().Add(duration)
	a.expireTimer = time.AfterFunc(duration, a.lock)

	slog.Debug("agent timeout extended", "expires_at", a.expiresAt)
}
