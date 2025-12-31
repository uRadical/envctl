package daemon

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"

	"envctl.dev/go/envctl/internal/secrets"
)

// Lease represents an active environment lease with TTL
type Lease struct {
	ID          string    `json:"id"`
	ProjectDir  string    `json:"project_dir"`
	ProjectName string    `json:"project_name"`
	Environment string    `json:"environment"`
	DotEnvPath  string    `json:"dotenv_path"`
	GrantedAt   time.Time `json:"granted_at"`
	ExpiresAt   time.Time `json:"expires_at"`
	TTL         string    `json:"ttl"` // Original TTL duration string for display
}

// IsExpired returns true if the lease has expired
func (l *Lease) IsExpired() bool {
	return time.Now().After(l.ExpiresAt)
}

// Remaining returns the time remaining on the lease
func (l *Lease) Remaining() time.Duration {
	remaining := time.Until(l.ExpiresAt)
	if remaining < 0 {
		return 0
	}
	return remaining
}

// LeaseManager manages active environment leases with TTL
type LeaseManager struct {
	mu       sync.RWMutex
	leases   map[string]*Lease // keyed by ID (projectDir + ":" + env)
	filePath string            // Path to persist leases
	daemon   *Daemon           // Reference to daemon for cleanup
	stopCh   chan struct{}
	wg       sync.WaitGroup
}

// NewLeaseManager creates a new lease manager
func NewLeaseManager(filePath string, daemon *Daemon) *LeaseManager {
	return &LeaseManager{
		leases:   make(map[string]*Lease),
		filePath: filePath,
		daemon:   daemon,
		stopCh:   make(chan struct{}),
	}
}

// leaseID generates a unique ID for a lease
func leaseID(projectDir, env string) string {
	return projectDir + ":" + env
}

// Start starts the lease expiry check loop
func (lm *LeaseManager) Start() {
	// Load persisted leases
	if err := lm.load(); err != nil {
		slog.Warn("Failed to load persisted leases", "error", err)
	}

	// Start expiry check loop
	lm.wg.Add(1)
	go lm.expiryLoop()

	slog.Info("Lease manager started", "active_leases", len(lm.leases))
}

// Stop stops the lease manager
func (lm *LeaseManager) Stop() {
	close(lm.stopCh)
	lm.wg.Wait()

	// Save leases before shutdown
	if err := lm.save(); err != nil {
		slog.Warn("Failed to save leases on shutdown", "error", err)
	}

	slog.Info("Lease manager stopped")
}

// expiryLoop checks for expired leases every minute
func (lm *LeaseManager) expiryLoop() {
	defer lm.wg.Done()

	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-lm.stopCh:
			return
		case <-ticker.C:
			lm.checkExpired()
		}
	}
}

// checkExpired checks for and cleans up expired leases
func (lm *LeaseManager) checkExpired() {
	lm.mu.Lock()
	defer lm.mu.Unlock()

	now := time.Now()
	var expired []*Lease

	for id, lease := range lm.leases {
		if now.After(lease.ExpiresAt) {
			expired = append(expired, lease)
			delete(lm.leases, id)
		}
	}

	// Clean up expired leases outside the lock (to avoid holding it during I/O)
	if len(expired) > 0 {
		// Save updated state first
		lm.saveUnlocked()

		// Clean up each expired lease
		for _, lease := range expired {
			lm.cleanupLease(lease)
		}
	}
}

// cleanupLease securely removes the .env file for an expired lease
func (lm *LeaseManager) cleanupLease(lease *Lease) {
	slog.Info("Lease expired, cleaning up",
		"project", lease.ProjectName,
		"env", lease.Environment,
		"dotenv", lease.DotEnvPath,
	)

	// Securely remove the .env file
	if err := secrets.RemoveDotEnv(lease.DotEnvPath); err != nil {
		slog.Error("Failed to remove .env on lease expiry",
			"path", lease.DotEnvPath,
			"error", err,
		)
	}

	// Broadcast event to IPC clients
	if lm.daemon != nil {
		payload, _ := json.Marshal(map[string]any{
			"project":     lease.ProjectName,
			"environment": lease.Environment,
			"project_dir": lease.ProjectDir,
			"reason":      "expired",
		})
		lm.daemon.BroadcastEvent(&Event{
			Event:   "lease.expired",
			Payload: payload,
		})
	}

	// Log audit event
	slog.Info("Environment access revoked",
		"project", lease.ProjectName,
		"env", lease.Environment,
		"reason", "lease_expired",
		"granted_at", lease.GrantedAt,
		"ttl", lease.TTL,
	)
}

// Grant creates a new lease for an environment
func (lm *LeaseManager) Grant(projectDir, projectName, env, dotEnvPath string, ttl time.Duration) (*Lease, error) {
	lm.mu.Lock()
	defer lm.mu.Unlock()

	id := leaseID(projectDir, env)
	now := time.Now()

	// Check if there's an existing lease
	if existing, ok := lm.leases[id]; ok {
		slog.Info("Replacing existing lease",
			"project", projectName,
			"env", env,
			"old_expires", existing.ExpiresAt,
		)
	}

	lease := &Lease{
		ID:          id,
		ProjectDir:  projectDir,
		ProjectName: projectName,
		Environment: env,
		DotEnvPath:  dotEnvPath,
		GrantedAt:   now,
		ExpiresAt:   now.Add(ttl),
		TTL:         ttl.String(),
	}

	lm.leases[id] = lease

	// Persist immediately
	if err := lm.saveUnlocked(); err != nil {
		slog.Warn("Failed to persist lease", "error", err)
	}

	slog.Info("Lease granted",
		"project", projectName,
		"env", env,
		"ttl", ttl,
		"expires", lease.ExpiresAt,
	)

	// Broadcast event
	if lm.daemon != nil {
		payload, _ := json.Marshal(map[string]any{
			"project":     projectName,
			"environment": env,
			"project_dir": projectDir,
			"expires_at":  lease.ExpiresAt,
			"ttl":         ttl.String(),
		})
		lm.daemon.BroadcastEvent(&Event{
			Event:   "lease.granted",
			Payload: payload,
		})
	}

	return lease, nil
}

// Revoke immediately revokes a lease and cleans up
func (lm *LeaseManager) Revoke(projectDir, env string) error {
	lm.mu.Lock()
	id := leaseID(projectDir, env)
	lease, ok := lm.leases[id]
	if !ok {
		lm.mu.Unlock()
		return fmt.Errorf("no active lease for %s:%s", projectDir, env)
	}

	delete(lm.leases, id)
	lm.saveUnlocked()
	lm.mu.Unlock()

	// Clean up outside lock
	slog.Info("Lease revoked",
		"project", lease.ProjectName,
		"env", lease.Environment,
	)

	if err := secrets.RemoveDotEnv(lease.DotEnvPath); err != nil {
		return fmt.Errorf("remove .env: %w", err)
	}

	// Broadcast event
	if lm.daemon != nil {
		payload, _ := json.Marshal(map[string]any{
			"project":     lease.ProjectName,
			"environment": lease.Environment,
			"project_dir": lease.ProjectDir,
			"reason":      "revoked",
		})
		lm.daemon.BroadcastEvent(&Event{
			Event:   "lease.revoked",
			Payload: payload,
		})
	}

	return nil
}

// Extend extends an existing lease by the given duration
func (lm *LeaseManager) Extend(projectDir, env string, extension time.Duration) (*Lease, error) {
	lm.mu.Lock()
	defer lm.mu.Unlock()

	id := leaseID(projectDir, env)
	lease, ok := lm.leases[id]
	if !ok {
		return nil, fmt.Errorf("no active lease for %s:%s", projectDir, env)
	}

	oldExpiry := lease.ExpiresAt
	lease.ExpiresAt = time.Now().Add(extension)
	lease.TTL = extension.String()

	if err := lm.saveUnlocked(); err != nil {
		slog.Warn("Failed to persist lease extension", "error", err)
	}

	slog.Info("Lease extended",
		"project", lease.ProjectName,
		"env", lease.Environment,
		"old_expires", oldExpiry,
		"new_expires", lease.ExpiresAt,
	)

	return lease, nil
}

// Get returns a lease by project dir and environment
func (lm *LeaseManager) Get(projectDir, env string) *Lease {
	lm.mu.RLock()
	defer lm.mu.RUnlock()

	return lm.leases[leaseID(projectDir, env)]
}

// List returns all active leases
func (lm *LeaseManager) List() []*Lease {
	lm.mu.RLock()
	defer lm.mu.RUnlock()

	result := make([]*Lease, 0, len(lm.leases))
	for _, lease := range lm.leases {
		result = append(result, lease)
	}
	return result
}

// Count returns the number of active leases
func (lm *LeaseManager) Count() int {
	lm.mu.RLock()
	defer lm.mu.RUnlock()
	return len(lm.leases)
}

// save persists leases to disk (must hold lock)
func (lm *LeaseManager) saveUnlocked() error {
	if lm.filePath == "" {
		return nil
	}

	// Ensure parent directory exists
	dir := filepath.Dir(lm.filePath)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("create lease dir: %w", err)
	}

	data, err := json.MarshalIndent(lm.leases, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal leases: %w", err)
	}

	if err := os.WriteFile(lm.filePath, data, 0600); err != nil {
		return fmt.Errorf("write leases: %w", err)
	}

	return nil
}

// save persists leases with locking
func (lm *LeaseManager) save() error {
	lm.mu.RLock()
	defer lm.mu.RUnlock()
	return lm.saveUnlocked()
}

// load loads persisted leases from disk
func (lm *LeaseManager) load() error {
	if lm.filePath == "" {
		return nil
	}

	data, err := os.ReadFile(lm.filePath)
	if os.IsNotExist(err) {
		return nil // No persisted leases
	}
	if err != nil {
		return fmt.Errorf("read leases: %w", err)
	}

	lm.mu.Lock()
	defer lm.mu.Unlock()

	if err := json.Unmarshal(data, &lm.leases); err != nil {
		return fmt.Errorf("unmarshal leases: %w", err)
	}

	// Remove already-expired leases and queue cleanup
	now := time.Now()
	var expired []*Lease
	for id, lease := range lm.leases {
		if now.After(lease.ExpiresAt) {
			expired = append(expired, lease)
			delete(lm.leases, id)
		}
	}

	// Clean up expired leases (do this after loading)
	if len(expired) > 0 {
		go func() {
			for _, lease := range expired {
				lm.cleanupLease(lease)
			}
		}()
	}

	return nil
}
