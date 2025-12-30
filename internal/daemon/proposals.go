package daemon

import (
	"context"
	"encoding/hex"
	"log/slog"
	"sync"
	"time"
)

const (
	// DefaultProposalTTL is how long proposals remain valid
	DefaultProposalTTL = 24 * time.Hour

	// ProposalCleanupInterval is how often to check for expired proposals
	ProposalCleanupInterval = 5 * time.Minute

	// MaxPendingProposals is the maximum number of pending proposals
	MaxPendingProposals = 1000
)

// EnhancedPendingProposal extends PendingProposal with TTL support
type EnhancedPendingProposal struct {
	*PendingProposal
	ExpiresAt time.Time
}

// IsExpired returns true if the proposal has expired
func (p *EnhancedPendingProposal) IsExpired() bool {
	return time.Now().After(p.ExpiresAt)
}

// TimeRemaining returns how long until the proposal expires
func (p *EnhancedPendingProposal) TimeRemaining() time.Duration {
	remaining := time.Until(p.ExpiresAt)
	if remaining < 0 {
		return 0
	}
	return remaining
}

// ProposalStore manages pending proposals with automatic expiry
type ProposalStore struct {
	proposals sync.Map // hashHex -> *EnhancedPendingProposal
	count     int64
	mu        sync.RWMutex

	ttl          time.Duration
	maxProposals int

	stopCh chan struct{}
}

// NewProposalStore creates a new proposal store
func NewProposalStore() *ProposalStore {
	return &ProposalStore{
		ttl:          DefaultProposalTTL,
		maxProposals: MaxPendingProposals,
		stopCh:       make(chan struct{}),
	}
}

// Start starts the background cleanup goroutine
func (ps *ProposalStore) Start(ctx context.Context) {
	go ps.cleanupLoop(ctx)
}

// Stop stops the background cleanup
func (ps *ProposalStore) Stop() {
	close(ps.stopCh)
}

// Add adds a new proposal
func (ps *ProposalStore) Add(hashHex string, proposal *PendingProposal) error {
	ps.mu.Lock()
	defer ps.mu.Unlock()

	// Check capacity
	if ps.count >= int64(ps.maxProposals) {
		// Try to clean up expired ones first
		ps.cleanupExpiredLocked()

		if ps.count >= int64(ps.maxProposals) {
			slog.Warn("Too many pending proposals, rejecting new proposal",
				"max", ps.maxProposals,
				"hash", hashHex[:min(8, len(hashHex))],
			)
			return errTooManyProposals
		}
	}

	enhanced := &EnhancedPendingProposal{
		PendingProposal: proposal,
		ExpiresAt:       time.Now().Add(ps.ttl),
	}

	ps.proposals.Store(hashHex, enhanced)
	ps.count++

	slog.Debug("Proposal added",
		"hash", hashHex[:min(8, len(hashHex))],
		"expires_at", enhanced.ExpiresAt.Format(time.RFC3339),
		"total_pending", ps.count,
	)

	return nil
}

// Get retrieves a proposal by hash
func (ps *ProposalStore) Get(hashHex string) (*EnhancedPendingProposal, bool) {
	value, ok := ps.proposals.Load(hashHex)
	if !ok {
		return nil, false
	}

	proposal := value.(*EnhancedPendingProposal)

	// Check if expired
	if proposal.IsExpired() {
		ps.Remove(hashHex)
		return nil, false
	}

	return proposal, true
}

// GetLegacy retrieves a proposal in legacy format (for compatibility)
func (ps *ProposalStore) GetLegacy(hashHex string) (*PendingProposal, bool) {
	enhanced, ok := ps.Get(hashHex)
	if !ok {
		return nil, false
	}
	return enhanced.PendingProposal, true
}

// Remove removes a proposal
func (ps *ProposalStore) Remove(hashHex string) {
	if _, loaded := ps.proposals.LoadAndDelete(hashHex); loaded {
		ps.mu.Lock()
		ps.count--
		ps.mu.Unlock()

		slog.Debug("Proposal removed", "hash", hashHex[:min(8, len(hashHex))])
	}
}

// List returns all non-expired proposals
func (ps *ProposalStore) List() []*EnhancedPendingProposal {
	var result []*EnhancedPendingProposal

	ps.proposals.Range(func(key, value interface{}) bool {
		proposal := value.(*EnhancedPendingProposal)

		if !proposal.IsExpired() {
			result = append(result, proposal)
		}

		return true
	})

	return result
}

// ListForTeam returns proposals for a specific team
func (ps *ProposalStore) ListForTeam(team string) []*EnhancedPendingProposal {
	var result []*EnhancedPendingProposal

	ps.proposals.Range(func(key, value interface{}) bool {
		proposal := value.(*EnhancedPendingProposal)

		if !proposal.IsExpired() && proposal.Team == team {
			result = append(result, proposal)
		}

		return true
	})

	return result
}

// Count returns the number of pending proposals
func (ps *ProposalStore) Count() int {
	ps.mu.RLock()
	defer ps.mu.RUnlock()
	return int(ps.count)
}

// cleanupLoop periodically removes expired proposals
func (ps *ProposalStore) cleanupLoop(ctx context.Context) {
	ticker := time.NewTicker(ProposalCleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ps.stopCh:
			return
		case <-ticker.C:
			ps.cleanupExpired()
		}
	}
}

// cleanupExpired removes expired proposals
func (ps *ProposalStore) cleanupExpired() {
	ps.mu.Lock()
	defer ps.mu.Unlock()
	ps.cleanupExpiredLocked()
}

// cleanupExpiredLocked removes expired proposals (must hold lock)
func (ps *ProposalStore) cleanupExpiredLocked() {
	var expired []string

	ps.proposals.Range(func(key, value interface{}) bool {
		proposal := value.(*EnhancedPendingProposal)

		if proposal.IsExpired() {
			expired = append(expired, key.(string))
		}

		return true
	})

	for _, hashHex := range expired {
		if value, loaded := ps.proposals.LoadAndDelete(hashHex); loaded {
			ps.count--

			proposal := value.(*EnhancedPendingProposal)

			slog.Info("Expired proposal removed",
				"hash", hashHex[:min(8, len(hashHex))],
				"team", proposal.Team,
				"action", proposal.Block.Action,
				"created_at", proposal.ReceivedAt.Format(time.RFC3339),
				"approvals", len(proposal.Approvals),
			)
		}
	}

	if len(expired) > 0 {
		slog.Debug("Proposal cleanup complete",
			"removed", len(expired),
			"remaining", ps.count,
		)
	}
}

// SetTTL sets the proposal TTL (for testing)
func (ps *ProposalStore) SetTTL(ttl time.Duration) {
	ps.ttl = ttl
}

// errTooManyProposals is returned when the proposal store is at capacity
var errTooManyProposals = &tooManyProposalsError{}

type tooManyProposalsError struct{}

func (e *tooManyProposalsError) Error() string {
	return "too many pending proposals"
}

// MigratePendingProposals migrates from the old map-based storage to ProposalStore
func MigratePendingProposals(oldProposals map[string]*PendingProposal, store *ProposalStore) {
	for hashHex, proposal := range oldProposals {
		store.Add(hashHex, proposal)
	}
}

// ProposalInfo represents public info about a proposal (for IPC/web)
type ProposalInfo struct {
	Hash              string    `json:"hash"`
	Team              string    `json:"team"`
	Action            string    `json:"action"`
	BlockIndex        uint64    `json:"block_index"`
	CreatedAt         time.Time `json:"created_at"`
	ExpiresAt         time.Time `json:"expires_at"`
	TimeRemaining     string    `json:"time_remaining"`
	Approvals         int       `json:"approvals"`
	RequiredApprovals int       `json:"required_approvals"`
}

// ToInfo converts an EnhancedPendingProposal to ProposalInfo
func (p *EnhancedPendingProposal) ToInfo(requiredApprovals int) *ProposalInfo {
	return &ProposalInfo{
		Hash:              hex.EncodeToString(p.Block.Hash),
		Team:              p.Team,
		Action:            string(p.Block.Action),
		BlockIndex:        p.Block.Index,
		CreatedAt:         p.ReceivedAt,
		ExpiresAt:         p.ExpiresAt,
		TimeRemaining:     p.TimeRemaining().Round(time.Second).String(),
		Approvals:         len(p.Block.Approvals),
		RequiredApprovals: requiredApprovals,
	}
}

// PeerManagerProposalMethods contains methods to integrate with PeerManager
// These methods wrap the ProposalStore and maintain backwards compatibility

// InitProposalStore initializes the proposal store for a PeerManager
func (pm *PeerManager) InitProposalStore(ctx context.Context) {
	pm.proposalStore = NewProposalStore()
	pm.proposalStore.Start(ctx)
}

// StopProposalStore stops the proposal store
func (pm *PeerManager) StopProposalStore() {
	if pm.proposalStore != nil {
		pm.proposalStore.Stop()
	}
}

// AddPendingProposalWithTTL adds a proposal with TTL support
func (pm *PeerManager) AddPendingProposalWithTTL(hashHex string, proposal *PendingProposal) error {
	if pm.proposalStore != nil {
		return pm.proposalStore.Add(hashHex, proposal)
	}

	// Fallback to old behavior
	pm.mu.Lock()
	pm.pendingProposals[hashHex] = proposal
	pm.mu.Unlock()
	return nil
}

// GetPendingProposalWithTTL gets a proposal, checking TTL
func (pm *PeerManager) GetPendingProposalWithTTL(hashHex string) (*PendingProposal, bool) {
	if pm.proposalStore != nil {
		return pm.proposalStore.GetLegacy(hashHex)
	}

	// Fallback to old behavior
	pm.mu.RLock()
	proposal, ok := pm.pendingProposals[hashHex]
	pm.mu.RUnlock()
	return proposal, ok
}

// RemovePendingProposalWithTTL removes a proposal
func (pm *PeerManager) RemovePendingProposalWithTTL(hashHex string) {
	if pm.proposalStore != nil {
		pm.proposalStore.Remove(hashHex)
		return
	}

	// Fallback to old behavior
	pm.mu.Lock()
	delete(pm.pendingProposals, hashHex)
	pm.mu.Unlock()
}

// GetPendingProposalInfo returns proposal info for IPC/web
func (pm *PeerManager) GetPendingProposalInfo(hashHex string) (*ProposalInfo, bool) {
	if pm.proposalStore == nil {
		return nil, false
	}

	enhanced, ok := pm.proposalStore.Get(hashHex)
	if !ok {
		return nil, false
	}

	c := pm.daemon.GetChain(enhanced.Team)
	required := 0
	if c != nil {
		required = c.RequiredApprovals(enhanced.Block)
	}

	return enhanced.ToInfo(required), true
}

// ListPendingProposalsInfo returns all proposals as ProposalInfo
func (pm *PeerManager) ListPendingProposalsInfo() []*ProposalInfo {
	if pm.proposalStore == nil {
		return nil
	}

	proposals := pm.proposalStore.List()
	result := make([]*ProposalInfo, 0, len(proposals))

	for _, p := range proposals {
		c := pm.daemon.GetChain(p.Team)
		required := 0
		if c != nil {
			required = c.RequiredApprovals(p.Block)
		}
		result = append(result, p.ToInfo(required))
	}

	return result
}
