package daemon

import (
	"fmt"
	"sync"
	"time"

	"golang.org/x/time/rate"
	"uradical.io/go/envctl/internal/protocol"
)

// RateLimitConfig defines rate limits for P2P messages
type RateLimitConfig struct {
	// Per-peer limits
	PeerMessagesPerSecond float64 // Overall messages per second per peer
	PeerBurst             int     // Burst allowance per peer

	// Per-message-type limits (messages per minute)
	TypeLimits map[protocol.MessageType]TypeLimit

	// Global limits
	GlobalMessagesPerSecond float64
	GlobalBurst             int

	// Size limits per message type (bytes)
	TypeSizeLimits map[protocol.MessageType]int
}

// TypeLimit defines rate limit for a specific message type
type TypeLimit struct {
	PerMinute int // Max messages of this type per minute
	Burst     int // Burst allowance
}

// DefaultRateLimitConfig returns sensible defaults
func DefaultRateLimitConfig() *RateLimitConfig {
	return &RateLimitConfig{
		// Per-peer: 50 msg/sec with burst of 100
		PeerMessagesPerSecond: 50,
		PeerBurst:             100,

		// Per-type limits (per minute)
		TypeLimits: map[protocol.MessageType]TypeLimit{
			// High-frequency: ping/pong (allow many)
			protocol.MsgPing: {PerMinute: 120, Burst: 10},
			protocol.MsgPong: {PerMinute: 120, Burst: 10},

			// Medium-frequency: sync messages
			protocol.MsgChainHead:  {PerMinute: 30, Burst: 5},
			protocol.MsgGetBlocks:  {PerMinute: 20, Burst: 3},
			protocol.MsgBlocks:     {PerMinute: 30, Burst: 5},
			protocol.MsgRequest:    {PerMinute: 30, Burst: 5},
			protocol.MsgOffer:      {PerMinute: 30, Burst: 5},
			protocol.MsgPayload:    {PerMinute: 30, Burst: 5},
			protocol.MsgEnvUpdated: {PerMinute: 30, Burst: 5},

			// Low-frequency: proposals/approvals
			protocol.MsgProposal: {PerMinute: 10, Burst: 2},
			protocol.MsgApproval: {PerMinute: 20, Burst: 5},

			// Handshake (should only happen once)
			protocol.MsgHandshake: {PerMinute: 5, Burst: 2},
		},

		// Global: 500 msg/sec across all peers
		GlobalMessagesPerSecond: 500,
		GlobalBurst:             1000,

		// Size limits per type (bytes)
		TypeSizeLimits: map[protocol.MessageType]int{
			protocol.MsgPing:       1024,            // 1 KB
			protocol.MsgPong:       1024,            // 1 KB
			protocol.MsgHandshake:  4096,            // 4 KB
			protocol.MsgChainHead:  4096,            // 4 KB
			protocol.MsgGetBlocks:  1024,            // 1 KB
			protocol.MsgBlocks:     5 * 1024 * 1024, // 5 MB (chains can be large)
			protocol.MsgProposal:   1024 * 1024,     // 1 MB
			protocol.MsgApproval:   4096,            // 4 KB
			protocol.MsgRequest:    4096,            // 4 KB
			protocol.MsgOffer:      4096,            // 4 KB
			protocol.MsgPayload:    5 * 1024 * 1024, // 5 MB (env data)
			protocol.MsgEnvUpdated: 4096,            // 4 KB
			protocol.MsgAck:        1024,            // 1 KB
			protocol.MsgReject:     4096,            // 4 KB
		},
	}
}

// RateLimiter manages rate limiting for P2P connections
type RateLimiter struct {
	config *RateLimitConfig

	// Global limiter
	globalLimiter *rate.Limiter

	// Per-peer limiters
	peerLimiters sync.Map // fingerprint -> *rate.Limiter

	// Per-peer per-type limiters
	peerTypeLimiters sync.Map // "fingerprint:type" -> *rate.Limiter

	// Metrics
	mu            sync.RWMutex
	dropped       map[string]int64 // fingerprint -> count
	droppedByType map[protocol.MessageType]int64
}

// NewRateLimiter creates a new rate limiter
func NewRateLimiter(config *RateLimitConfig) *RateLimiter {
	if config == nil {
		config = DefaultRateLimitConfig()
	}

	return &RateLimiter{
		config:        config,
		globalLimiter: rate.NewLimiter(rate.Limit(config.GlobalMessagesPerSecond), config.GlobalBurst),
		dropped:       make(map[string]int64),
		droppedByType: make(map[protocol.MessageType]int64),
	}
}

// Allow checks if a message should be allowed through
func (rl *RateLimiter) Allow(peerFingerprint string, msgType protocol.MessageType, msgSize int) error {
	// Check 1: Message size limit
	if err := rl.checkSizeLimit(msgType, msgSize); err != nil {
		rl.recordDrop(peerFingerprint, msgType)
		return err
	}

	// Check 2: Global rate limit
	if !rl.globalLimiter.Allow() {
		rl.recordDrop(peerFingerprint, msgType)
		return fmt.Errorf("global rate limit exceeded")
	}

	// Check 3: Per-peer rate limit
	peerLimiter := rl.getPeerLimiter(peerFingerprint)
	if !peerLimiter.Allow() {
		rl.recordDrop(peerFingerprint, msgType)
		return fmt.Errorf("peer rate limit exceeded")
	}

	// Check 4: Per-type rate limit
	typeLimiter := rl.getTypeLimiter(peerFingerprint, msgType)
	if typeLimiter != nil && !typeLimiter.Allow() {
		rl.recordDrop(peerFingerprint, msgType)
		return fmt.Errorf("message type %s rate limit exceeded", msgType)
	}

	return nil
}

// checkSizeLimit verifies message size is within limits
func (rl *RateLimiter) checkSizeLimit(msgType protocol.MessageType, size int) error {
	limit, exists := rl.config.TypeSizeLimits[msgType]
	if !exists {
		// Default to 1MB for unknown types
		limit = 1024 * 1024
	}

	if size > limit {
		return fmt.Errorf("message size %d exceeds limit %d for type %s", size, limit, msgType)
	}

	return nil
}

// getPeerLimiter returns the rate limiter for a specific peer
func (rl *RateLimiter) getPeerLimiter(fingerprint string) *rate.Limiter {
	if limiter, ok := rl.peerLimiters.Load(fingerprint); ok {
		return limiter.(*rate.Limiter)
	}

	limiter := rate.NewLimiter(
		rate.Limit(rl.config.PeerMessagesPerSecond),
		rl.config.PeerBurst,
	)

	rl.peerLimiters.Store(fingerprint, limiter)
	return limiter
}

// getTypeLimiter returns the rate limiter for a specific peer and message type
func (rl *RateLimiter) getTypeLimiter(fingerprint string, msgType protocol.MessageType) *rate.Limiter {
	key := fmt.Sprintf("%s:%s", fingerprint, msgType)

	if limiter, ok := rl.peerTypeLimiters.Load(key); ok {
		return limiter.(*rate.Limiter)
	}

	typeLimit, exists := rl.config.TypeLimits[msgType]
	if !exists {
		return nil // No type-specific limit
	}

	// Convert per-minute to per-second
	perSecond := float64(typeLimit.PerMinute) / 60.0
	limiter := rate.NewLimiter(rate.Limit(perSecond), typeLimit.Burst)

	rl.peerTypeLimiters.Store(key, limiter)
	return limiter
}

// recordDrop records a dropped message for metrics
func (rl *RateLimiter) recordDrop(fingerprint string, msgType protocol.MessageType) {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	rl.dropped[fingerprint]++
	rl.droppedByType[msgType]++
}

// RemovePeer cleans up limiters for a disconnected peer
func (rl *RateLimiter) RemovePeer(fingerprint string) {
	rl.peerLimiters.Delete(fingerprint)

	// Remove all type limiters for this peer
	for msgType := range rl.config.TypeLimits {
		key := fmt.Sprintf("%s:%s", fingerprint, msgType)
		rl.peerTypeLimiters.Delete(key)
	}
}

// Stats returns rate limiting statistics
func (rl *RateLimiter) Stats() RateLimitStats {
	rl.mu.RLock()
	defer rl.mu.RUnlock()

	stats := RateLimitStats{
		DroppedByPeer: make(map[string]int64),
		DroppedByType: make(map[protocol.MessageType]int64),
	}

	for k, v := range rl.dropped {
		stats.DroppedByPeer[k] = v
		stats.TotalDropped += v
	}

	for k, v := range rl.droppedByType {
		stats.DroppedByType[k] = v
	}

	return stats
}

// RateLimitStats holds rate limiting statistics
type RateLimitStats struct {
	TotalDropped  int64
	DroppedByPeer map[string]int64
	DroppedByType map[protocol.MessageType]int64
}

// ResetStats resets the rate limiting statistics
func (rl *RateLimiter) ResetStats() {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	rl.dropped = make(map[string]int64)
	rl.droppedByType = make(map[protocol.MessageType]int64)
}

// GetDropCount returns the number of dropped messages for a peer
func (rl *RateLimiter) GetDropCount(fingerprint string) int64 {
	rl.mu.RLock()
	defer rl.mu.RUnlock()
	return rl.dropped[fingerprint]
}

// peerRateLimitDrops tracks rate limit drops per peer for disconnection logic
type peerRateLimitTracker struct {
	mu      sync.RWMutex
	drops   map[string]int
	lastReset map[string]time.Time
}

func newPeerRateLimitTracker() *peerRateLimitTracker {
	return &peerRateLimitTracker{
		drops:     make(map[string]int),
		lastReset: make(map[string]time.Time),
	}
}

func (t *peerRateLimitTracker) recordDrop(fingerprint string) int {
	t.mu.Lock()
	defer t.mu.Unlock()

	// Reset if it's been more than a minute since last reset
	if time.Since(t.lastReset[fingerprint]) > time.Minute {
		t.drops[fingerprint] = 0
		t.lastReset[fingerprint] = time.Now()
	}

	t.drops[fingerprint]++
	return t.drops[fingerprint]
}

func (t *peerRateLimitTracker) reset(fingerprint string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.drops[fingerprint] = 0
	t.lastReset[fingerprint] = time.Now()
}

func (t *peerRateLimitTracker) remove(fingerprint string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.drops, fingerprint)
	delete(t.lastReset, fingerprint)
}
