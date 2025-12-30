package daemon

import (
	"fmt"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/time/rate"
)

// ConnectionLimiter protects against connection-level DoS attacks.
// It applies rate limiting BEFORE any message parsing occurs.
type ConnectionLimiter struct {
	// Global limits
	maxConnections     int32
	currentConnections int32
	connectionsPerSec  *rate.Limiter

	// Per-IP limits
	perIPLimits sync.Map // IP -> *ipLimit

	// Handshake timeout
	handshakeTimeout time.Duration

	// Blocked IPs (temporary bans)
	blocked sync.Map // IP -> unblockTime

	// Config
	maxConnectionsPerIP int32
	maxFailuresPerIP    int32
	blockDuration       time.Duration
	failureWindow       time.Duration
	ipConnectionsPerSec float64
	ipConnectionBurst   int
}

// ipLimit tracks connection state for a single IP
type ipLimit struct {
	connections int32
	limiter     *rate.Limiter
	failures    int32
	lastFailure time.Time
	mu          sync.Mutex
}

// ConnectionLimiterConfig holds configuration for the connection limiter
type ConnectionLimiterConfig struct {
	MaxConnections      int32         // Max total connections
	ConnectionsPerSec   float64       // New connections per second globally
	ConnectionBurst     int           // Burst allowance
	MaxConnectionsPerIP int32         // Max connections per IP
	IPConnectionsPerSec float64       // New connections per second per IP
	IPConnectionBurst   int           // Burst per IP
	HandshakeTimeout    time.Duration // Max time for handshake
	MaxFailuresPerIP    int32         // Failures before temp ban
	FailureWindow       time.Duration // Window for counting failures
	BlockDuration       time.Duration // How long to block after failures
}

// DefaultConnectionLimiterConfig returns production-safe defaults
func DefaultConnectionLimiterConfig() *ConnectionLimiterConfig {
	return &ConnectionLimiterConfig{
		MaxConnections:      100,              // Max 100 total connections
		ConnectionsPerSec:   10,               // 10 new connections/sec globally
		ConnectionBurst:     20,               // Burst of 20
		MaxConnectionsPerIP: 5,                // Max 5 per IP
		IPConnectionsPerSec: 2,                // 2 per second per IP
		IPConnectionBurst:   3,                // Burst of 3
		HandshakeTimeout:    10 * time.Second, // 10 second handshake deadline
		MaxFailuresPerIP:    5,                // 5 failures
		FailureWindow:       time.Minute,      // Within 1 minute
		BlockDuration:       5 * time.Minute,  // Block for 5 minutes
	}
}

// NewConnectionLimiter creates a new connection limiter
func NewConnectionLimiter(config *ConnectionLimiterConfig) *ConnectionLimiter {
	if config == nil {
		config = DefaultConnectionLimiterConfig()
	}

	return &ConnectionLimiter{
		maxConnections:      config.MaxConnections,
		connectionsPerSec:   rate.NewLimiter(rate.Limit(config.ConnectionsPerSec), config.ConnectionBurst),
		handshakeTimeout:    config.HandshakeTimeout,
		maxConnectionsPerIP: config.MaxConnectionsPerIP,
		maxFailuresPerIP:    config.MaxFailuresPerIP,
		blockDuration:       config.BlockDuration,
		failureWindow:       config.FailureWindow,
		ipConnectionsPerSec: config.IPConnectionsPerSec,
		ipConnectionBurst:   config.IPConnectionBurst,
	}
}

// AllowConnection checks if a new connection should be accepted.
// This MUST be called BEFORE any parsing occurs.
func (cl *ConnectionLimiter) AllowConnection(remoteAddr net.Addr) error {
	ip := extractIP(remoteAddr)

	// Check if IP is blocked
	if unblockTime, blocked := cl.blocked.Load(ip); blocked {
		if time.Now().Before(unblockTime.(time.Time)) {
			return fmt.Errorf("IP temporarily blocked")
		}
		cl.blocked.Delete(ip)
	}

	// Check global connection rate
	if !cl.connectionsPerSec.Allow() {
		return fmt.Errorf("global connection rate exceeded")
	}

	// Check global connection count
	if atomic.LoadInt32(&cl.currentConnections) >= cl.maxConnections {
		return fmt.Errorf("max connections reached")
	}

	// Check per-IP limits
	limit := cl.getIPLimit(ip)

	// Max connections per IP
	if atomic.LoadInt32(&limit.connections) >= cl.maxConnectionsPerIP {
		return fmt.Errorf("per-IP connection limit exceeded")
	}

	// Rate limit per IP
	if !limit.limiter.Allow() {
		return fmt.Errorf("per-IP rate limit exceeded")
	}

	// Track connection
	atomic.AddInt32(&cl.currentConnections, 1)
	atomic.AddInt32(&limit.connections, 1)

	return nil
}

// ReleaseConnection decrements connection counters.
// Must be called when a connection closes.
func (cl *ConnectionLimiter) ReleaseConnection(remoteAddr net.Addr) {
	ip := extractIP(remoteAddr)

	atomic.AddInt32(&cl.currentConnections, -1)

	if limitVal, ok := cl.perIPLimits.Load(ip); ok {
		limit := limitVal.(*ipLimit)
		atomic.AddInt32(&limit.connections, -1)
	}
}

// RecordFailure records a failed handshake/auth attempt.
// After too many failures, the IP is temporarily blocked.
func (cl *ConnectionLimiter) RecordFailure(remoteAddr net.Addr) {
	ip := extractIP(remoteAddr)
	limit := cl.getIPLimit(ip)

	limit.mu.Lock()
	defer limit.mu.Unlock()

	// Reset counter if outside failure window
	if time.Since(limit.lastFailure) > cl.failureWindow {
		limit.failures = 0
	}

	limit.failures++
	limit.lastFailure = time.Now()

	// Block IP after too many failures
	if limit.failures >= cl.maxFailuresPerIP {
		unblockTime := time.Now().Add(cl.blockDuration)
		cl.blocked.Store(ip, unblockTime)
		slog.Warn("IP blocked due to repeated failures",
			"ip", ip,
			"failures", limit.failures,
			"blocked_until", unblockTime.Format(time.RFC3339))

		// Reset counter
		limit.failures = 0
	}
}

// RecordSuccess resets the failure counter for an IP
func (cl *ConnectionLimiter) RecordSuccess(remoteAddr net.Addr) {
	ip := extractIP(remoteAddr)
	if limitVal, ok := cl.perIPLimits.Load(ip); ok {
		limit := limitVal.(*ipLimit)
		limit.mu.Lock()
		limit.failures = 0
		limit.mu.Unlock()
	}
}

// HandshakeTimeout returns the handshake deadline duration
func (cl *ConnectionLimiter) HandshakeTimeout() time.Duration {
	return cl.handshakeTimeout
}

// Stats returns current connection limiter statistics
func (cl *ConnectionLimiter) Stats() ConnectionLimiterStats {
	var blockedCount int
	cl.blocked.Range(func(_, _ interface{}) bool {
		blockedCount++
		return true
	})

	return ConnectionLimiterStats{
		CurrentConnections: atomic.LoadInt32(&cl.currentConnections),
		MaxConnections:     cl.maxConnections,
		BlockedIPs:         blockedCount,
	}
}

// ConnectionLimiterStats holds connection limiter statistics
type ConnectionLimiterStats struct {
	CurrentConnections int32
	MaxConnections     int32
	BlockedIPs         int
}

// getIPLimit returns or creates the rate limit state for an IP
func (cl *ConnectionLimiter) getIPLimit(ip string) *ipLimit {
	if limitVal, ok := cl.perIPLimits.Load(ip); ok {
		return limitVal.(*ipLimit)
	}

	limit := &ipLimit{
		limiter: rate.NewLimiter(rate.Limit(cl.ipConnectionsPerSec), cl.ipConnectionBurst),
	}

	actual, _ := cl.perIPLimits.LoadOrStore(ip, limit)
	return actual.(*ipLimit)
}

// extractIP extracts the IP address from a net.Addr
func extractIP(addr net.Addr) string {
	switch v := addr.(type) {
	case *net.TCPAddr:
		return v.IP.String()
	case *net.UDPAddr:
		return v.IP.String()
	default:
		// Fallback: try to parse as "host:port"
		host, _, err := net.SplitHostPort(addr.String())
		if err != nil {
			return addr.String()
		}
		return host
	}
}

// Cleanup removes stale entries from the limiter.
// Should be called periodically.
func (cl *ConnectionLimiter) Cleanup() {
	now := time.Now()

	// Remove expired blocks
	cl.blocked.Range(func(key, value interface{}) bool {
		if now.After(value.(time.Time)) {
			cl.blocked.Delete(key)
		}
		return true
	})

	// Remove stale IP limits (no connections, no recent failures)
	cl.perIPLimits.Range(func(key, value interface{}) bool {
		limit := value.(*ipLimit)
		limit.mu.Lock()
		if atomic.LoadInt32(&limit.connections) == 0 &&
			time.Since(limit.lastFailure) > 10*time.Minute {
			cl.perIPLimits.Delete(key)
		}
		limit.mu.Unlock()
		return true
	})
}
