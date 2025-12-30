package daemon

import (
	"net"
	"testing"
	"time"
)

func TestConnectionLimiter_AllowConnection(t *testing.T) {
	config := &ConnectionLimiterConfig{
		MaxConnections:      10,
		ConnectionsPerSec:   100,
		ConnectionBurst:     100,
		MaxConnectionsPerIP: 3,
		IPConnectionsPerSec: 10,
		IPConnectionBurst:   10,
		HandshakeTimeout:    10 * time.Second,
		MaxFailuresPerIP:    3,
		FailureWindow:       time.Minute,
		BlockDuration:       time.Minute,
	}

	cl := NewConnectionLimiter(config)

	addr := &net.TCPAddr{IP: net.ParseIP("192.168.1.1"), Port: 12345}

	// First connection should be allowed
	if err := cl.AllowConnection(addr); err != nil {
		t.Errorf("First connection should be allowed: %v", err)
	}

	// Second and third should also be allowed
	if err := cl.AllowConnection(addr); err != nil {
		t.Errorf("Second connection should be allowed: %v", err)
	}
	if err := cl.AllowConnection(addr); err != nil {
		t.Errorf("Third connection should be allowed: %v", err)
	}

	// Fourth should be rejected (per-IP limit)
	if err := cl.AllowConnection(addr); err == nil {
		t.Error("Fourth connection should be rejected (per-IP limit)")
	}

	// Different IP should still work
	addr2 := &net.TCPAddr{IP: net.ParseIP("192.168.1.2"), Port: 12345}
	if err := cl.AllowConnection(addr2); err != nil {
		t.Errorf("Connection from different IP should be allowed: %v", err)
	}
}

func TestConnectionLimiter_GlobalLimit(t *testing.T) {
	config := &ConnectionLimiterConfig{
		MaxConnections:      3,
		ConnectionsPerSec:   100,
		ConnectionBurst:     100,
		MaxConnectionsPerIP: 10,
		IPConnectionsPerSec: 100,
		IPConnectionBurst:   100,
		HandshakeTimeout:    10 * time.Second,
		MaxFailuresPerIP:    5,
		FailureWindow:       time.Minute,
		BlockDuration:       time.Minute,
	}

	cl := NewConnectionLimiter(config)

	// Create connections from different IPs until global limit
	for i := 0; i < 3; i++ {
		addr := &net.TCPAddr{IP: net.ParseIP("192.168.1." + string(rune('1'+i))), Port: 12345}
		if err := cl.AllowConnection(addr); err != nil {
			t.Errorf("Connection %d should be allowed: %v", i+1, err)
		}
	}

	// Next connection should be rejected (global limit)
	addr := &net.TCPAddr{IP: net.ParseIP("192.168.1.100"), Port: 12345}
	if err := cl.AllowConnection(addr); err == nil {
		t.Error("Connection should be rejected (global limit)")
	}
}

func TestConnectionLimiter_ReleaseConnection(t *testing.T) {
	config := &ConnectionLimiterConfig{
		MaxConnections:      2,
		ConnectionsPerSec:   100,
		ConnectionBurst:     100,
		MaxConnectionsPerIP: 2,
		IPConnectionsPerSec: 100,
		IPConnectionBurst:   100,
		HandshakeTimeout:    10 * time.Second,
		MaxFailuresPerIP:    5,
		FailureWindow:       time.Minute,
		BlockDuration:       time.Minute,
	}

	cl := NewConnectionLimiter(config)

	addr := &net.TCPAddr{IP: net.ParseIP("192.168.1.1"), Port: 12345}

	// Fill up connections
	cl.AllowConnection(addr)
	cl.AllowConnection(addr)

	// Should be at limit
	if err := cl.AllowConnection(addr); err == nil {
		t.Error("Should be at limit")
	}

	// Release one connection
	cl.ReleaseConnection(addr)

	// Should now allow one more
	if err := cl.AllowConnection(addr); err != nil {
		t.Errorf("Should allow after release: %v", err)
	}
}

func TestConnectionLimiter_FailureBlocking(t *testing.T) {
	config := &ConnectionLimiterConfig{
		MaxConnections:      100,
		ConnectionsPerSec:   1000, // Very high for testing
		ConnectionBurst:     1000,
		MaxConnectionsPerIP: 100,
		IPConnectionsPerSec: 1000, // Very high for testing
		IPConnectionBurst:   1000,
		HandshakeTimeout:    10 * time.Second,
		MaxFailuresPerIP:    3,
		FailureWindow:       time.Minute,
		BlockDuration:       100 * time.Millisecond, // Short for testing
	}

	cl := NewConnectionLimiter(config)

	addr := &net.TCPAddr{IP: net.ParseIP("192.168.1.1"), Port: 12345}

	// Record failures
	cl.AllowConnection(addr)
	cl.RecordFailure(addr)
	cl.ReleaseConnection(addr)

	cl.AllowConnection(addr)
	cl.RecordFailure(addr)
	cl.ReleaseConnection(addr)

	cl.AllowConnection(addr)
	cl.RecordFailure(addr)
	cl.ReleaseConnection(addr)

	// IP should now be blocked
	if err := cl.AllowConnection(addr); err == nil {
		t.Error("IP should be blocked after failures")
	}

	// Wait for block to expire
	time.Sleep(150 * time.Millisecond)

	// Should be unblocked now
	if err := cl.AllowConnection(addr); err != nil {
		t.Errorf("IP should be unblocked after timeout: %v", err)
	}
}

func TestConnectionLimiter_SuccessResetsFailures(t *testing.T) {
	config := &ConnectionLimiterConfig{
		MaxConnections:      100,
		ConnectionsPerSec:   1000, // Very high for testing
		ConnectionBurst:     1000,
		MaxConnectionsPerIP: 100,
		IPConnectionsPerSec: 1000, // Very high for testing
		IPConnectionBurst:   1000,
		HandshakeTimeout:    10 * time.Second,
		MaxFailuresPerIP:    3,
		FailureWindow:       time.Minute,
		BlockDuration:       time.Minute,
	}

	cl := NewConnectionLimiter(config)

	addr := &net.TCPAddr{IP: net.ParseIP("192.168.1.1"), Port: 12345}

	// Record 2 failures
	cl.AllowConnection(addr)
	cl.RecordFailure(addr)
	cl.ReleaseConnection(addr)

	cl.AllowConnection(addr)
	cl.RecordFailure(addr)
	cl.ReleaseConnection(addr)

	// Record success (should reset counter)
	cl.AllowConnection(addr)
	cl.RecordSuccess(addr)
	cl.ReleaseConnection(addr)

	// Record 2 more failures (should not block because counter was reset)
	cl.AllowConnection(addr)
	cl.RecordFailure(addr)
	cl.ReleaseConnection(addr)

	cl.AllowConnection(addr)
	cl.RecordFailure(addr)
	cl.ReleaseConnection(addr)

	// Should still be allowed (only 2 failures since last success)
	if err := cl.AllowConnection(addr); err != nil {
		t.Errorf("Should not be blocked yet: %v", err)
	}
}

func TestConnectionLimiter_Stats(t *testing.T) {
	cl := NewConnectionLimiter(nil)

	addr1 := &net.TCPAddr{IP: net.ParseIP("192.168.1.1"), Port: 12345}
	addr2 := &net.TCPAddr{IP: net.ParseIP("192.168.1.2"), Port: 12345}

	cl.AllowConnection(addr1)
	cl.AllowConnection(addr2)

	stats := cl.Stats()
	if stats.CurrentConnections != 2 {
		t.Errorf("Expected 2 connections, got %d", stats.CurrentConnections)
	}

	cl.ReleaseConnection(addr1)

	stats = cl.Stats()
	if stats.CurrentConnections != 1 {
		t.Errorf("Expected 1 connection after release, got %d", stats.CurrentConnections)
	}
}

func TestExtractIP(t *testing.T) {
	tests := []struct {
		name     string
		addr     net.Addr
		expected string
	}{
		{
			name:     "TCPAddr",
			addr:     &net.TCPAddr{IP: net.ParseIP("192.168.1.1"), Port: 12345},
			expected: "192.168.1.1",
		},
		{
			name:     "UDPAddr",
			addr:     &net.UDPAddr{IP: net.ParseIP("10.0.0.1"), Port: 8080},
			expected: "10.0.0.1",
		},
		{
			name:     "IPv6",
			addr:     &net.TCPAddr{IP: net.ParseIP("::1"), Port: 443},
			expected: "::1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractIP(tt.addr)
			if result != tt.expected {
				t.Errorf("extractIP(%v) = %q, want %q", tt.addr, result, tt.expected)
			}
		})
	}
}
