package daemon

import (
	"testing"
	"time"
)

func TestMetricsNew(t *testing.T) {
	m := NewMetrics()
	if m == nil {
		t.Fatal("NewMetrics returned nil")
	}

	if m.startTime.IsZero() {
		t.Error("startTime should be set")
	}
}

func TestMetricsRecordMessage(t *testing.T) {
	m := NewMetrics()

	// Record some messages
	m.RecordMessageReceived("proposal", 1024)
	m.RecordMessageReceived("proposal", 2048)
	m.RecordMessageReceived("approval", 512)
	m.RecordMessageSent("chain_head", 256)

	if m.MessagesReceived.Load() != 3 {
		t.Errorf("MessagesReceived: got %d, want 3", m.MessagesReceived.Load())
	}

	if m.MessagesSent.Load() != 1 {
		t.Errorf("MessagesSent: got %d, want 1", m.MessagesSent.Load())
	}

	if m.BytesReceived.Load() != 3584 { // 1024 + 2048 + 512
		t.Errorf("BytesReceived: got %d, want 3584", m.BytesReceived.Load())
	}
}

func TestMetricsRecordError(t *testing.T) {
	m := NewMetrics()

	m.RecordError("tls_handshake", "connection refused", "192.168.1.1:7834")
	m.RecordError("send", "broken pipe", "peer123")

	snapshot := m.Snapshot(nil)
	if len(snapshot.RecentErrors) != 2 {
		t.Errorf("RecentErrors: got %d, want 2", len(snapshot.RecentErrors))
	}

	// Most recent error should be first
	if snapshot.RecentErrors[0].Type != "send" {
		t.Errorf("First error type: got %s, want send", snapshot.RecentErrors[0].Type)
	}
}

func TestMetricsRecordLatency(t *testing.T) {
	m := NewMetrics()

	// Record some latencies
	m.RecordHandshakeLatency(10 * time.Millisecond)
	m.RecordHandshakeLatency(20 * time.Millisecond)
	m.RecordHandshakeLatency(15 * time.Millisecond)

	m.RecordSyncLatency(100 * time.Millisecond)
	m.RecordSyncLatency(200 * time.Millisecond)

	snapshot := m.Snapshot(nil)

	// Check handshake latency (avg should be ~15ms)
	if snapshot.Latencies.HandshakeAvgMs < 14 || snapshot.Latencies.HandshakeAvgMs > 16 {
		t.Errorf("HandshakeAvgMs: got %f, want ~15", snapshot.Latencies.HandshakeAvgMs)
	}

	// Check sync latency (avg should be 150ms)
	if snapshot.Latencies.SyncAvgMs < 140 || snapshot.Latencies.SyncAvgMs > 160 {
		t.Errorf("SyncAvgMs: got %f, want ~150", snapshot.Latencies.SyncAvgMs)
	}
}

func TestMetricsCounters(t *testing.T) {
	m := NewMetrics()

	m.BlocksCommitted.Add(5)
	m.ProposalsCreated.Add(10)
	m.RateLimitDrops.Add(2)
	m.TLSHandshakes.Add(8)
	m.TLSFailures.Add(1)
	m.SyncRequests.Add(20)
	m.ForksResolved.Add(1)

	snapshot := m.Snapshot(nil)

	if snapshot.Counters.BlocksCommitted != 5 {
		t.Errorf("BlocksCommitted: got %d, want 5", snapshot.Counters.BlocksCommitted)
	}
	if snapshot.Counters.ProposalsCreated != 10 {
		t.Errorf("ProposalsCreated: got %d, want 10", snapshot.Counters.ProposalsCreated)
	}
	if snapshot.Counters.RateLimitDrops != 2 {
		t.Errorf("RateLimitDrops: got %d, want 2", snapshot.Counters.RateLimitDrops)
	}
	if snapshot.Counters.TLSHandshakes != 8 {
		t.Errorf("TLSHandshakes: got %d, want 8", snapshot.Counters.TLSHandshakes)
	}
	if snapshot.Counters.TLSFailures != 1 {
		t.Errorf("TLSFailures: got %d, want 1", snapshot.Counters.TLSFailures)
	}
	if snapshot.Counters.SyncRequests != 20 {
		t.Errorf("SyncRequests: got %d, want 20", snapshot.Counters.SyncRequests)
	}
	if snapshot.Counters.ForksResolved != 1 {
		t.Errorf("ForksResolved: got %d, want 1", snapshot.Counters.ForksResolved)
	}
}

func TestMetricsSnapshot(t *testing.T) {
	m := NewMetrics()

	// Add some data
	m.RecordMessageReceived("proposal", 1024)
	m.BlocksCommitted.Add(3)

	// Get snapshot with gauge provider
	snapshot := m.Snapshot(func() GaugeMetrics {
		return GaugeMetrics{
			ConnectedPeers:   5,
			PendingProposals: 2,
			TeamCount:        3,
			ChainLengths:     map[string]int{"team-a": 100, "team-b": 50},
		}
	})

	// Check timestamp
	if snapshot.Timestamp.IsZero() {
		t.Error("Timestamp should be set")
	}

	// Check uptime
	if snapshot.UptimeSec < 0 {
		t.Error("UptimeSec should be non-negative")
	}

	// Check system metrics
	if snapshot.System.GoVersion == "" {
		t.Error("GoVersion should be set")
	}
	if snapshot.System.NumCPU < 1 {
		t.Error("NumCPU should be at least 1")
	}
	if snapshot.System.NumGoroutine < 1 {
		t.Error("NumGoroutine should be at least 1")
	}

	// Check gauges from provider
	if snapshot.Gauges.ConnectedPeers != 5 {
		t.Errorf("ConnectedPeers: got %d, want 5", snapshot.Gauges.ConnectedPeers)
	}
	if snapshot.Gauges.TeamCount != 3 {
		t.Errorf("TeamCount: got %d, want 3", snapshot.Gauges.TeamCount)
	}

	// Check message breakdown
	if snapshot.MessagesByType.Received["proposal"] != 1 {
		t.Errorf("MessagesByType.Received[proposal]: got %d, want 1", snapshot.MessagesByType.Received["proposal"])
	}
}

func TestMetricsReset(t *testing.T) {
	m := NewMetrics()

	// Add some data
	m.RecordMessageReceived("test", 100)
	m.BlocksCommitted.Add(5)
	m.RecordError("test", "error", "peer")

	// Reset
	m.Reset()

	// Check all counters are zero
	if m.MessagesReceived.Load() != 0 {
		t.Error("MessagesReceived should be 0 after reset")
	}
	if m.BlocksCommitted.Load() != 0 {
		t.Error("BlocksCommitted should be 0 after reset")
	}

	snapshot := m.Snapshot(nil)
	if len(snapshot.RecentErrors) != 0 {
		t.Error("RecentErrors should be empty after reset")
	}
}

func TestMetricsMessageBreakdown(t *testing.T) {
	m := NewMetrics()

	// Record different message types
	m.RecordMessageReceived("proposal", 100)
	m.RecordMessageReceived("proposal", 100)
	m.RecordMessageReceived("approval", 50)
	m.RecordMessageReceived("chain_head", 30)
	m.RecordMessageSent("get_blocks", 20)
	m.RecordMessageSent("blocks", 5000)

	snapshot := m.Snapshot(nil)

	if snapshot.MessagesByType.Received["proposal"] != 2 {
		t.Errorf("Received proposal: got %d, want 2", snapshot.MessagesByType.Received["proposal"])
	}
	if snapshot.MessagesByType.Received["approval"] != 1 {
		t.Errorf("Received approval: got %d, want 1", snapshot.MessagesByType.Received["approval"])
	}
	if snapshot.MessagesByType.Sent["blocks"] != 1 {
		t.Errorf("Sent blocks: got %d, want 1", snapshot.MessagesByType.Sent["blocks"])
	}
}
