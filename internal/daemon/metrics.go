package daemon

import (
	"runtime"
	"sync"
	"sync/atomic"
	"time"
)

// Metrics collects operational metrics for observability
type Metrics struct {
	startTime time.Time

	// Counters (use atomic for lock-free updates)
	MessagesReceived atomic.Int64
	MessagesSent     atomic.Int64
	BlocksCommitted  atomic.Int64
	ProposalsCreated atomic.Int64
	ProposalsExpired atomic.Int64
	RateLimitDrops   atomic.Int64
	TLSHandshakes    atomic.Int64
	TLSFailures      atomic.Int64
	SyncRequests     atomic.Int64
	ForksResolved    atomic.Int64

	// Message counters by type
	msgCountersMu sync.RWMutex
	msgReceived   map[string]int64
	msgSent       map[string]int64

	// Bytes transferred
	BytesReceived atomic.Int64
	BytesSent     atomic.Int64

	// Error tracking (ring buffer)
	errorsMu   sync.RWMutex
	errors     []ErrorEntry
	errorIndex int

	// Latency tracking (ring buffer for last N samples)
	latencyMu         sync.RWMutex
	handshakeLatency  []time.Duration
	syncLatency       []time.Duration
	latencyIndex      int
	syncLatencyIndex  int
}

// ErrorEntry records an error event
type ErrorEntry struct {
	Time    time.Time `json:"time"`
	Type    string    `json:"type"`
	Message string    `json:"message"`
	Peer    string    `json:"peer,omitempty"`
}

// MetricsSnapshot is a point-in-time view of all metrics
type MetricsSnapshot struct {
	// Timestamps
	Timestamp time.Time `json:"timestamp"`
	Uptime    string    `json:"uptime"`
	UptimeSec float64   `json:"uptime_sec"`

	// System metrics
	System SystemMetrics `json:"system"`

	// Counters
	Counters CounterMetrics `json:"counters"`

	// Message breakdown
	MessagesByType MessageMetrics `json:"messages_by_type"`

	// Gauges (current state)
	Gauges GaugeMetrics `json:"gauges"`

	// Latencies
	Latencies LatencyMetrics `json:"latencies"`

	// Recent errors
	RecentErrors []ErrorEntry `json:"recent_errors"`
}

// SystemMetrics contains runtime/system information
type SystemMetrics struct {
	GoVersion    string `json:"go_version"`
	NumCPU       int    `json:"num_cpu"`
	NumGoroutine int    `json:"num_goroutine"`

	// Memory stats
	MemAllocMB      float64 `json:"mem_alloc_mb"`
	MemTotalAllocMB float64 `json:"mem_total_alloc_mb"`
	MemSysMB        float64 `json:"mem_sys_mb"`
	MemHeapMB       float64 `json:"mem_heap_mb"`
	MemHeapObjects  uint64  `json:"mem_heap_objects"`
	NumGC           uint32  `json:"num_gc"`
	LastGCPauseMs   float64 `json:"last_gc_pause_ms"`
}

// CounterMetrics contains cumulative counters
type CounterMetrics struct {
	MessagesReceived int64 `json:"messages_received"`
	MessagesSent     int64 `json:"messages_sent"`
	BytesReceived    int64 `json:"bytes_received"`
	BytesSent        int64 `json:"bytes_sent"`
	BlocksCommitted  int64 `json:"blocks_committed"`
	ProposalsCreated int64 `json:"proposals_created"`
	ProposalsExpired int64 `json:"proposals_expired"`
	RateLimitDrops   int64 `json:"rate_limit_drops"`
	TLSHandshakes    int64 `json:"tls_handshakes"`
	TLSFailures      int64 `json:"tls_failures"`
	SyncRequests     int64 `json:"sync_requests"`
	ForksResolved    int64 `json:"forks_resolved"`
}

// MessageMetrics breaks down messages by type
type MessageMetrics struct {
	Received map[string]int64 `json:"received"`
	Sent     map[string]int64 `json:"sent"`
}

// GaugeMetrics contains current state values
type GaugeMetrics struct {
	ConnectedPeers   int            `json:"connected_peers"`
	PendingProposals int            `json:"pending_proposals"`
	TeamCount        int            `json:"team_count"`
	ChainLengths     map[string]int `json:"chain_lengths"`
}

// LatencyMetrics contains latency statistics
type LatencyMetrics struct {
	HandshakeAvgMs float64 `json:"handshake_avg_ms"`
	HandshakeP95Ms float64 `json:"handshake_p95_ms"`
	HandshakeMaxMs float64 `json:"handshake_max_ms"`
	SyncAvgMs      float64 `json:"sync_avg_ms"`
	SyncP95Ms      float64 `json:"sync_p95_ms"`
	SyncMaxMs      float64 `json:"sync_max_ms"`
}

const (
	maxErrorEntries   = 100
	maxLatencySamples = 100
)

// NewMetrics creates a new metrics collector
func NewMetrics() *Metrics {
	return &Metrics{
		startTime:        time.Now(),
		msgReceived:      make(map[string]int64),
		msgSent:          make(map[string]int64),
		errors:           make([]ErrorEntry, maxErrorEntries),
		handshakeLatency: make([]time.Duration, maxLatencySamples),
		syncLatency:      make([]time.Duration, maxLatencySamples),
	}
}

// RecordMessageReceived records a received message
func (m *Metrics) RecordMessageReceived(msgType string, size int) {
	m.MessagesReceived.Add(1)
	m.BytesReceived.Add(int64(size))

	m.msgCountersMu.Lock()
	m.msgReceived[msgType]++
	m.msgCountersMu.Unlock()
}

// RecordMessageSent records a sent message
func (m *Metrics) RecordMessageSent(msgType string, size int) {
	m.MessagesSent.Add(1)
	m.BytesSent.Add(int64(size))

	m.msgCountersMu.Lock()
	m.msgSent[msgType]++
	m.msgCountersMu.Unlock()
}

// RecordError records an error event
func (m *Metrics) RecordError(errType, message, peer string) {
	entry := ErrorEntry{
		Time:    time.Now(),
		Type:    errType,
		Message: message,
		Peer:    peer,
	}

	m.errorsMu.Lock()
	m.errors[m.errorIndex] = entry
	m.errorIndex = (m.errorIndex + 1) % maxErrorEntries
	m.errorsMu.Unlock()
}

// RecordHandshakeLatency records a handshake duration
func (m *Metrics) RecordHandshakeLatency(d time.Duration) {
	m.latencyMu.Lock()
	m.handshakeLatency[m.latencyIndex] = d
	m.latencyIndex = (m.latencyIndex + 1) % maxLatencySamples
	m.latencyMu.Unlock()
}

// RecordSyncLatency records a sync operation duration
func (m *Metrics) RecordSyncLatency(d time.Duration) {
	m.latencyMu.Lock()
	m.syncLatency[m.syncLatencyIndex] = d
	m.syncLatencyIndex = (m.syncLatencyIndex + 1) % maxLatencySamples
	m.latencyMu.Unlock()
}

// Snapshot returns a point-in-time view of all metrics
func (m *Metrics) Snapshot(gaugeProvider func() GaugeMetrics) *MetricsSnapshot {
	now := time.Now()
	uptime := now.Sub(m.startTime)

	// Get runtime memory stats
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)

	// Calculate last GC pause
	var lastGCPause float64
	if memStats.NumGC > 0 {
		lastGCPause = float64(memStats.PauseNs[(memStats.NumGC+255)%256]) / 1e6
	}

	// Build message type maps
	m.msgCountersMu.RLock()
	received := make(map[string]int64, len(m.msgReceived))
	for k, v := range m.msgReceived {
		received[k] = v
	}
	sent := make(map[string]int64, len(m.msgSent))
	for k, v := range m.msgSent {
		sent[k] = v
	}
	m.msgCountersMu.RUnlock()

	// Get recent errors
	m.errorsMu.RLock()
	recentErrors := make([]ErrorEntry, 0, maxErrorEntries)
	for i := 0; i < maxErrorEntries; i++ {
		idx := (m.errorIndex - 1 - i + maxErrorEntries) % maxErrorEntries
		if !m.errors[idx].Time.IsZero() {
			recentErrors = append(recentErrors, m.errors[idx])
		}
	}
	m.errorsMu.RUnlock()

	// Calculate latency stats
	latencies := m.calculateLatencyStats()

	// Get gauge values from provider
	var gauges GaugeMetrics
	if gaugeProvider != nil {
		gauges = gaugeProvider()
	}

	return &MetricsSnapshot{
		Timestamp: now,
		Uptime:    uptime.Round(time.Second).String(),
		UptimeSec: uptime.Seconds(),
		System: SystemMetrics{
			GoVersion:       runtime.Version(),
			NumCPU:          runtime.NumCPU(),
			NumGoroutine:    runtime.NumGoroutine(),
			MemAllocMB:      float64(memStats.Alloc) / 1024 / 1024,
			MemTotalAllocMB: float64(memStats.TotalAlloc) / 1024 / 1024,
			MemSysMB:        float64(memStats.Sys) / 1024 / 1024,
			MemHeapMB:       float64(memStats.HeapAlloc) / 1024 / 1024,
			MemHeapObjects:  memStats.HeapObjects,
			NumGC:           memStats.NumGC,
			LastGCPauseMs:   lastGCPause,
		},
		Counters: CounterMetrics{
			MessagesReceived: m.MessagesReceived.Load(),
			MessagesSent:     m.MessagesSent.Load(),
			BytesReceived:    m.BytesReceived.Load(),
			BytesSent:        m.BytesSent.Load(),
			BlocksCommitted:  m.BlocksCommitted.Load(),
			ProposalsCreated: m.ProposalsCreated.Load(),
			ProposalsExpired: m.ProposalsExpired.Load(),
			RateLimitDrops:   m.RateLimitDrops.Load(),
			TLSHandshakes:    m.TLSHandshakes.Load(),
			TLSFailures:      m.TLSFailures.Load(),
			SyncRequests:     m.SyncRequests.Load(),
			ForksResolved:    m.ForksResolved.Load(),
		},
		MessagesByType: MessageMetrics{
			Received: received,
			Sent:     sent,
		},
		Gauges:       gauges,
		Latencies:    latencies,
		RecentErrors: recentErrors,
	}
}

// calculateLatencyStats computes latency statistics from samples
func (m *Metrics) calculateLatencyStats() LatencyMetrics {
	m.latencyMu.RLock()
	defer m.latencyMu.RUnlock()

	handshakeStats := computeLatencyStats(m.handshakeLatency)
	syncStats := computeLatencyStats(m.syncLatency)

	return LatencyMetrics{
		HandshakeAvgMs: handshakeStats.avg,
		HandshakeP95Ms: handshakeStats.p95,
		HandshakeMaxMs: handshakeStats.max,
		SyncAvgMs:      syncStats.avg,
		SyncP95Ms:      syncStats.p95,
		SyncMaxMs:      syncStats.max,
	}
}

type latencyStats struct {
	avg, p95, max float64
}

func computeLatencyStats(samples []time.Duration) latencyStats {
	// Filter non-zero samples
	var valid []time.Duration
	for _, d := range samples {
		if d > 0 {
			valid = append(valid, d)
		}
	}

	if len(valid) == 0 {
		return latencyStats{}
	}

	// Calculate average and max
	var total time.Duration
	maxVal := time.Duration(0)
	for _, d := range valid {
		total += d
		if d > maxVal {
			maxVal = d
		}
	}
	avg := total / time.Duration(len(valid))

	// Sort for percentile (simple insertion sort for small arrays)
	sorted := make([]time.Duration, len(valid))
	copy(sorted, valid)
	for i := 1; i < len(sorted); i++ {
		for j := i; j > 0 && sorted[j] < sorted[j-1]; j-- {
			sorted[j], sorted[j-1] = sorted[j-1], sorted[j]
		}
	}

	// P95
	p95Index := int(float64(len(sorted)) * 0.95)
	if p95Index >= len(sorted) {
		p95Index = len(sorted) - 1
	}

	return latencyStats{
		avg: float64(avg.Microseconds()) / 1000,
		p95: float64(sorted[p95Index].Microseconds()) / 1000,
		max: float64(maxVal.Microseconds()) / 1000,
	}
}

// Reset resets all metrics (useful for testing)
func (m *Metrics) Reset() {
	m.startTime = time.Now()
	m.MessagesReceived.Store(0)
	m.MessagesSent.Store(0)
	m.BytesReceived.Store(0)
	m.BytesSent.Store(0)
	m.BlocksCommitted.Store(0)
	m.ProposalsCreated.Store(0)
	m.ProposalsExpired.Store(0)
	m.RateLimitDrops.Store(0)
	m.TLSHandshakes.Store(0)
	m.TLSFailures.Store(0)
	m.SyncRequests.Store(0)
	m.ForksResolved.Store(0)

	m.msgCountersMu.Lock()
	m.msgReceived = make(map[string]int64)
	m.msgSent = make(map[string]int64)
	m.msgCountersMu.Unlock()

	m.errorsMu.Lock()
	m.errors = make([]ErrorEntry, maxErrorEntries)
	m.errorIndex = 0
	m.errorsMu.Unlock()

	m.latencyMu.Lock()
	m.handshakeLatency = make([]time.Duration, maxLatencySamples)
	m.syncLatency = make([]time.Duration, maxLatencySamples)
	m.latencyIndex = 0
	m.syncLatencyIndex = 0
	m.latencyMu.Unlock()
}
