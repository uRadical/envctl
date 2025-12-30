package daemon

import (
	"context"
	"log/slog"
	"sync"
	"time"
)

// LogBufferSize is the default number of log entries to keep
const LogBufferSize = 10000

// LogEntry represents a single log entry
type LogEntry struct {
	Timestamp time.Time      `json:"ts"`
	Level     string         `json:"level"`
	Message   string         `json:"msg"`
	Fields    map[string]any `json:"fields,omitempty"`
}

// LogBuffer is a thread-safe ring buffer for log entries
type LogBuffer struct {
	entries []LogEntry
	head    int
	count   int
	maxSize int
	mu      sync.RWMutex
}

// NewLogBuffer creates a buffer with the given capacity
func NewLogBuffer(maxSize int) *LogBuffer {
	return &LogBuffer{
		entries: make([]LogEntry, maxSize),
		maxSize: maxSize,
	}
}

// Add appends a log entry to the buffer
func (b *LogBuffer) Add(entry LogEntry) {
	b.mu.Lock()
	defer b.mu.Unlock()

	b.entries[b.head] = entry
	b.head = (b.head + 1) % b.maxSize
	if b.count < b.maxSize {
		b.count++
	}
}

// Query returns log entries matching the given criteria
func (b *LogBuffer) Query(opts QueryOpts) []LogEntry {
	b.mu.RLock()
	defer b.mu.RUnlock()

	results := make([]LogEntry, 0)

	// Iterate through buffer in chronological order
	start := 0
	if b.count == b.maxSize {
		start = b.head
	}

	for i := 0; i < b.count; i++ {
		idx := (start + i) % b.maxSize
		entry := b.entries[idx]

		// Apply filters
		if opts.Since != nil && entry.Timestamp.Before(*opts.Since) {
			continue
		}
		if opts.Until != nil && entry.Timestamp.After(*opts.Until) {
			continue
		}
		if opts.Level != "" && !matchesLevel(entry.Level, opts.Level) {
			continue
		}

		results = append(results, entry)

		if opts.Limit > 0 && len(results) >= opts.Limit {
			break
		}
	}

	return results
}

// Count returns the number of entries in the buffer
func (b *LogBuffer) Count() int {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.count
}

// QueryOpts specifies log query parameters
type QueryOpts struct {
	Since *time.Time
	Until *time.Time
	Level string // "DEBUG", "INFO", "WARN", "ERROR" - returns this level and above
	Limit int
}

// matchesLevel returns true if entryLevel is at or above filterLevel
func matchesLevel(entryLevel, filterLevel string) bool {
	levels := map[string]int{
		"DEBUG": 0,
		"INFO":  1,
		"WARN":  2,
		"ERROR": 3,
	}

	entryVal, ok1 := levels[entryLevel]
	filterVal, ok2 := levels[filterLevel]

	if !ok1 || !ok2 {
		return true
	}

	return entryVal >= filterVal
}

// BufferedHandler is an slog.Handler that writes to both a buffer and another handler
type BufferedHandler struct {
	buffer *LogBuffer
	next   slog.Handler
	attrs  []slog.Attr
	group  string
}

// NewBufferedHandler creates a handler that captures logs to the buffer
func NewBufferedHandler(buffer *LogBuffer, next slog.Handler) *BufferedHandler {
	return &BufferedHandler{
		buffer: buffer,
		next:   next,
	}
}

func (h *BufferedHandler) Enabled(ctx context.Context, level slog.Level) bool {
	return h.next.Enabled(ctx, level)
}

func (h *BufferedHandler) Handle(ctx context.Context, r slog.Record) error {
	// Build fields map from attributes
	fields := make(map[string]any)

	// Add pre-set attrs
	for _, attr := range h.attrs {
		fields[attr.Key] = attr.Value.Any()
	}

	// Add record attrs
	r.Attrs(func(a slog.Attr) bool {
		key := a.Key
		if h.group != "" {
			key = h.group + "." + key
		}
		fields[key] = a.Value.Any()
		return true
	})

	entry := LogEntry{
		Timestamp: r.Time,
		Level:     r.Level.String(),
		Message:   r.Message,
		Fields:    fields,
	}

	h.buffer.Add(entry)

	// Also pass to next handler (stderr, file, etc.)
	return h.next.Handle(ctx, r)
}

func (h *BufferedHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &BufferedHandler{
		buffer: h.buffer,
		next:   h.next.WithAttrs(attrs),
		attrs:  append(h.attrs, attrs...),
		group:  h.group,
	}
}

func (h *BufferedHandler) WithGroup(name string) slog.Handler {
	newGroup := name
	if h.group != "" {
		newGroup = h.group + "." + name
	}
	return &BufferedHandler{
		buffer: h.buffer,
		next:   h.next.WithGroup(name),
		attrs:  h.attrs,
		group:  newGroup,
	}
}
