package audit

import (
	"bufio"
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"envctl.dev/go/envctl/internal/config"
)

// Logger handles audit logging with both file persistence and in-memory ring buffer
type Logger struct {
	file     *os.File
	path     string
	buffer   *RingBuffer
	mu       sync.Mutex
	identity string // Current user's fingerprint
}

// RingBuffer holds recent events in memory for fast querying
type RingBuffer struct {
	events []Event
	head   int
	count  int
	size   int
	mu     sync.RWMutex
}

// NewRingBuffer creates a new ring buffer with the given capacity
func NewRingBuffer(size int) *RingBuffer {
	return &RingBuffer{
		events: make([]Event, size),
		size:   size,
	}
}

// Add adds an event to the ring buffer
func (rb *RingBuffer) Add(event Event) {
	rb.mu.Lock()
	defer rb.mu.Unlock()

	rb.events[rb.head] = event
	rb.head = (rb.head + 1) % rb.size
	if rb.count < rb.size {
		rb.count++
	}
}

// Query returns events matching the query options
func (rb *RingBuffer) Query(opts QueryOpts) []Event {
	rb.mu.RLock()
	defer rb.mu.RUnlock()

	results := make([]Event, 0)

	// Start from oldest event
	start := 0
	if rb.count == rb.size {
		start = rb.head
	}

	// Iterate in chronological order, then reverse for newest-first
	for i := rb.count - 1; i >= 0; i-- {
		idx := (start + i) % rb.size
		event := rb.events[idx]

		if opts.matches(event) {
			results = append(results, event)
		}

		if opts.Limit > 0 && len(results) >= opts.Limit {
			break
		}
	}

	return results
}

// Count returns the number of events in the buffer
func (rb *RingBuffer) Count() int {
	rb.mu.RLock()
	defer rb.mu.RUnlock()
	return rb.count
}

// QueryOpts defines query parameters for filtering events
type QueryOpts struct {
	Since    *time.Time
	Until    *time.Time
	Level    string
	Category string
	Action   string
	Project  string
	Search   string
	Limit    int
}

func (o QueryOpts) matches(e Event) bool {
	if o.Since != nil && e.Timestamp.Before(*o.Since) {
		return false
	}
	if o.Until != nil && e.Timestamp.After(*o.Until) {
		return false
	}
	if o.Level != "" && !matchesLevel(e.Level, o.Level) {
		return false
	}
	if o.Category != "" && e.Category != o.Category {
		return false
	}
	if o.Action != "" && e.Action != o.Action {
		return false
	}
	if o.Project != "" && e.Project != o.Project {
		return false
	}
	if o.Search != "" && !containsSearch(e, o.Search) {
		return false
	}
	return true
}

func matchesLevel(eventLevel, filterLevel string) bool {
	levels := map[string]int{"DEBUG": 0, "INFO": 1, "WARN": 2, "ERROR": 3}
	el, eok := levels[eventLevel]
	fl, fok := levels[filterLevel]
	if !eok || !fok {
		return true
	}
	return el >= fl
}

func containsSearch(e Event, search string) bool {
	search = strings.ToLower(search)
	if strings.Contains(strings.ToLower(e.Message), search) {
		return true
	}
	if strings.Contains(strings.ToLower(e.Action), search) {
		return true
	}
	if strings.Contains(strings.ToLower(e.Project), search) {
		return true
	}
	if strings.Contains(strings.ToLower(e.Target), search) {
		return true
	}
	if strings.Contains(strings.ToLower(e.Peer), search) {
		return true
	}
	return false
}

var (
	defaultLogger *Logger
	once          sync.Once
)

// Default returns the default audit logger (singleton)
func Default() *Logger {
	once.Do(func() {
		defaultLogger = NewLogger()
	})
	return defaultLogger
}

// NewLogger creates a new audit logger
func NewLogger() *Logger {
	paths, err := config.GetPaths()
	if err != nil {
		slog.Error("failed to get paths for audit log", "err", err)
		return &Logger{
			buffer: NewRingBuffer(10000),
		}
	}

	return NewLoggerWithPath(paths.AuditLogFile)
}

// NewLoggerWithPath creates a new audit logger with a specific path
func NewLoggerWithPath(path string) *Logger {
	// Ensure parent directory exists
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		slog.Error("failed to create audit directory", "err", err)
	}

	file, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		slog.Error("failed to open audit log", "err", err, "path", path)
	}

	logger := &Logger{
		file:   file,
		path:   path,
		buffer: NewRingBuffer(10000),
	}

	// Load existing events into buffer
	logger.loadExistingEvents()

	return logger
}

// loadExistingEvents loads recent events from the file into the ring buffer
func (l *Logger) loadExistingEvents() {
	if l.path == "" {
		return
	}

	f, err := os.Open(l.path)
	if err != nil {
		return
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		var event Event
		if err := json.Unmarshal(scanner.Bytes(), &event); err != nil {
			continue
		}
		l.buffer.Add(event)
	}
}

// SetIdentity sets the current user's fingerprint for actor field
func (l *Logger) SetIdentity(fingerprint string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.identity = fingerprint
}

// Log records an audit event
func (l *Logger) Log(event Event) {
	l.mu.Lock()
	defer l.mu.Unlock()

	// Fill in defaults
	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now().UTC()
	}
	if event.Level == "" {
		event.Level = LevelInfo
	}
	if event.Actor == "" {
		event.Actor = l.identity
	}

	// Extract category from action if not set
	if event.Category == "" && event.Action != "" {
		if idx := strings.Index(event.Action, "."); idx > 0 {
			event.Category = event.Action[:idx]
		}
	}

	// Add to ring buffer
	l.buffer.Add(event)

	// Write to file
	if l.file != nil {
		data, err := json.Marshal(event)
		if err == nil {
			l.file.Write(data)
			l.file.Write([]byte("\n"))
		}
	}

	// Also log via slog for console/daemon output
	attrs := []any{
		"action", event.Action,
	}
	if event.Project != "" {
		attrs = append(attrs, "project", event.Project)
	}
	if event.Env != "" {
		attrs = append(attrs, "env", event.Env)
	}
	if event.Target != "" {
		attrs = append(attrs, "target", event.Target)
	}
	if event.Peer != "" {
		attrs = append(attrs, "peer", event.Peer)
	}
	if event.Error != "" {
		attrs = append(attrs, "error", event.Error)
	}

	switch event.Level {
	case LevelDebug:
		slog.Debug(event.Message, attrs...)
	case LevelInfo:
		slog.Info(event.Message, attrs...)
	case LevelWarn:
		slog.Warn(event.Message, attrs...)
	case LevelError:
		slog.Error(event.Message, attrs...)
	}
}

// Query returns events matching the criteria
func (l *Logger) Query(opts QueryOpts) []Event {
	return l.buffer.Query(opts)
}

// QueryFromFile reads events directly from the audit file (for larger time ranges)
func (l *Logger) QueryFromFile(opts QueryOpts) ([]Event, error) {
	if l.path == "" {
		return nil, nil
	}

	f, err := os.Open(l.path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer f.Close()

	var results []Event
	scanner := bufio.NewScanner(f)

	for scanner.Scan() {
		var event Event
		if err := json.Unmarshal(scanner.Bytes(), &event); err != nil {
			continue
		}

		if opts.matches(event) {
			results = append(results, event)
			if opts.Limit > 0 && len(results) >= opts.Limit {
				break
			}
		}
	}

	return results, scanner.Err()
}

// CategoryCounts returns counts of events by category
func (l *Logger) CategoryCounts() map[string]int {
	counts := make(map[string]int)
	events := l.buffer.Query(QueryOpts{})
	for _, e := range events {
		counts[e.Category]++
	}
	return counts
}

// Close closes the audit logger
func (l *Logger) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.file != nil {
		return l.file.Close()
	}
	return nil
}
