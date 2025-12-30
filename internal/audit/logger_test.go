package audit

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestRingBuffer(t *testing.T) {
	rb := NewRingBuffer(5)

	// Add some events
	for i := 0; i < 3; i++ {
		rb.Add(Event{
			Timestamp: time.Now(),
			Level:     LevelInfo,
			Action:    ActionDaemonStarted,
			Message:   "test message",
		})
	}

	if rb.Count() != 3 {
		t.Errorf("expected count 3, got %d", rb.Count())
	}

	// Query all
	events := rb.Query(QueryOpts{})
	if len(events) != 3 {
		t.Errorf("expected 3 events, got %d", len(events))
	}
}

func TestRingBufferOverflow(t *testing.T) {
	rb := NewRingBuffer(3)

	// Add 5 events to overflow the buffer
	for i := 0; i < 5; i++ {
		rb.Add(Event{
			Timestamp: time.Now().Add(time.Duration(i) * time.Second),
			Level:     LevelInfo,
			Action:    "test.action",
			Message:   "message",
			Details:   map[string]any{"index": i},
		})
	}

	if rb.Count() != 3 {
		t.Errorf("expected count 3 after overflow, got %d", rb.Count())
	}

	// Should only have last 3 events
	events := rb.Query(QueryOpts{})
	if len(events) != 3 {
		t.Errorf("expected 3 events, got %d", len(events))
	}
}

func TestQueryOptsByLevel(t *testing.T) {
	rb := NewRingBuffer(10)

	rb.Add(Event{Timestamp: time.Now(), Level: LevelDebug, Message: "debug"})
	rb.Add(Event{Timestamp: time.Now(), Level: LevelInfo, Message: "info"})
	rb.Add(Event{Timestamp: time.Now(), Level: LevelWarn, Message: "warn"})
	rb.Add(Event{Timestamp: time.Now(), Level: LevelError, Message: "error"})

	// Query errors only
	errors := rb.Query(QueryOpts{Level: LevelError})
	if len(errors) != 1 {
		t.Errorf("expected 1 error event, got %d", len(errors))
	}

	// Query warn and above
	warnPlus := rb.Query(QueryOpts{Level: LevelWarn})
	if len(warnPlus) != 2 {
		t.Errorf("expected 2 warn+ events, got %d", len(warnPlus))
	}

	// Query info and above
	infoPlus := rb.Query(QueryOpts{Level: LevelInfo})
	if len(infoPlus) != 3 {
		t.Errorf("expected 3 info+ events, got %d", len(infoPlus))
	}
}

func TestQueryOptsByCategory(t *testing.T) {
	rb := NewRingBuffer(10)

	rb.Add(Event{Timestamp: time.Now(), Category: CategorySecrets, Action: ActionSecretsSent})
	rb.Add(Event{Timestamp: time.Now(), Category: CategorySecrets, Action: ActionSecretsReceived})
	rb.Add(Event{Timestamp: time.Now(), Category: CategoryPeer, Action: ActionPeerConnected})
	rb.Add(Event{Timestamp: time.Now(), Category: CategoryDaemon, Action: ActionDaemonStarted})

	secrets := rb.Query(QueryOpts{Category: CategorySecrets})
	if len(secrets) != 2 {
		t.Errorf("expected 2 secrets events, got %d", len(secrets))
	}

	peers := rb.Query(QueryOpts{Category: CategoryPeer})
	if len(peers) != 1 {
		t.Errorf("expected 1 peer event, got %d", len(peers))
	}
}

func TestQueryOptsBySearch(t *testing.T) {
	rb := NewRingBuffer(10)

	rb.Add(Event{Timestamp: time.Now(), Message: "secrets sent to alice"})
	rb.Add(Event{Timestamp: time.Now(), Message: "secrets sent to bob"})
	rb.Add(Event{Timestamp: time.Now(), Message: "connected to peer"})

	alice := rb.Query(QueryOpts{Search: "alice"})
	if len(alice) != 1 {
		t.Errorf("expected 1 alice event, got %d", len(alice))
	}

	secrets := rb.Query(QueryOpts{Search: "secrets"})
	if len(secrets) != 2 {
		t.Errorf("expected 2 secrets events, got %d", len(secrets))
	}
}

func TestQueryOptsLimit(t *testing.T) {
	rb := NewRingBuffer(100)

	for i := 0; i < 50; i++ {
		rb.Add(Event{Timestamp: time.Now(), Message: "test"})
	}

	limited := rb.Query(QueryOpts{Limit: 10})
	if len(limited) != 10 {
		t.Errorf("expected 10 events with limit, got %d", len(limited))
	}
}

func TestLoggerPersistence(t *testing.T) {
	// Create temp directory
	tmpDir := t.TempDir()
	logPath := filepath.Join(tmpDir, "audit.log")

	// Create logger and add events
	logger := NewLoggerWithPath(logPath)
	logger.Log(Event{
		Level:   LevelInfo,
		Action:  ActionDaemonStarted,
		Message: "test daemon started",
	})
	logger.Log(Event{
		Level:   LevelInfo,
		Action:  ActionProjectCreated,
		Message: "project created",
		Project: "testproj",
	})
	logger.Close()

	// Verify file was written
	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("failed to read log file: %v", err)
	}
	if len(data) == 0 {
		t.Error("log file is empty")
	}

	// Create new logger and verify events loaded from file
	logger2 := NewLoggerWithPath(logPath)
	events := logger2.Query(QueryOpts{})
	if len(events) != 2 {
		t.Errorf("expected 2 events loaded from file, got %d", len(events))
	}
	logger2.Close()
}

func TestHelperFunctions(t *testing.T) {
	tmpDir := t.TempDir()
	logPath := filepath.Join(tmpDir, "audit.log")

	// Create a fresh logger for this test
	logger := NewLoggerWithPath(logPath)
	defer logger.Close()

	// Log directly to the test logger
	logger.Log(Event{Level: LevelInfo, Action: ActionDaemonStarted, Message: "daemon started"})
	logger.Log(Event{Level: LevelWarn, Action: ActionPeerDisconnected, Message: "peer disconnected"})
	logger.Log(Event{Level: LevelError, Action: ActionDaemonError, Message: "daemon error"})

	events := logger.Query(QueryOpts{})
	if len(events) != 3 {
		t.Errorf("expected 3 events, got %d", len(events))
	}

	// Check levels
	errors := logger.Query(QueryOpts{Level: LevelError})
	if len(errors) != 1 {
		t.Errorf("expected 1 error, got %d", len(errors))
	}
}

func TestCategoryExtraction(t *testing.T) {
	rb := NewRingBuffer(10)

	// Add event with action but no category
	event := Event{
		Timestamp: time.Now(),
		Action:    ActionSecretsSent,
		Message:   "test",
	}

	// The logger should extract category from action
	tmpDir := t.TempDir()
	logPath := filepath.Join(tmpDir, "audit.log")
	logger := NewLoggerWithPath(logPath)
	logger.Log(event)

	events := logger.Query(QueryOpts{})
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}

	if events[0].Category != CategorySecrets {
		t.Errorf("expected category %q, got %q", CategorySecrets, events[0].Category)
	}

	_ = rb // silence unused warning
	logger.Close()
}
