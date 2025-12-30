package audit

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// Action represents the type of audit event
type Action string

const (
	ActionSent      Action = "SENT"
	ActionReceived  Action = "RECEIVED"
	ActionRequested Action = "REQUESTED"
	ActionDenied    Action = "DENIED"
	ActionVerified  Action = "VERIFIED"
	ActionNotified  Action = "NOTIFIED"
)

// Entry represents an audit log entry
type Entry struct {
	Timestamp time.Time `json:"ts"`
	Action    Action    `json:"action"`
	Team      string    `json:"team,omitempty"`
	Env       string    `json:"env,omitempty"`
	To        string    `json:"to,omitempty"`
	ToPubkey  []byte    `json:"to_pubkey,omitempty"`
	From      string    `json:"from,omitempty"`
	FromPubkey []byte   `json:"from_pubkey,omitempty"`
	Peer      string    `json:"peer,omitempty"`
	Pubkey    []byte    `json:"pubkey,omitempty"`
	VarCount  int       `json:"vars,omitempty"`
	Redacted  int       `json:"redacted,omitempty"`
	Method    string    `json:"method,omitempty"`
}

// Log is an audit log
type Log struct {
	path string
}

// Open opens or creates an audit log
func Open(path string) (*Log, error) {
	// Ensure parent directory exists
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, fmt.Errorf("create audit directory: %w", err)
	}

	// Create file if it doesn't exist
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return nil, fmt.Errorf("open audit log: %w", err)
	}
	f.Close()

	return &Log{path: path}, nil
}

// Write writes an entry to the audit log
func (l *Log) Write(entry *Entry) error {
	if entry.Timestamp.IsZero() {
		entry.Timestamp = time.Now().UTC()
	}

	data, err := json.Marshal(entry)
	if err != nil {
		return fmt.Errorf("marshal entry: %w", err)
	}

	f, err := os.OpenFile(l.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return fmt.Errorf("open file: %w", err)
	}
	defer f.Close()

	_, err = f.Write(append(data, '\n'))
	return err
}

// Read reads all entries from the audit log
func (l *Log) Read() ([]*Entry, error) {
	f, err := os.Open(l.path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("open file: %w", err)
	}
	defer f.Close()

	entries := make([]*Entry, 0)
	scanner := bufio.NewScanner(f)

	for scanner.Scan() {
		var entry Entry
		if err := json.Unmarshal(scanner.Bytes(), &entry); err != nil {
			continue // Skip malformed entries
		}
		entries = append(entries, &entry)
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read file: %w", err)
	}

	return entries, nil
}

// ReadLast reads the last n entries
func (l *Log) ReadLast(n int) ([]*Entry, error) {
	entries, err := l.Read()
	if err != nil {
		return nil, err
	}

	if len(entries) <= n {
		return entries, nil
	}

	return entries[len(entries)-n:], nil
}

// Filter returns entries matching a filter function
func (l *Log) Filter(fn func(*Entry) bool) ([]*Entry, error) {
	entries, err := l.Read()
	if err != nil {
		return nil, err
	}

	result := make([]*Entry, 0)
	for _, e := range entries {
		if fn(e) {
			result = append(result, e)
		}
	}

	return result, nil
}

// Convenience methods for writing common entries

// LogSent logs an env share event
func (l *Log) LogSent(team, env, to string, toPubkey []byte, varCount, redacted int) error {
	return l.Write(&Entry{
		Action:   ActionSent,
		Team:     team,
		Env:      env,
		To:       to,
		ToPubkey: toPubkey,
		VarCount: varCount,
		Redacted: redacted,
	})
}

// LogReceived logs an env receive event
func (l *Log) LogReceived(team, env, from string, fromPubkey []byte, varCount int) error {
	return l.Write(&Entry{
		Action:     ActionReceived,
		Team:       team,
		Env:        env,
		From:       from,
		FromPubkey: fromPubkey,
		VarCount:   varCount,
	})
}

// LogRequested logs an env request event
func (l *Log) LogRequested(team, env string) error {
	return l.Write(&Entry{
		Action: ActionRequested,
		Team:   team,
		Env:    env,
	})
}

// LogDenied logs a denied request
func (l *Log) LogDenied(team, env, from string) error {
	return l.Write(&Entry{
		Action: ActionDenied,
		Team:   team,
		Env:    env,
		From:   from,
	})
}

// LogVerified logs a peer verification event
func (l *Log) LogVerified(peer string, pubkey []byte, method string) error {
	return l.Write(&Entry{
		Action: ActionVerified,
		Peer:   peer,
		Pubkey: pubkey,
		Method: method,
	})
}

// LogNotified logs a staleness notification
func (l *Log) LogNotified(team, env string) error {
	return l.Write(&Entry{
		Action: ActionNotified,
		Team:   team,
		Env:    env,
	})
}
