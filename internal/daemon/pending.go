package daemon

import (
	"sync"
	"time"
)

// PendingSecret represents a secret that arrived while the agent was locked
type PendingSecret struct {
	Peer       string
	Project    string
	Env        string
	Payload    []byte
	ReceivedAt time.Time
}

// PendingQueue holds secrets that arrived while the agent was locked
type PendingQueue struct {
	mu      sync.Mutex
	items   []PendingSecret
	maxAge  time.Duration
	maxSize int
}

// NewPendingQueue creates a new pending queue
func NewPendingQueue(maxAge time.Duration, maxSize int) *PendingQueue {
	if maxSize <= 0 {
		maxSize = 100
	}
	return &PendingQueue{
		items:   make([]PendingSecret, 0),
		maxAge:  maxAge,
		maxSize: maxSize,
	}
}

// Add adds a pending secret to the queue
func (q *PendingQueue) Add(peer, project, env string, payload []byte) {
	q.mu.Lock()
	defer q.mu.Unlock()

	// Remove expired items first
	q.pruneExpiredLocked()

	// Check size limit
	if len(q.items) >= q.maxSize {
		// Remove oldest
		q.items = q.items[1:]
	}

	// Make a copy of the payload
	payloadCopy := make([]byte, len(payload))
	copy(payloadCopy, payload)

	q.items = append(q.items, PendingSecret{
		Peer:       peer,
		Project:    project,
		Env:        env,
		Payload:    payloadCopy,
		ReceivedAt: time.Now(),
	})
}

// Drain removes and returns all valid pending secrets
func (q *PendingQueue) Drain() []PendingSecret {
	q.mu.Lock()
	defer q.mu.Unlock()

	now := time.Now()
	valid := make([]PendingSecret, 0, len(q.items))

	for _, item := range q.items {
		if now.Sub(item.ReceivedAt) < q.maxAge {
			valid = append(valid, item)
		}
	}

	q.items = nil
	return valid
}

// Count returns the number of pending secrets
func (q *PendingQueue) Count() int {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.pruneExpiredLocked()
	return len(q.items)
}

// pruneExpiredLocked removes expired items (must hold lock)
func (q *PendingQueue) pruneExpiredLocked() {
	if q.maxAge <= 0 {
		return
	}

	now := time.Now()
	valid := make([]PendingSecret, 0, len(q.items))

	for _, item := range q.items {
		if now.Sub(item.ReceivedAt) < q.maxAge {
			valid = append(valid, item)
		}
	}

	q.items = valid
}

// Clear removes all pending secrets
func (q *PendingQueue) Clear() {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.items = nil
}

// List returns a copy of pending secrets without removing them
func (q *PendingQueue) List() []PendingSecret {
	q.mu.Lock()
	defer q.mu.Unlock()

	q.pruneExpiredLocked()

	result := make([]PendingSecret, len(q.items))
	copy(result, q.items)
	return result
}

// IncomingRequest represents an incoming environment request from a peer
type IncomingRequest struct {
	ID          string
	Team        string
	Env         string
	From        string // Peer name
	Fingerprint string // Peer fingerprint
	ReceivedAt  time.Time
}

// RequestQueue holds incoming environment requests
type RequestQueue struct {
	mu      sync.Mutex
	items   map[string]IncomingRequest // keyed by request ID
	maxAge  time.Duration
	maxSize int
}

// NewRequestQueue creates a new request queue
func NewRequestQueue(maxAge time.Duration, maxSize int) *RequestQueue {
	if maxSize <= 0 {
		maxSize = 100
	}
	return &RequestQueue{
		items:   make(map[string]IncomingRequest),
		maxAge:  maxAge,
		maxSize: maxSize,
	}
}

// Add adds an incoming request to the queue
func (q *RequestQueue) Add(id, team, env, from, fingerprint string) {
	q.mu.Lock()
	defer q.mu.Unlock()

	// Remove expired items first
	q.pruneExpiredLocked()

	// Check size limit - remove oldest if full
	if len(q.items) >= q.maxSize {
		var oldest string
		var oldestTime time.Time
		for k, v := range q.items {
			if oldest == "" || v.ReceivedAt.Before(oldestTime) {
				oldest = k
				oldestTime = v.ReceivedAt
			}
		}
		if oldest != "" {
			delete(q.items, oldest)
		}
	}

	q.items[id] = IncomingRequest{
		ID:          id,
		Team:        team,
		Env:         env,
		From:        from,
		Fingerprint: fingerprint,
		ReceivedAt:  time.Now(),
	}
}

// Get returns a request by ID
func (q *RequestQueue) Get(id string) (IncomingRequest, bool) {
	q.mu.Lock()
	defer q.mu.Unlock()

	req, ok := q.items[id]
	if !ok {
		return IncomingRequest{}, false
	}

	// Check if expired
	if time.Since(req.ReceivedAt) > q.maxAge {
		delete(q.items, id)
		return IncomingRequest{}, false
	}

	return req, true
}

// Remove removes a request by ID
func (q *RequestQueue) Remove(id string) {
	q.mu.Lock()
	defer q.mu.Unlock()
	delete(q.items, id)
}

// List returns all valid requests
func (q *RequestQueue) List() []IncomingRequest {
	q.mu.Lock()
	defer q.mu.Unlock()

	q.pruneExpiredLocked()

	result := make([]IncomingRequest, 0, len(q.items))
	for _, item := range q.items {
		result = append(result, item)
	}
	return result
}

// Count returns the number of pending requests
func (q *RequestQueue) Count() int {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.pruneExpiredLocked()
	return len(q.items)
}

// pruneExpiredLocked removes expired items (must hold lock)
func (q *RequestQueue) pruneExpiredLocked() {
	if q.maxAge <= 0 {
		return
	}

	now := time.Now()
	for id, item := range q.items {
		if now.Sub(item.ReceivedAt) > q.maxAge {
			delete(q.items, id)
		}
	}
}
