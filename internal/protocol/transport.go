package protocol

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"
)

// Transport abstracts network transport for P2P communication
type Transport interface {
	// Dial connects to a peer at the given address
	Dial(ctx context.Context, addr PeerAddr) (net.Conn, error)

	// Accept waits for and returns the next incoming connection
	Accept(ctx context.Context) (net.Conn, error)

	// Close shuts down the transport
	Close() error

	// LocalAddrs returns addresses where this transport is listening
	LocalAddrs() []PeerAddr
}

// DirectTransport implements Transport over TCP
type DirectTransport struct {
	listener net.Listener
	port     int
	host     string
	mu       sync.RWMutex
	closed   bool
}

// NewDirectTransport creates a new TCP transport listening on the given port
func NewDirectTransport(port int) (*DirectTransport, error) {
	addr := fmt.Sprintf("0.0.0.0:%d", port)
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("listen on %s: %w", addr, err)
	}

	return &DirectTransport{
		listener: listener,
		port:     port,
		host:     "",
	}, nil
}

// Dial connects to a peer
func (t *DirectTransport) Dial(ctx context.Context, addr PeerAddr) (net.Conn, error) {
	if addr.Type != "direct" && addr.Type != "" {
		return nil, fmt.Errorf("unsupported address type: %s", addr.Type)
	}

	dialer := &net.Dialer{
		Timeout: 30 * time.Second,
	}

	conn, err := dialer.DialContext(ctx, "tcp", addr.Addr)
	if err != nil {
		return nil, fmt.Errorf("dial %s: %w", addr.Addr, err)
	}

	return conn, nil
}

// Accept waits for the next incoming connection
func (t *DirectTransport) Accept(ctx context.Context) (net.Conn, error) {
	t.mu.RLock()
	if t.closed {
		t.mu.RUnlock()
		return nil, fmt.Errorf("transport closed")
	}
	t.mu.RUnlock()

	// Set up a channel for the accept result
	type acceptResult struct {
		conn net.Conn
		err  error
	}
	resultCh := make(chan acceptResult, 1)

	go func() {
		conn, err := t.listener.Accept()
		resultCh <- acceptResult{conn, err}
	}()

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case result := <-resultCh:
		return result.conn, result.err
	}
}

// Close shuts down the transport
func (t *DirectTransport) Close() error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.closed {
		return nil
	}

	t.closed = true
	return t.listener.Close()
}

// LocalAddrs returns the local addresses
func (t *DirectTransport) LocalAddrs() []PeerAddr {
	addr := t.listener.Addr().String()
	return []PeerAddr{
		{
			Type: "direct",
			Addr: addr,
		},
	}
}

// Port returns the port this transport is listening on
func (t *DirectTransport) Port() int {
	return t.port
}

// SetHost sets the host for address advertisement
func (t *DirectTransport) SetHost(host string) {
	t.mu.Lock()
	t.host = host
	t.mu.Unlock()
}

// MultiTransport combines multiple transports
type MultiTransport struct {
	transports []Transport
	mu         sync.RWMutex
}

// NewMultiTransport creates a transport that uses multiple underlying transports
func NewMultiTransport(transports ...Transport) *MultiTransport {
	return &MultiTransport{
		transports: transports,
	}
}

// AddTransport adds a transport to the multi-transport
func (t *MultiTransport) AddTransport(transport Transport) {
	t.mu.Lock()
	t.transports = append(t.transports, transport)
	t.mu.Unlock()
}

// Dial tries each transport until one succeeds
func (t *MultiTransport) Dial(ctx context.Context, addr PeerAddr) (net.Conn, error) {
	t.mu.RLock()
	transports := t.transports
	t.mu.RUnlock()

	var lastErr error
	for _, transport := range transports {
		conn, err := transport.Dial(ctx, addr)
		if err == nil {
			return conn, nil
		}
		lastErr = err
	}

	if lastErr != nil {
		return nil, lastErr
	}
	return nil, fmt.Errorf("no transports available")
}

// Accept returns the first connection from any transport
func (t *MultiTransport) Accept(ctx context.Context) (net.Conn, error) {
	t.mu.RLock()
	transports := t.transports
	t.mu.RUnlock()

	if len(transports) == 0 {
		<-ctx.Done()
		return nil, ctx.Err()
	}

	// Simple implementation: just use first transport
	// A more sophisticated version would multiplex all transports
	return transports[0].Accept(ctx)
}

// Close closes all transports
func (t *MultiTransport) Close() error {
	t.mu.Lock()
	defer t.mu.Unlock()

	var lastErr error
	for _, transport := range t.transports {
		if err := transport.Close(); err != nil {
			lastErr = err
		}
	}
	return lastErr
}

// LocalAddrs returns addresses from all transports
func (t *MultiTransport) LocalAddrs() []PeerAddr {
	t.mu.RLock()
	defer t.mu.RUnlock()

	var addrs []PeerAddr
	for _, transport := range t.transports {
		addrs = append(addrs, transport.LocalAddrs()...)
	}
	return addrs
}
