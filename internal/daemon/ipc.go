package daemon

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync"
	"time"

	"envctl.dev/go/envctl/internal/protocol"
)

// Request represents an IPC request from a client
type Request struct {
	ID     string          `json:"id"`
	Method string          `json:"method"`
	Params json.RawMessage `json:"params,omitempty"`
}

// Response represents an IPC response to a client
type Response struct {
	ID       string          `json:"id"`
	Result   json.RawMessage `json:"result,omitempty"`
	Error    *Error          `json:"error,omitempty"`
	Progress *Progress       `json:"progress,omitempty"`
}

// Error represents an IPC error
type Error struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// Progress represents progress information for long operations
type Progress struct {
	Current int    `json:"current"`
	Total   int    `json:"total"`
	Message string `json:"message,omitempty"`
}

// Event represents a server-initiated event
type Event struct {
	Event   string          `json:"event"`
	Payload json.RawMessage `json:"payload"`
}

// Common error codes
const (
	ErrCodeInvalidRequest  = -32600
	ErrCodeMethodNotFound  = -32601
	ErrCodeInvalidParams   = -32602
	ErrCodeInternalError   = -32603
	ErrCodeNotFound        = -32000
	ErrCodePermissionDenied = -32001
	ErrCodeAlreadyExists   = -32002
)

// IPCServer handles IPC connections from CLI clients
type IPCServer struct {
	socketPath string
	listener   net.Listener
	daemon     *Daemon
	clients    map[*IPCClient]bool
	clientsMu  sync.RWMutex
	done       chan struct{}
}

// IPCClient represents a connected IPC client
type IPCClient struct {
	conn       net.Conn
	server     *IPCServer
	writer     *bufio.Writer
	writerMu   sync.Mutex
	subscribed bool
}

// NewIPCServer creates a new IPC server
func NewIPCServer(socketPath string, daemon *Daemon) *IPCServer {
	return &IPCServer{
		socketPath: socketPath,
		daemon:     daemon,
		clients:    make(map[*IPCClient]bool),
		done:       make(chan struct{}),
	}
}

// Start starts the IPC server
func (s *IPCServer) Start(ctx context.Context) error {
	// Create platform-specific listener
	listener, err := createIPCListener(s.socketPath)
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}
	s.listener = listener

	_, address := getIPCAddress(s.socketPath)
	slog.Info("IPC server listening", "address", address)

	// Accept connections
	go s.acceptLoop(ctx)

	return nil
}

// Stop stops the IPC server
func (s *IPCServer) Stop() {
	close(s.done)

	if s.listener != nil {
		s.listener.Close()
	}

	// Close all clients
	s.clientsMu.Lock()
	for client := range s.clients {
		client.conn.Close()
	}
	s.clientsMu.Unlock()

	// Platform-specific cleanup
	cleanupIPCListener(s.socketPath)
}

func (s *IPCServer) acceptLoop(ctx context.Context) {
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			select {
			case <-s.done:
				return
			default:
				slog.Error("IPC accept error", "error", err)
				continue
			}
		}

		client := &IPCClient{
			conn:   conn,
			server: s,
			writer: bufio.NewWriter(conn),
		}

		s.clientsMu.Lock()
		s.clients[client] = true
		s.clientsMu.Unlock()

		go s.handleClient(ctx, client)
	}
}

func (s *IPCServer) handleClient(ctx context.Context, client *IPCClient) {
	defer func() {
		client.conn.Close()
		s.clientsMu.Lock()
		delete(s.clients, client)
		s.clientsMu.Unlock()
	}()

	reader := bufio.NewReader(client.conn)
	decoder := json.NewDecoder(reader)

	for {
		select {
		case <-ctx.Done():
			return
		case <-s.done:
			return
		default:
		}

		var req Request
		if err := decoder.Decode(&req); err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) {
				return
			}
			slog.Debug("IPC decode error", "error", err)
			continue
		}

		// Handle request
		resp := s.handleRequest(ctx, client, &req)
		if err := client.SendResponse(resp); err != nil {
			slog.Debug("IPC send error", "error", err)
			return
		}
	}
}

func (s *IPCServer) handleRequest(ctx context.Context, client *IPCClient, req *Request) *Response {
	handler, ok := ipcHandlers[req.Method]
	if !ok {
		return &Response{
			ID: req.ID,
			Error: &Error{
				Code:    ErrCodeMethodNotFound,
				Message: fmt.Sprintf("method not found: %s", req.Method),
			},
		}
	}

	result, err := handler(ctx, s.daemon, client, req.Params)
	if err != nil {
		return &Response{
			ID: req.ID,
			Error: &Error{
				Code:    ErrCodeInternalError,
				Message: err.Error(),
			},
		}
	}

	resultJSON, err := json.Marshal(result)
	if err != nil {
		return &Response{
			ID: req.ID,
			Error: &Error{
				Code:    ErrCodeInternalError,
				Message: "failed to encode result",
			},
		}
	}

	return &Response{
		ID:     req.ID,
		Result: resultJSON,
	}
}

// SendResponse sends a response to the client
func (c *IPCClient) SendResponse(resp *Response) error {
	c.writerMu.Lock()
	defer c.writerMu.Unlock()

	encoder := json.NewEncoder(c.writer)
	if err := encoder.Encode(resp); err != nil {
		return err
	}
	return c.writer.Flush()
}

// SendEvent sends an event to the client (if subscribed)
func (c *IPCClient) SendEvent(event *Event) error {
	if !c.subscribed {
		return nil
	}

	c.writerMu.Lock()
	defer c.writerMu.Unlock()

	encoder := json.NewEncoder(c.writer)
	if err := encoder.Encode(event); err != nil {
		return err
	}
	return c.writer.Flush()
}

// BroadcastEvent broadcasts an event to all subscribed clients
func (s *IPCServer) BroadcastEvent(event *Event) {
	s.clientsMu.RLock()
	defer s.clientsMu.RUnlock()

	for client := range s.clients {
		if client.subscribed {
			go client.SendEvent(event)
		}
	}
}

// IPC handler function type
type IPCHandler func(ctx context.Context, d *Daemon, client *IPCClient, params json.RawMessage) (interface{}, error)

// ipcHandlers maps method names to handlers
var ipcHandlers = map[string]IPCHandler{
	"status":                      handleStatus,
	"metrics":                     handleMetrics,
	"peers.list":                  handlePeersList,
	"peers.add":                   handlePeersAdd,
	"peers.forget":                handlePeersForget,
	"peers.saved":                 handlePeersSaved,
	"team.create":                 handleTeamCreate,
	"team.members":                handleTeamMembers,
	"chains.reload":               handleChainsReload,
	"subscribe":                   handleSubscribe,
	"identity.broadcast_rotation": handleBroadcastKeyRotation,
	"relay.status":                handleRelayStatus,
	"relay.project_status":        handleRelayProjectStatus,
	"relay.connect":               handleRelayConnect,
	"relay.disconnect":            handleRelayDisconnect,
}

// Handler implementations

func handleStatus(ctx context.Context, d *Daemon, client *IPCClient, params json.RawMessage) (interface{}, error) {
	return d.Status(), nil
}

func handleMetrics(ctx context.Context, d *Daemon, client *IPCClient, params json.RawMessage) (interface{}, error) {
	return d.MetricsSnapshot(), nil
}

func handlePeersList(ctx context.Context, d *Daemon, client *IPCClient, params json.RawMessage) (interface{}, error) {
	return d.PeerManager().Peers(), nil
}

func handlePeersAdd(ctx context.Context, d *Daemon, client *IPCClient, params json.RawMessage) (interface{}, error) {
	var addr string
	if err := json.Unmarshal(params, &addr); err != nil {
		return nil, fmt.Errorf("invalid params: %w", err)
	}
	return nil, d.PeerManager().AddPeer(addr)
}

func handlePeersForget(ctx context.Context, d *Daemon, client *IPCClient, params json.RawMessage) (interface{}, error) {
	var req struct {
		Fingerprint string `json:"fingerprint"`
		Name        string `json:"name"`
	}
	if err := json.Unmarshal(params, &req); err != nil {
		return nil, fmt.Errorf("invalid params: %w", err)
	}

	pm := d.PeerManager()

	// Find the peer by name or fingerprint
	fingerprint := req.Fingerprint
	if fingerprint == "" && req.Name != "" {
		// Look up by name in saved peers
		for _, sp := range pm.GetSavedPeers() {
			if sp.Name == req.Name {
				fingerprint = sp.Fingerprint
				break
			}
		}
		if fingerprint == "" {
			return nil, fmt.Errorf("peer not found: %s", req.Name)
		}
	}

	if fingerprint == "" {
		return nil, fmt.Errorf("fingerprint or name is required")
	}

	// Remove from saved peers
	if err := pm.ForgetPeer(fingerprint); err != nil {
		return nil, fmt.Errorf("forget peer: %w", err)
	}

	return map[string]interface{}{
		"forgotten": true,
	}, nil
}

func handlePeersSaved(ctx context.Context, d *Daemon, client *IPCClient, params json.RawMessage) (interface{}, error) {
	return d.PeerManager().GetSavedPeers(), nil
}

func handleTeamCreate(ctx context.Context, d *Daemon, client *IPCClient, params json.RawMessage) (interface{}, error) {
	var name string
	if err := json.Unmarshal(params, &name); err != nil {
		return nil, fmt.Errorf("invalid params: %w", err)
	}
	// Team creation is handled through the chain module
	return map[string]string{"status": "not_implemented"}, nil
}

func handleTeamMembers(ctx context.Context, d *Daemon, client *IPCClient, params json.RawMessage) (interface{}, error) {
	var teamName string
	if err := json.Unmarshal(params, &teamName); err != nil {
		return nil, fmt.Errorf("invalid params: %w", err)
	}

	teamChain := d.GetChain(teamName)
	if teamChain == nil {
		return nil, fmt.Errorf("team not found: %s", teamName)
	}

	return teamChain.Members(), nil
}

func handleChainsReload(ctx context.Context, d *Daemon, client *IPCClient, params json.RawMessage) (interface{}, error) {
	if err := d.ReloadChains(); err != nil {
		return nil, fmt.Errorf("reload chains: %w", err)
	}
	return map[string]interface{}{
		"reloaded": true,
		"teams":    d.Teams(),
	}, nil
}

func handleSubscribe(ctx context.Context, d *Daemon, client *IPCClient, params json.RawMessage) (interface{}, error) {
	client.subscribed = true
	return map[string]bool{"subscribed": true}, nil
}

func handleBroadcastKeyRotation(ctx context.Context, d *Daemon, client *IPCClient, params json.RawMessage) (interface{}, error) {
	// Parse the key rotation announcement
	var ann struct {
		Type           string          `json:"type"`
		OldFingerprint string          `json:"old_fingerprint"`
		NewPublicKey   json.RawMessage `json:"new_public_key"`
		NewFingerprint string          `json:"new_fingerprint"`
		Timestamp      time.Time       `json:"timestamp"`
		Signature      []byte          `json:"signature"`
	}
	if err := json.Unmarshal(params, &ann); err != nil {
		return nil, fmt.Errorf("invalid announcement: %w", err)
	}

	// Broadcast to all connected peers
	slog.Info("broadcasting key rotation",
		"old_fingerprint", ann.OldFingerprint,
		"new_fingerprint", ann.NewFingerprint,
	)

	// Broadcast key rotation to all teams we're a member of
	for _, team := range d.Teams() {
		msg, _ := protocol.NewMessage(protocol.MsgProposal, protocol.Proposal{
			Team:  team,
			Block: params, // The key rotation announcement as the block
		})
		d.peerManager.BroadcastToTeam(team, msg)
	}

	return map[string]bool{"broadcast": true}, nil
}

func handleRelayStatus(ctx context.Context, d *Daemon, client *IPCClient, params json.RawMessage) (interface{}, error) {
	rm := d.RelayManager()
	if rm == nil {
		return map[string]interface{}{
			"enabled": false,
		}, nil
	}

	status := rm.Status()
	return map[string]interface{}{
		"enabled":  true,
		"projects": status.ProjectStatuses,
	}, nil
}

func handleRelayProjectStatus(ctx context.Context, d *Daemon, client *IPCClient, params json.RawMessage) (interface{}, error) {
	var project string
	if err := json.Unmarshal(params, &project); err != nil {
		return nil, fmt.Errorf("invalid params: %w", err)
	}

	rm := d.RelayManager()
	if rm == nil {
		return map[string]interface{}{
			"enabled": false,
		}, nil
	}

	// Get relay URL from chain
	chain := d.GetChain(project)
	if chain == nil {
		return nil, fmt.Errorf("project not found: %s", project)
	}

	return map[string]interface{}{
		"project":      project,
		"relay_url":    chain.RelayURL(),
		"allow_relay":  chain.AllowRelay(),
		"status":       rm.ProjectStatus(project),
	}, nil
}

func handleRelayConnect(ctx context.Context, d *Daemon, client *IPCClient, params json.RawMessage) (interface{}, error) {
	var project string
	if err := json.Unmarshal(params, &project); err != nil {
		return nil, fmt.Errorf("invalid params: %w", err)
	}

	if err := d.ConnectProjectRelay(project); err != nil {
		return nil, err
	}

	return map[string]interface{}{
		"connected": true,
		"project":   project,
	}, nil
}

func handleRelayDisconnect(ctx context.Context, d *Daemon, client *IPCClient, params json.RawMessage) (interface{}, error) {
	var project string
	if err := json.Unmarshal(params, &project); err != nil {
		return nil, fmt.Errorf("invalid params: %w", err)
	}

	rm := d.RelayManager()
	if rm == nil {
		return nil, fmt.Errorf("relay not enabled")
	}

	if err := rm.DisconnectProject(project); err != nil {
		return nil, err
	}

	return map[string]interface{}{
		"disconnected": true,
		"project":      project,
	}, nil
}
