package daemon

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"envctl.dev/go/envctl/internal/chain"
	"envctl.dev/go/envctl/internal/crypto"
	"envctl.dev/go/envctl/internal/opschain"
	"envctl.dev/go/envctl/internal/protocol"
)

const (
	// DefaultP2PPort is the default port for P2P connections
	DefaultP2PPort = 7834

	// PeerConnectTimeout is how long to wait when connecting to a peer
	PeerConnectTimeout = 30 * time.Second

	// PeerPingInterval is how often to send ping messages
	PeerPingInterval = 30 * time.Second

	// PeerPingTimeout is how long to wait for a pong response
	PeerPingTimeout = 10 * time.Second

	// ChainSyncInterval is how often to sync chains with peers
	ChainSyncInterval = 60 * time.Second
)

// PeerState represents the connection state of a peer
type PeerState int

const (
	PeerStateDisconnected PeerState = iota
	PeerStateConnecting
	PeerStateHandshaking
	PeerStateConnected
)

func (s PeerState) String() string {
	switch s {
	case PeerStateDisconnected:
		return "disconnected"
	case PeerStateConnecting:
		return "connecting"
	case PeerStateHandshaking:
		return "handshaking"
	case PeerStateConnected:
		return "connected"
	default:
		return "unknown"
	}
}

// Peer represents a connected peer
type Peer struct {
	Name        string    `json:"name"`
	Fingerprint string    `json:"fingerprint"`
	Addr        string    `json:"addr"`
	Teams       []string  `json:"teams"`
	State       PeerState `json:"state"`
	LastSeen    time.Time `json:"last_seen"`
	ConnectedAt time.Time `json:"connected_at,omitempty"`

	// Internal fields
	mu          sync.RWMutex
	conn        net.Conn
	framer      *protocol.Framer
	handshake   *protocol.Handshake
	pubKey      []byte // Peer's Ed25519 public key for message verification
	ctx         context.Context
	cancel      context.CancelFunc
	sendCh      chan *protocol.Message
	sharedTeams []string // Teams we have in common

	// Replay protection
	lastSeenNonce uint64 // Last nonce received from this peer (must be monotonically increasing)
}

// PeerInfo is the public view of a peer
type PeerInfo struct {
	Name        string    `json:"name"`
	Fingerprint string    `json:"fingerprint"`
	Addr        string    `json:"addr"`
	State       string    `json:"state"`
	Connected   bool      `json:"connected"`
	LastSeen    time.Time `json:"last_seen"`
	Teams       []string  `json:"teams"`
	SharedTeams []string  `json:"shared_teams"`
}

// SavedPeer represents a peer that should be reconnected on daemon restart
type SavedPeer struct {
	Name        string    `json:"name"`
	Fingerprint string    `json:"fingerprint"`
	Addr        string    `json:"addr"`
	AddedAt     time.Time `json:"added_at"`
	LastSeen    time.Time `json:"last_seen,omitempty"`
}

// SavedPeersFile represents the peers.json file structure
type SavedPeersFile struct {
	Version int          `json:"version"`
	Peers   []*SavedPeer `json:"peers"`
}

// PendingProposal tracks a proposal waiting for approvals
type PendingProposal struct {
	Block          *chain.Block
	Team           string
	ReceivedAt     time.Time
	Approvals      map[string]protocol.Approval // fingerprint -> approval
	mu             sync.Mutex
}

// PendingJoinRequest tracks a join request waiting for chain response
type PendingJoinRequest struct {
	RequestID  string
	InviteCode string
	Name       string
	SigningPub []byte
	MLKEMPub   []byte
	CreatedAt  time.Time
}

// PeerManager handles peer connections and P2P communication
type PeerManager struct {
	daemon   *Daemon
	port     int

	mu               sync.RWMutex
	peers            map[string]*Peer            // fingerprint -> peer
	savedPeers       map[string]*SavedPeer       // fingerprint -> saved peer info for persistence
	pendingProposals map[string]*PendingProposal // block hash hex -> proposal (legacy, use proposalStore)
	proposalStore    *ProposalStore              // proposal store with TTL
	pendingJoins     map[string]*PendingJoinRequest // request ID -> pending join
	listener         net.Listener
	mdns             *MDNSService

	// TLS configuration for mutual TLS
	tlsConfig *crypto.TLSConfig

	// Signing key for message authentication
	signingKey ed25519.PrivateKey

	// Nonce counter for replay protection (atomically incremented for each outgoing message)
	nonceCounter uint64

	// Rate limiting
	rateLimiter *RateLimiter
	dropTracker *peerRateLimitTracker

	// Connection-level DoS protection (applied BEFORE parsing)
	connLimiter *ConnectionLimiter

	ctx    context.Context
	cancel context.CancelFunc
}

// NewPeerManager creates a new peer manager
func NewPeerManager(daemon *Daemon, port int) *PeerManager {
	ctx, cancel := context.WithCancel(context.Background())
	return &PeerManager{
		daemon:           daemon,
		port:             port,
		peers:            make(map[string]*Peer),
		savedPeers:       make(map[string]*SavedPeer),
		pendingProposals: make(map[string]*PendingProposal),
		proposalStore:    NewProposalStore(),
		pendingJoins:     make(map[string]*PendingJoinRequest),
		rateLimiter:      NewRateLimiter(nil),
		dropTracker:      newPeerRateLimitTracker(),
		connLimiter:      NewConnectionLimiter(nil),
		ctx:              ctx,
		cancel:           cancel,
	}
}

// StorePendingJoin stores a pending join request to be processed when chain is received
func (pm *PeerManager) StorePendingJoin(requestID, inviteCode, name string, signingPub, mlkemPub []byte) {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	pm.pendingJoins[requestID] = &PendingJoinRequest{
		RequestID:  requestID,
		InviteCode: inviteCode,
		Name:       name,
		SigningPub: signingPub,
		MLKEMPub:   mlkemPub,
		CreatedAt:  time.Now(),
	}

	slog.Debug("Stored pending join request", "request_id", requestID, "name", name)
}

// ClearPendingJoin removes a pending join request
func (pm *PeerManager) ClearPendingJoin(requestID string) {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	delete(pm.pendingJoins, requestID)
}

// Start starts the peer manager
func (pm *PeerManager) Start(ctx context.Context) error {
	// Update context
	pm.ctx, pm.cancel = context.WithCancel(ctx)

	// Start proposal store cleanup
	pm.proposalStore.Start(ctx)

	// Generate TLS configuration from identity
	if pm.daemon.identity == nil {
		return fmt.Errorf("identity not initialized")
	}
	tlsConfig, err := crypto.GenerateTLSConfig(pm.daemon.identity)
	if err != nil {
		return fmt.Errorf("generate TLS config: %w", err)
	}
	pm.tlsConfig = tlsConfig

	// Store signing key for message authentication
	pm.signingKey = pm.daemon.identity.SigningPrivateKey()

	// Start P2P listener with TLS (mutual TLS)
	addr := fmt.Sprintf("0.0.0.0:%d", pm.port)
	serverTLSConfig := pm.tlsConfig.NewServerTLSConfig()
	listener, err := tls.Listen("tcp", addr, serverTLSConfig)
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}
	pm.listener = listener

	slog.Info("P2P TLS listener started", "addr", addr, "fingerprint", pm.tlsConfig.Fingerprint[:8])

	// Accept connections
	go pm.acceptLoop()

	// Start mDNS
	pm.startMDNS()

	// Start chain sync loop (team membership chains)
	go pm.chainSyncLoop()

	// Start ops chain sync loop (environment variables)
	go pm.opsChainSyncLoop()

	return nil
}

// startMDNS starts the mDNS service
func (pm *PeerManager) startMDNS() {
	if pm.daemon == nil || pm.daemon.identity == nil {
		slog.Warn("Cannot start mDNS: no identity")
		return
	}

	hostname := getSystemHostname()
	fingerprint := pm.daemon.identity.Fingerprint()
	name := pm.daemon.identity.Name
	teams := pm.daemon.Teams()

	// Use identity name + hostname for unique mDNS instance (allows multiple daemons on same host)
	instanceName := fmt.Sprintf("%s-%s", strings.ToLower(name), hostname)
	pm.mdns = NewMDNSService(instanceName, pm.port, fingerprint, name, teams)

	// Register callback for discovered peers
	pm.mdns.OnPeerDiscovered(func(discovered *DiscoveredPeer) {
		// Connect to all discovered peers - security is enforced at the crypto layer
		// (signatures, encryption, team membership) not at the network layer.
		// This enables:
		// - Join flow: can find peers with invite codes without being in their team yet
		// - Relay: messages can route through any peer for better fault tolerance
		// - Discovery: chain requests can be broadcast to all peers
		ourTeams := pm.daemon.Teams()
		sharedTeams := findSharedTeams(ourTeams, discovered.Teams)

		slog.Debug("mDNS discovered peer",
			"fingerprint", discovered.Fingerprint[:min(8, len(discovered.Fingerprint))],
			"name", discovered.Name,
			"shared_teams", len(sharedTeams),
		)

		// Connect to the peer
		addr := fmt.Sprintf("%s:%d", discovered.Host, discovered.Port)
		go pm.connectToPeer(discovered.Fingerprint, discovered.Name, addr)
	})

	if err := pm.mdns.Start(); err != nil {
		slog.Warn("Failed to start mDNS", "error", err)
	}
}

// acceptLoop accepts incoming connections
func (pm *PeerManager) acceptLoop() {
	for {
		conn, err := pm.listener.Accept()
		if err != nil {
			select {
			case <-pm.ctx.Done():
				return
			default:
				slog.Error("P2P accept error", "error", err)
				continue
			}
		}

		// Check connection limits BEFORE any parsing (DoS protection)
		if err := pm.connLimiter.AllowConnection(conn.RemoteAddr()); err != nil {
			slog.Debug("Connection rejected by limiter",
				"remote", conn.RemoteAddr(),
				"reason", err)
			pm.daemon.metrics.RecordError("connection_limited", err.Error(), conn.RemoteAddr().String())
			conn.Close()
			continue
		}

		// Set handshake deadline BEFORE any reads
		deadline := time.Now().Add(pm.connLimiter.HandshakeTimeout())
		conn.SetDeadline(deadline)

		go pm.handleIncomingConnection(conn)
	}
}

// handleIncomingConnection handles a new incoming connection
func (pm *PeerManager) handleIncomingConnection(conn net.Conn) {
	remoteAddr := conn.RemoteAddr()
	remoteAddrStr := remoteAddr.String()
	handshakeStart := time.Now()
	handshakeSucceeded := false

	// Release connection slot on exit and record success/failure
	defer func() {
		if !handshakeSucceeded {
			pm.connLimiter.RecordFailure(remoteAddr)
			pm.connLimiter.ReleaseConnection(remoteAddr)
		}
	}()

	slog.Debug("Incoming P2P TLS connection", "addr", remoteAddrStr)

	// Cast to TLS connection to access certificate info
	tlsConn, ok := conn.(*tls.Conn)
	if !ok {
		slog.Warn("Connection is not TLS", "addr", remoteAddrStr)
		pm.daemon.metrics.TLSFailures.Add(1)
		conn.Close()
		return
	}

	// Complete TLS handshake to get peer certificate
	if err := tlsConn.Handshake(); err != nil {
		slog.Warn("TLS handshake failed", "addr", remoteAddrStr, "error", err)
		pm.daemon.metrics.TLSFailures.Add(1)
		pm.daemon.metrics.RecordError("tls_handshake", err.Error(), remoteAddrStr)
		conn.Close()
		return
	}
	pm.daemon.metrics.TLSHandshakes.Add(1)
	pm.daemon.metrics.RecordHandshakeLatency(time.Since(handshakeStart))

	// Extract fingerprint from peer's TLS certificate
	state := tlsConn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		slog.Warn("Peer did not provide TLS certificate", "addr", remoteAddrStr)
		conn.Close()
		return
	}

	// Get raw certificate bytes for fingerprint extraction
	rawCerts := make([][]byte, len(state.PeerCertificates))
	for i, cert := range state.PeerCertificates {
		rawCerts[i] = cert.Raw
	}

	fingerprint, err := crypto.ExtractFingerprintFromCert(rawCerts)
	if err != nil {
		slog.Warn("Failed to extract fingerprint from TLS cert", "addr", remoteAddrStr, "error", err)
		conn.Close()
		return
	}

	slog.Debug("TLS peer authenticated", "addr", remoteAddrStr, "fingerprint", fingerprint[:8])

	// Perform protocol handshake (for team/name exchange)
	ourHandshake := pm.createHandshake()
	theirHandshake, err := protocol.PerformHandshake(conn, ourHandshake)
	if err != nil {
		slog.Warn("Protocol handshake failed", "addr", remoteAddrStr, "error", err)
		conn.Close()
		return
	}

	// Verify that protocol handshake fingerprint matches TLS certificate
	handshakeFingerprint := crypto.PublicKeyFingerprint(theirHandshake.Pubkey)
	if handshakeFingerprint != fingerprint {
		slog.Warn("TLS certificate fingerprint mismatch with handshake",
			"tls_fingerprint", fingerprint,
			"handshake_fingerprint", handshakeFingerprint)
		conn.Close()
		return
	}

	// Check if we already have this peer
	pm.mu.Lock()
	existingPeer, exists := pm.peers[fingerprint]
	if exists && existingPeer.State == PeerStateConnected {
		pm.mu.Unlock()
		slog.Debug("Already connected to peer, closing duplicate", "fingerprint", fingerprint[:8])
		conn.Close()
		return
	}
	pm.mu.Unlock()

	// Handshake succeeded - clear deadline for normal operation
	conn.SetDeadline(time.Time{})
	handshakeSucceeded = true
	pm.connLimiter.RecordSuccess(remoteAddr)

	// Create peer and start handling
	pm.setupPeer(fingerprint, theirHandshake, conn)
}

// connectToPeer connects to a peer at the given address
func (pm *PeerManager) connectToPeer(fingerprint, name, addr string) {
	// Check if already connected
	pm.mu.RLock()
	if peer, exists := pm.peers[fingerprint]; exists {
		if peer.State == PeerStateConnected || peer.State == PeerStateConnecting {
			pm.mu.RUnlock()
			return
		}
	}
	pm.mu.RUnlock()

	// Ensure TLS config is available
	if pm.tlsConfig == nil {
		slog.Error("TLS config not initialized, cannot connect to peer")
		return
	}

	// Create connecting peer entry
	peer := &Peer{
		Name:        name,
		Fingerprint: fingerprint,
		Addr:        addr,
		State:       PeerStateConnecting,
		LastSeen:    time.Now(),
	}

	pm.mu.Lock()
	pm.peers[fingerprint] = peer
	pm.mu.Unlock()

	slog.Info("Connecting to peer via TLS", "addr", addr, "fingerprint", fingerprint[:min(8, len(fingerprint))])

	// Create TLS dialer with peer verification
	clientTLSConfig := pm.tlsConfig.NewClientTLSConfig(fingerprint)
	dialer := &tls.Dialer{
		NetDialer: &net.Dialer{Timeout: PeerConnectTimeout},
		Config:    clientTLSConfig,
	}

	conn, err := dialer.DialContext(pm.ctx, "tcp", addr)
	if err != nil {
		slog.Warn("Failed to connect to peer via TLS", "addr", addr, "error", err)
		pm.mu.Lock()
		peer.State = PeerStateDisconnected
		pm.mu.Unlock()
		return
	}

	slog.Debug("TLS connection established", "addr", addr, "fingerprint", fingerprint[:8])

	// Perform protocol handshake (for team/name exchange)
	peer.State = PeerStateHandshaking
	ourHandshake := pm.createHandshake()
	theirHandshake, err := protocol.PerformHandshake(conn, ourHandshake)
	if err != nil {
		slog.Warn("Protocol handshake failed", "addr", addr, "error", err)
		conn.Close()
		pm.mu.Lock()
		peer.State = PeerStateDisconnected
		pm.mu.Unlock()
		return
	}

	// Verify that protocol handshake fingerprint matches TLS certificate (already verified in TLS)
	handshakeFingerprint := crypto.PublicKeyFingerprint(theirHandshake.Pubkey)
	if handshakeFingerprint != fingerprint {
		slog.Warn("TLS certificate fingerprint mismatch with handshake",
			"expected", fingerprint,
			"got", handshakeFingerprint)
		conn.Close()
		pm.mu.Lock()
		peer.State = PeerStateDisconnected
		pm.mu.Unlock()
		return
	}

	pm.setupPeer(fingerprint, theirHandshake, conn)
}

// setupPeer sets up a connected peer
func (pm *PeerManager) setupPeer(fingerprint string, handshake *protocol.Handshake, conn net.Conn) {
	ctx, cancel := context.WithCancel(pm.ctx)

	// Find shared teams
	ourTeams := pm.daemon.Teams()
	sharedTeams := findSharedTeams(ourTeams, handshake.Teams)

	peer := &Peer{
		Name:        handshake.Name,
		Fingerprint: fingerprint,
		Addr:        conn.RemoteAddr().String(),
		Teams:       handshake.Teams,
		State:       PeerStateConnected,
		LastSeen:    time.Now(),
		ConnectedAt: time.Now(),
		conn:        conn,
		framer:      protocol.NewFramer(conn, conn),
		handshake:   handshake,
		pubKey:      handshake.Pubkey, // Store public key for message verification
		ctx:         ctx,
		cancel:      cancel,
		sendCh:      make(chan *protocol.Message, 100),
		sharedTeams: sharedTeams,
	}

	pm.mu.Lock()
	pm.peers[fingerprint] = peer
	pm.mu.Unlock()

	slog.Info("Peer connected",
		"fingerprint", fingerprint[:min(8, len(fingerprint))],
		"name", handshake.Name,
		"addr", conn.RemoteAddr().String(),
		"shared_teams", sharedTeams,
	)

	// Start send/receive loops
	go pm.sendLoop(peer)
	go pm.receiveLoop(peer)

	// Start ping loop
	go pm.pingLoop(peer)

	// Trigger initial chain sync for shared teams
	go pm.syncChainsWithPeer(peer)

	// Update or save peer for persistence (so it reconnects on restart)
	// Only save if we have shared teams (otherwise the peer isn't useful)
	if len(sharedTeams) > 0 {
		if err := pm.SavePeer(fingerprint, handshake.Name, conn.RemoteAddr().String()); err != nil {
			slog.Debug("Failed to save peer", "fingerprint", fingerprint[:8], "error", err)
		}
	}

	// Broadcast peer connected event
	pm.daemon.BroadcastEvent(&Event{
		Event: "peer.connected",
		Payload: mustMarshal(map[string]any{
			"fingerprint": fingerprint,
			"name":        handshake.Name,
			"addr":        conn.RemoteAddr().String(),
		}),
	})
}

// sendLoop handles outgoing messages for a peer
func (pm *PeerManager) sendLoop(peer *Peer) {
	for {
		select {
		case <-peer.ctx.Done():
			return
		case msg := <-peer.sendCh:
			// Assign nonce and sign the message before sending
			if pm.signingKey != nil {
				msg.Nonce = atomic.AddUint64(&pm.nonceCounter, 1)
				msg.Sign(pm.signingKey)
			}

			if err := peer.framer.WriteMessage(msg); err != nil {
				slog.Debug("Send failed", "peer", peer.Fingerprint[:8], "error", err)
				pm.daemon.metrics.RecordError("send", err.Error(), peer.Fingerprint[:8])
				pm.disconnectPeer(peer)
				return
			}
			// Estimate message size (actual size is internal to framer)
			pm.daemon.metrics.RecordMessageSent(string(msg.Type), 0)
		}
	}
}

// receiveLoop handles incoming messages from a peer with rate limiting
func (pm *PeerManager) receiveLoop(peer *Peer) {
	const maxDropsBeforeDisconnect = 100

	for {
		select {
		case <-peer.ctx.Done():
			return
		default:
		}

		msg, msgSize, err := peer.framer.ReadMessageWithSize()
		if err != nil {
			slog.Debug("Receive failed", "peer", peer.Fingerprint[:8], "error", err)
			pm.daemon.metrics.RecordError("receive", err.Error(), peer.Fingerprint[:8])
			pm.disconnectPeer(peer)
			return
		}

		// Verify message signature (required)
		if !msg.IsSigned() {
			slog.Warn("Received unsigned message, rejecting",
				"peer", peer.Fingerprint[:8],
				"type", msg.Type,
			)
			pm.daemon.metrics.RecordError("unsigned_message", "message not signed", peer.Fingerprint[:8])
			continue
		}

		if err := msg.VerifyFrom(peer.pubKey); err != nil {
			slog.Warn("Message signature verification failed",
				"peer", peer.Fingerprint[:8],
				"type", msg.Type,
				"error", err,
			)
			pm.daemon.metrics.RecordError("signature_verify", err.Error(), peer.Fingerprint[:8])
			continue
		}

		// Verify nonce is strictly increasing (replay protection)
		peer.mu.Lock()
		if msg.Nonce <= peer.lastSeenNonce {
			peer.mu.Unlock()
			slog.Warn("Message rejected: nonce not increasing (possible replay)",
				"peer", peer.Fingerprint[:8],
				"type", msg.Type,
				"nonce", msg.Nonce,
				"last_seen", peer.lastSeenNonce,
			)
			pm.daemon.metrics.RecordError("replay_detected", "nonce not increasing", peer.Fingerprint[:8])
			continue
		}
		peer.lastSeenNonce = msg.Nonce
		peer.mu.Unlock()

		// Record message received
		pm.daemon.metrics.RecordMessageReceived(string(msg.Type), msgSize)

		// Apply rate limiting
		if err := pm.rateLimiter.Allow(peer.Fingerprint, msg.Type, msgSize); err != nil {
			pm.daemon.metrics.RateLimitDrops.Add(1)
			drops := pm.dropTracker.recordDrop(peer.Fingerprint)
			slog.Warn("Message rate limited",
				"peer", peer.Fingerprint[:8],
				"type", msg.Type,
				"size", msgSize,
				"error", err,
				"drops", drops,
			)

			// Disconnect if too many drops
			if drops > maxDropsBeforeDisconnect {
				slog.Warn("Too many rate limit drops, disconnecting peer",
					"peer", peer.Fingerprint[:8],
					"drops", drops,
				)
				pm.disconnectPeer(peer)
				return
			}
			continue
		}

		// Reset drop counter on successful message
		pm.dropTracker.reset(peer.Fingerprint)

		peer.mu.Lock()
		peer.LastSeen = time.Now()
		peer.mu.Unlock()

		pm.handleMessage(peer, msg)
	}
}

// pingLoop sends periodic pings to keep the connection alive
func (pm *PeerManager) pingLoop(peer *Peer) {
	ticker := time.NewTicker(PeerPingInterval)
	defer ticker.Stop()

	for {
		select {
		case <-peer.ctx.Done():
			return
		case <-ticker.C:
			pm.sendPing(peer)
		}
	}
}

// sendPing sends a ping message
func (pm *PeerManager) sendPing(peer *Peer) {
	msg, _ := protocol.NewMessage(protocol.MsgPing, struct{}{})
	select {
	case peer.sendCh <- msg:
	default:
		slog.Debug("Send buffer full, skipping ping", "peer", peer.Fingerprint[:8])
	}
}

// handleMessage handles an incoming message from a peer
func (pm *PeerManager) handleMessage(peer *Peer, msg *protocol.Message) {
	slog.Debug("Received message",
		"peer", peer.Fingerprint[:8],
		"type", msg.Type,
	)

	switch msg.Type {
	case protocol.MsgPing:
		pm.handlePing(peer, msg)
	case protocol.MsgPong:
		// Just update last seen (already done)
	case protocol.MsgChainHead:
		pm.handleChainHead(peer, msg)
	case protocol.MsgGetBlocks:
		pm.handleGetBlocks(peer, msg)
	case protocol.MsgBlocks:
		pm.handleBlocks(peer, msg)
	case protocol.MsgProposal:
		pm.handleProposal(peer, msg)
	case protocol.MsgApproval:
		pm.handleApproval(peer, msg)
	case protocol.MsgRequest:
		pm.handleEnvRequest(peer, msg)
	case protocol.MsgOffer:
		pm.handleEnvOffer(peer, msg)
	case protocol.MsgPayload:
		pm.handleEnvPayload(peer, msg)
	case protocol.MsgEnvUpdated:
		pm.handleEnvUpdated(peer, msg)
	case protocol.MsgAck:
		// Acknowledgement received
	case protocol.MsgReject:
		pm.handleReject(peer, msg)
	case protocol.MsgChainRequest:
		pm.handleChainRequest(peer, msg)
	case protocol.MsgChainResponse:
		pm.handleChainResponse(peer, msg)
	case protocol.MsgJoinRequest:
		pm.handleJoinRequest(peer, msg)
	case protocol.MsgJoinApproved:
		pm.handleJoinApproved(peer, msg)
	case protocol.MsgOpsHead:
		pm.handleOpsHead(peer, msg)
	case protocol.MsgOpsGetOps:
		pm.handleOpsGetOps(peer, msg)
	case protocol.MsgOpsOps:
		pm.handleOpsOps(peer, msg)
	case protocol.MsgOpsPush:
		pm.handleOpsPush(peer, msg)
	case protocol.MsgOpsAck:
		// Acknowledgement for ops, nothing to do
	default:
		slog.Warn("Unknown message type", "peer", peer.Fingerprint[:8], "type", msg.Type)
	}
}

// handlePing responds to a ping with a pong
func (pm *PeerManager) handlePing(peer *Peer, msg *protocol.Message) {
	pong, _ := protocol.NewMessage(protocol.MsgPong, struct{}{})
	select {
	case peer.sendCh <- pong:
	default:
	}
}

// handleChainHead handles chain head announcements
func (pm *PeerManager) handleChainHead(peer *Peer, msg *protocol.Message) {
	var head protocol.ChainHead
	if err := msg.ParsePayload(&head); err != nil {
		slog.Warn("Invalid chain_head payload", "peer", peer.Fingerprint[:8], "error", err)
		return
	}

	// Check if we have this team
	c := pm.daemon.GetChain(head.Team)
	if c == nil {
		slog.Debug("Received chain_head for unknown team", "team", head.Team)
		return
	}

	// Compare with our chain
	ourHead := c.Head()
	if ourHead == nil {
		// We have no blocks, request all
		pm.requestBlocks(peer, head.Team, 0, false)
		return
	}

	if head.Index > ourHead.Index {
		// They have more blocks, request missing ones
		pm.requestBlocks(peer, head.Team, ourHead.Index+1, false)
	} else if head.Index == ourHead.Index && string(head.Hash) != string(ourHead.Hash) {
		// Same index but different hash - conflict!
		slog.Warn("Chain conflict detected",
			"team", head.Team,
			"our_hash", hex.EncodeToString(ourHead.Hash[:min(8, len(ourHead.Hash))]),
			"their_hash", hex.EncodeToString(head.Hash[:min(8, len(head.Hash))]),
		)
		// Request their full chain for conflict resolution
		pm.requestBlocks(peer, head.Team, 0, true)
	}
}

// requestBlocks requests blocks from a peer
func (pm *PeerManager) requestBlocks(peer *Peer, team string, startIndex uint64, forConflict bool) {
	pm.daemon.metrics.SyncRequests.Add(1)

	req := protocol.GetBlocks{
		Team:        team,
		StartIndex:  startIndex,
		MaxBlocks:   100,
		ForConflict: forConflict,
	}

	msg, _ := protocol.NewMessage(protocol.MsgGetBlocks, req)
	select {
	case peer.sendCh <- msg:
	default:
		slog.Warn("Failed to send get_blocks", "peer", peer.Fingerprint[:8])
	}
}

// handleGetBlocks responds to a blocks request
func (pm *PeerManager) handleGetBlocks(peer *Peer, msg *protocol.Message) {
	var req protocol.GetBlocks
	if err := msg.ParsePayload(&req); err != nil {
		slog.Warn("Invalid get_blocks payload", "peer", peer.Fingerprint[:8], "error", err)
		return
	}

	// Get chain
	c := pm.daemon.GetChain(req.Team)
	if c == nil {
		pm.sendReject(peer, "", "unknown team", protocol.RejectCodeInvalidRequest)
		return
	}

	// Get blocks
	blocks := c.Blocks(req.StartIndex)
	if len(blocks) == 0 {
		return
	}

	// Limit number of blocks
	maxBlocks := req.MaxBlocks
	if maxBlocks == 0 || maxBlocks > 100 {
		maxBlocks = 100
	}
	if len(blocks) > maxBlocks {
		blocks = blocks[:maxBlocks]
	}

	// Serialize blocks
	blocksJSON, err := json.Marshal(blocks)
	if err != nil {
		slog.Error("Failed to marshal blocks", "error", err)
		return
	}

	resp := protocol.Blocks{
		Team:        req.Team,
		Blocks:      blocksJSON,
		ForConflict: req.ForConflict,
	}

	respMsg, _ := protocol.NewMessage(protocol.MsgBlocks, resp)
	select {
	case peer.sendCh <- respMsg:
	default:
		slog.Warn("Failed to send blocks", "peer", peer.Fingerprint[:8])
	}
}

// handleBlocks handles incoming blocks
func (pm *PeerManager) handleBlocks(peer *Peer, msg *protocol.Message) {
	var resp protocol.Blocks
	if err := msg.ParsePayload(&resp); err != nil {
		slog.Warn("Invalid blocks payload", "peer", peer.Fingerprint[:8], "error", err)
		return
	}

	// Get chain
	c := pm.daemon.GetChain(resp.Team)
	if c == nil {
		slog.Warn("Received blocks for unknown team", "team", resp.Team)
		return
	}

	// Deserialize blocks
	var blocks []*chain.Block
	if err := json.Unmarshal(resp.Blocks, &blocks); err != nil {
		slog.Warn("Failed to unmarshal blocks", "error", err)
		return
	}

	// Handle conflict resolution if this was a conflict request
	if resp.ForConflict && len(blocks) > 0 {
		pm.resolveChainConflict(resp.Team, c, blocks)
		return
	}

	// Normal case: append blocks to our chain
	addedCount := 0
	for _, block := range blocks {
		if err := c.AppendBlock(block); err != nil {
			slog.Debug("Failed to append block",
				"team", resp.Team,
				"index", block.Index,
				"error", err,
			)
			continue
		}
		addedCount++
	}

	if addedCount > 0 {
		slog.Info("Chain synced",
			"team", resp.Team,
			"added", addedCount,
			"new_length", c.Len(),
		)

		// Save chain
		if err := c.Save(pm.daemon.paths.ChainFile(resp.Team)); err != nil {
			slog.Error("Failed to save chain", "team", resp.Team, "error", err)
		}

		// Broadcast chain update event
		pm.daemon.BroadcastEvent(&Event{
			Event: "chain.updated",
			Payload: mustMarshal(map[string]any{
				"team":         resp.Team,
				"blocks_added": addedCount,
				"length":       c.Len(),
			}),
		})
	}
}

// resolveChainConflict handles deterministic fork resolution
func (pm *PeerManager) resolveChainConflict(team string, ourChain *chain.Chain, theirBlocks []*chain.Block) {
	if len(theirBlocks) == 0 {
		return
	}

	// Build their chain for comparison
	theirChain, err := chain.NewFromGenesis(theirBlocks[0])
	if err != nil {
		slog.Warn("Failed to build their chain for conflict resolution", "error", err)
		return
	}

	// Add remaining blocks
	for i := 1; i < len(theirBlocks); i++ {
		if err := theirChain.AppendBlock(theirBlocks[i]); err != nil {
			slog.Warn("Failed to append block to their chain", "index", i, "error", err)
			return
		}
	}

	// Find where chains diverge
	divergeIndex := chain.FindDivergencePoint(ourChain, theirChain)

	if divergeIndex == -1 {
		slog.Debug("No divergence found, chains are compatible")

		// If their chain is longer, append new blocks
		if theirChain.Len() > ourChain.Len() {
			for i := ourChain.Len(); i < theirChain.Len(); i++ {
				if err := ourChain.AppendBlock(theirChain.Block(uint64(i))); err != nil {
					slog.Debug("Failed to append block", "index", i, "error", err)
				}
			}
			pm.saveChain(team, ourChain)
		}
		return
	}

	// Resolve the fork deterministically
	resolution, err := chain.ResolveFork(ourChain, theirChain, divergeIndex)
	if err != nil {
		slog.Error("Failed to resolve fork", "error", err)
		return
	}

	// If our chain won, nothing to do
	if len(resolution.RolledBack) == 0 {
		slog.Info("Fork resolved - our chain wins",
			"team", team,
			"reason", resolution.Reason)
		return
	}

	// Their chain won - we need to rollback and apply
	slog.Info("Fork resolved - their chain wins",
		"team", team,
		"reason", resolution.Reason,
		"rollback", len(resolution.RolledBack),
		"apply", len(resolution.Applied))

	// Rollback our blocks
	if divergeIndex > 0 {
		prevBlock := ourChain.Block(uint64(divergeIndex - 1))
		if prevBlock != nil {
			if _, err := ourChain.RollbackTo(prevBlock.Hash); err != nil {
				slog.Error("Rollback failed", "error", err)
				return
			}
		}
	}

	// Apply their blocks
	for _, block := range resolution.Applied {
		if err := ourChain.AppendBlock(block); err != nil {
			slog.Error("Apply block failed", "error", err)
			return
		}
	}

	// Save the resolved chain
	pm.saveChain(team, ourChain)

	// Record fork resolution metric
	pm.daemon.metrics.ForksResolved.Add(1)

	// Broadcast fork resolution event
	pm.daemon.BroadcastEvent(&Event{
		Event: "chain.fork_resolved",
		Payload: mustMarshal(map[string]any{
			"team":        team,
			"reason":      resolution.Reason,
			"rolled_back": len(resolution.RolledBack),
			"applied":     len(resolution.Applied),
			"new_length":  ourChain.Len(),
		}),
	})
}

// handleProposal handles a new block proposal
func (pm *PeerManager) handleProposal(peer *Peer, msg *protocol.Message) {
	var prop protocol.Proposal
	if err := msg.ParsePayload(&prop); err != nil {
		slog.Warn("Invalid proposal payload", "peer", peer.Fingerprint[:8], "error", err)
		return
	}

	// Get chain
	c := pm.daemon.GetChain(prop.Team)
	if c == nil {
		pm.sendReject(peer, "", "unknown team", protocol.RejectCodeNotMember)
		return
	}

	// Deserialize block
	var block chain.Block
	if err := json.Unmarshal(prop.Block, &block); err != nil {
		slog.Warn("Failed to unmarshal block", "error", err)
		return
	}

	// Check if block already has sufficient approvals
	if c.HasSufficientApprovals(&block) {
		// Try to append block immediately
		if err := c.AppendBlock(&block); err != nil {
			slog.Debug("Failed to append proposed block", "error", err)
		} else {
			slog.Info("Block appended with sufficient approvals",
				"team", prop.Team,
				"action", block.Action,
				"index", block.Index,
			)
			// Save chain
			pm.saveChain(prop.Team, c)
		}
	} else {
		// Store as pending proposal with TTL
		hashHex := hex.EncodeToString(block.Hash)
		proposal := &PendingProposal{
			Block:      &block,
			Team:       prop.Team,
			ReceivedAt: time.Now(),
			Approvals:  make(map[string]protocol.Approval),
		}

		if err := pm.proposalStore.Add(hashHex, proposal); err != nil {
			slog.Warn("Failed to store proposal", "error", err)
			return
		}
		pm.daemon.metrics.ProposalsCreated.Add(1)

		slog.Info("Stored pending proposal",
			"team", prop.Team,
			"action", block.Action,
			"index", block.Index,
			"approvals", len(block.Approvals),
			"required", c.RequiredApprovals(&block),
		)
	}

	// Forward proposal to other peers in this team
	pm.forwardToTeam(prop.Team, msg, peer.Fingerprint)

	// Notify via IPC
	pm.daemon.BroadcastEvent(&Event{
		Event: "chain.proposal",
		Payload: mustMarshal(map[string]any{
			"team":   prop.Team,
			"action": block.Action,
			"index":  block.Index,
		}),
	})
}

// handleApproval handles a block approval
func (pm *PeerManager) handleApproval(peer *Peer, msg *protocol.Message) {
	var approval protocol.Approval
	if err := msg.ParsePayload(&approval); err != nil {
		slog.Warn("Invalid approval payload", "peer", peer.Fingerprint[:8], "error", err)
		return
	}

	// Get chain
	c := pm.daemon.GetChain(approval.Team)
	if c == nil {
		return
	}

	// Verify the approval signature
	hashHex := hex.EncodeToString(approval.BlockHash)

	// Look up pending proposal
	pending, exists := pm.proposalStore.GetLegacy(hashHex)
	if !exists {
		slog.Debug("Received approval for unknown proposal", "hash", hashHex[:8])
		// Still forward it - another peer might have the proposal
		pm.forwardToTeam(approval.Team, msg, peer.Fingerprint)
		return
	}

	// Verify the approver is a member
	if !c.IsMember(approval.By) {
		slog.Warn("Approval from non-member", "hash", hashHex[:8])
		return
	}

	// Verify signature
	chainApproval := chain.Approval{
		By:        approval.By,
		SigAlgo:   approval.SigAlgo,
		Signature: approval.Signature,
		Timestamp: approval.Timestamp,
	}
	if !pending.Block.VerifyApproval(&chainApproval) {
		slog.Warn("Invalid approval signature", "hash", hashHex[:8])
		return
	}

	// Add approval to pending proposal
	pending.mu.Lock()
	approverKey := hex.EncodeToString(approval.By)
	if _, alreadyApproved := pending.Approvals[approverKey]; alreadyApproved {
		pending.mu.Unlock()
		return // Already have this approval
	}
	pending.Approvals[approverKey] = approval

	// Also add to block's approvals
	pending.Block.Approvals = append(pending.Block.Approvals, chainApproval)
	approvalCount := len(pending.Block.Approvals)
	pending.mu.Unlock()

	slog.Info("Added approval to pending proposal",
		"hash", hashHex[:8],
		"from", peer.Fingerprint[:8],
		"approvals", approvalCount,
		"required", c.RequiredApprovals(pending.Block),
	)

	// Check if we now have sufficient approvals
	if c.HasSufficientApprovals(pending.Block) {
		// Try to commit the block
		if err := c.AppendBlock(pending.Block); err != nil {
			slog.Error("Failed to commit block with sufficient approvals",
				"hash", hashHex[:8],
				"error", err,
			)
		} else {
			slog.Info("Block committed with consensus",
				"team", approval.Team,
				"action", pending.Block.Action,
				"index", pending.Block.Index,
				"approvals", approvalCount,
			)

			// Save chain
			pm.saveChain(approval.Team, c)

			// Remove from pending
			pm.proposalStore.Remove(hashHex)

			// Record block committed metric
			pm.daemon.metrics.BlocksCommitted.Add(1)

			// Broadcast the committed block
			pm.broadcastCommittedBlock(approval.Team, pending.Block)

			// Notify via IPC
			pm.daemon.BroadcastEvent(&Event{
				Event: "chain.block_committed",
				Payload: mustMarshal(map[string]any{
					"team":      approval.Team,
					"action":    pending.Block.Action,
					"index":     pending.Block.Index,
					"approvals": approvalCount,
				}),
			})
		}
	}

	// Forward approval to other peers
	pm.forwardToTeam(approval.Team, msg, peer.Fingerprint)
}

// saveChain persists a chain to disk
func (pm *PeerManager) saveChain(team string, c *chain.Chain) {
	chainPath := pm.daemon.paths.ChainFile(team)
	if err := c.Save(chainPath); err != nil {
		slog.Error("Failed to save chain", "team", team, "error", err)
	}
}

// broadcastCommittedBlock broadcasts a committed block to all peers
func (pm *PeerManager) broadcastCommittedBlock(team string, block *chain.Block) {
	blockData, err := json.Marshal(block)
	if err != nil {
		return
	}

	payload := protocol.Blocks{
		Team:   team,
		Blocks: blockData,
	}

	msg, err := protocol.NewMessage(protocol.MsgBlocks, payload)
	if err != nil {
		return
	}

	pm.BroadcastToTeam(team, msg)
}

// handleEnvRequest handles an environment request
func (pm *PeerManager) handleEnvRequest(peer *Peer, msg *protocol.Message) {
	var req protocol.EnvRequest
	if err := msg.ParsePayload(&req); err != nil {
		slog.Warn("Invalid env request payload", "peer", peer.Fingerprint[:8], "error", err)
		return
	}

	slog.Info("Received env request",
		"from", peer.Name,
		"team", req.Team,
		"env", req.Env,
	)

	// Check if we're a member with access
	c := pm.daemon.GetChain(req.Team)
	if c == nil {
		pm.sendReject(peer, req.ID, "unknown team", protocol.RejectCodeNotMember)
		return
	}

	// Check if requester is a member
	if !c.IsMember(req.From) {
		pm.sendReject(peer, req.ID, "not a member", protocol.RejectCodeNotMember)
		return
	}

	// Check if we have access to this env
	ourPubkey := pm.daemon.identity.SigningPublicKey()
	if !c.HasEnvAccess(ourPubkey, req.Env) {
		// We don't have this env, don't respond
		return
	}

	// Store in incoming requests queue
	pm.daemon.IncomingRequests().Add(req.ID, req.Team, req.Env, peer.Name, peer.Fingerprint)

	// Show notification
	pm.daemon.Notifier().Notify(
		"envctl - Environment Request",
		fmt.Sprintf("%s is requesting %s/%s", peer.Name, req.Team, req.Env),
	)

	// Broadcast to IPC clients so they can approve
	pm.daemon.BroadcastEvent(&Event{
		Event: "env.request",
		Payload: mustMarshal(map[string]any{
			"id":          req.ID,
			"team":        req.Team,
			"env":         req.Env,
			"from":        peer.Name,
			"fingerprint": peer.Fingerprint,
			"timestamp":   req.Timestamp,
		}),
	})
}

// handleEnvOffer handles an environment offer
func (pm *PeerManager) handleEnvOffer(peer *Peer, msg *protocol.Message) {
	var offer protocol.EnvOffer
	if err := msg.ParsePayload(&offer); err != nil {
		slog.Warn("Invalid env offer payload", "peer", peer.Fingerprint[:8], "error", err)
		return
	}

	slog.Info("Received env offer",
		"from", peer.Name,
		"team", offer.Team,
		"env", offer.Env,
		"vars", offer.VarCount,
	)

	// Broadcast to IPC clients
	pm.daemon.BroadcastEvent(&Event{
		Event: "env.offer",
		Payload: mustMarshal(map[string]any{
			"request_id":  offer.RequestID,
			"team":        offer.Team,
			"env":         offer.Env,
			"from":        peer.Name,
			"fingerprint": peer.Fingerprint,
			"var_count":   offer.VarCount,
		}),
	})
}

// handleEnvPayload handles encrypted environment data
func (pm *PeerManager) handleEnvPayload(peer *Peer, msg *protocol.Message) {
	var payload protocol.EnvPayload
	if err := msg.ParsePayload(&payload); err != nil {
		slog.Warn("Invalid env payload", "peer", peer.Fingerprint[:8], "error", err)
		return
	}

	slog.Info("Received env payload",
		"from", peer.Name,
		"team", payload.Team,
		"env", payload.Env,
		"size", len(payload.Ciphertext),
	)

	// If agent is locked, queue for later
	if !pm.daemon.Agent().IsUnlocked() {
		pm.daemon.QueuePendingSecret(peer.Name, payload.Team, payload.Env, payload.Ciphertext)
		return
	}

	// Decrypt the payload
	plaintext, err := pm.daemon.Agent().Decrypt(payload.Ciphertext)
	if err != nil {
		slog.Error("Failed to decrypt env payload", "error", err)
		return
	}

	// Store the decrypted secret
	if err := pm.daemon.storeSecret(payload.Team, payload.Env, plaintext); err != nil {
		slog.Error("Failed to store env payload",
			"team", payload.Team,
			"env", payload.Env,
			"error", err,
		)
		// Continue to broadcast even if storage fails
	} else {
		slog.Info("Stored secret from peer",
			"from", peer.Name,
			"team", payload.Team,
			"env", payload.Env,
		)
	}

	// Broadcast to IPC clients
	pm.daemon.BroadcastEvent(&Event{
		Event: "env.received",
		Payload: mustMarshal(map[string]any{
			"request_id":  payload.RequestID,
			"team":        payload.Team,
			"env":         payload.Env,
			"from":        peer.Name,
			"fingerprint": peer.Fingerprint,
			"stored":      true,
		}),
	})

	// Send ack
	ack := protocol.Ack{RequestID: payload.RequestID}
	ackMsg, _ := protocol.NewMessage(protocol.MsgAck, ack)
	select {
	case peer.sendCh <- ackMsg:
	default:
	}
}

// handleEnvUpdated handles staleness notifications
func (pm *PeerManager) handleEnvUpdated(peer *Peer, msg *protocol.Message) {
	var updated protocol.EnvUpdated
	if err := msg.ParsePayload(&updated); err != nil {
		slog.Warn("Invalid env_updated payload", "peer", peer.Fingerprint[:8], "error", err)
		return
	}

	slog.Info("Env updated notification",
		"team", updated.Team,
		"env", updated.Env,
		"by", peer.Name,
	)

	// Show notification
	pm.daemon.Notifier().Notify(
		"envctl - Environment Updated",
		fmt.Sprintf("%s/%s was updated by %s", updated.Team, updated.Env, peer.Name),
	)

	// Broadcast to IPC clients
	pm.daemon.BroadcastEvent(&Event{
		Event: "env.updated",
		Payload: mustMarshal(map[string]any{
			"team":        updated.Team,
			"env":         updated.Env,
			"updated_by":  peer.Name,
			"fingerprint": peer.Fingerprint,
			"timestamp":   updated.Timestamp,
		}),
	})
}

// handleReject handles rejection messages
func (pm *PeerManager) handleReject(peer *Peer, msg *protocol.Message) {
	var reject protocol.Reject
	if err := msg.ParsePayload(&reject); err != nil {
		return
	}

	slog.Info("Received rejection",
		"peer", peer.Name,
		"code", reject.Code,
		"reason", reject.Reason,
	)

	// Broadcast to IPC clients
	pm.daemon.BroadcastEvent(&Event{
		Event: "peer.reject",
		Payload: mustMarshal(map[string]any{
			"peer":       peer.Name,
			"request_id": reject.RequestID,
			"code":       reject.Code,
			"reason":     reject.Reason,
		}),
	})
}

// sendReject sends a rejection message
func (pm *PeerManager) sendReject(peer *Peer, requestID, reason, code string) {
	reject := protocol.Reject{
		RequestID: requestID,
		Reason:    reason,
		Code:      code,
	}
	msg, _ := protocol.NewMessage(protocol.MsgReject, reject)
	select {
	case peer.sendCh <- msg:
	default:
	}
}

// handleChainRequest handles requests for a chain by invite code
func (pm *PeerManager) handleChainRequest(peer *Peer, msg *protocol.Message) {
	var req protocol.ChainRequest
	if err := msg.ParsePayload(&req); err != nil {
		slog.Error("Failed to parse chain request", "error", err)
		return
	}

	slog.Info("Received chain request",
		"peer", peer.Name,
		"invite_code", req.InviteCode[:3]+"...",
	)

	// Search all chains for one with this invite code
	for _, teamName := range pm.daemon.Teams() {
		teamChain := pm.daemon.GetChain(teamName)
		if teamChain == nil {
			continue
		}

		// Check if this chain has the invite
		invite, _, err := teamChain.FindInvite(req.InviteCode)
		if err != nil {
			continue
		}

		// Verify the pubkey hash matches
		if invite.PubKeyHash != req.PubKeyHash {
			slog.Warn("Chain request pubkey hash mismatch",
				"peer", peer.Name,
				"team", teamName,
			)
			continue
		}

		// Found a match! Send the full chain
		blocks := teamChain.Blocks(0)
		blocksJSON, err := json.Marshal(blocks)
		if err != nil {
			slog.Error("Failed to marshal blocks", "error", err)
			continue
		}

		response := protocol.ChainResponse{
			RequestID: req.RequestID,
			Team:      teamName,
			Found:     true,
			Blocks:    blocksJSON,
		}

		respMsg, err := protocol.NewMessage(protocol.MsgChainResponse, response)
		if err != nil {
			slog.Error("Failed to create chain response", "error", err)
			return
		}

		select {
		case peer.sendCh <- respMsg:
			slog.Info("Sent chain response",
				"peer", peer.Name,
				"team", teamName,
				"blocks", len(blocks),
			)
		default:
			slog.Warn("Failed to send chain response - channel full", "peer", peer.Name)
		}
		return
	}

	// No matching chain found
	response := protocol.ChainResponse{
		RequestID: req.RequestID,
		Found:     false,
		Error:     "no chain found with this invite code",
	}

	respMsg, _ := protocol.NewMessage(protocol.MsgChainResponse, response)
	select {
	case peer.sendCh <- respMsg:
	default:
	}
}

// handleChainResponse handles chain responses for join requests
func (pm *PeerManager) handleChainResponse(peer *Peer, msg *protocol.Message) {
	var resp protocol.ChainResponse
	if err := msg.ParsePayload(&resp); err != nil {
		slog.Error("Failed to parse chain response", "error", err)
		return
	}

	if !resp.Found {
		slog.Info("Chain not found by peer",
			"peer", peer.Name,
			"error", resp.Error,
		)
		return
	}

	slog.Info("Received chain response",
		"peer", peer.Name,
		"team", resp.Team,
	)

	// Parse the blocks
	var blocks []*chain.Block
	if err := json.Unmarshal(resp.Blocks, &blocks); err != nil {
		slog.Error("Failed to parse blocks from chain response", "error", err)
		return
	}

	if len(blocks) == 0 {
		slog.Error("Chain response has no blocks")
		return
	}

	// Create a new chain from the blocks
	newChain, err := chain.FromBlocks(blocks)
	if err != nil {
		slog.Error("Failed to create chain from blocks", "error", err)
		return
	}

	// Verify the chain
	if err := newChain.Verify(); err != nil {
		slog.Error("Chain verification failed", "error", err)
		return
	}

	// Save the chain
	chainPath := pm.daemon.paths.ChainFile(resp.Team)
	if err := newChain.Save(chainPath); err != nil {
		slog.Error("Failed to save chain", "error", err)
		return
	}

	// Add to daemon's chains
	pm.daemon.mu.Lock()
	pm.daemon.chains[resp.Team] = newChain
	pm.daemon.mu.Unlock()

	slog.Info("Saved new chain from peer",
		"peer", peer.Name,
		"team", resp.Team,
		"blocks", len(blocks),
	)

	// Check if we have a pending join request for this request ID
	pm.mu.RLock()
	pendingJoin := pm.pendingJoins[resp.RequestID]
	pm.mu.RUnlock()

	if pendingJoin != nil {
		// We received the chain in response to a join request - now send the actual join request
		slog.Info("Sending join request after receiving chain",
			"team", resp.Team,
			"peer", peer.Name,
		)

		joinReq := protocol.JoinRequest{
			RequestID:  resp.RequestID,
			Team:       resp.Team,
			InviteCode: pendingJoin.InviteCode,
			Name:       pendingJoin.Name,
			SigningPub: pendingJoin.SigningPub,
			MLKEMPub:   pendingJoin.MLKEMPub,
		}

		msg, err := protocol.NewMessage(protocol.MsgJoinRequest, joinReq)
		if err != nil {
			slog.Error("Failed to create join request message", "error", err)
		} else {
			select {
			case peer.sendCh <- msg:
				slog.Info("Sent join request to peer", "peer", peer.Name, "team", resp.Team)
			default:
				slog.Warn("Failed to send join request - channel full")
			}
		}
	}

	// Broadcast event
	pm.daemon.BroadcastEvent(&Event{
		Event: "chain.received",
		Payload: mustMarshal(map[string]any{
			"team":   resp.Team,
			"blocks": len(blocks),
			"from":   peer.Name,
		}),
	})
}

// handleJoinRequest handles a request from a peer to join a team
// This is called when Bob (who has an invite) asks Alice (a team member) to add him
func (pm *PeerManager) handleJoinRequest(peer *Peer, msg *protocol.Message) {
	var req protocol.JoinRequest
	if err := msg.ParsePayload(&req); err != nil {
		slog.Error("Failed to parse join request", "error", err)
		return
	}

	slog.Info("Received join request",
		"peer", peer.Name,
		"team", req.Team,
		"invite_code", req.InviteCode[:min(3, len(req.InviteCode))]+"...",
	)

	// Get our chain for this team
	teamChain := pm.daemon.GetChain(req.Team)
	if teamChain == nil {
		slog.Warn("Join request for unknown team", "team", req.Team)
		pm.sendJoinRejection(peer, req.RequestID, "team not found")
		return
	}

	// Check if we're a member who can add people
	if !teamChain.IsMember(pm.daemon.identity.SigningPublicKey()) {
		slog.Warn("Cannot process join request - not a team member")
		pm.sendJoinRejection(peer, req.RequestID, "not authorized to add members")
		return
	}

	// Validate the invite
	invite, err := teamChain.ValidateInvite(req.InviteCode, req.SigningPub)
	if err != nil {
		slog.Warn("Invalid invite in join request", "error", err)
		pm.sendJoinRejection(peer, req.RequestID, err.Error())
		return
	}

	// Create the member to add
	member := chain.Member{
		Name:         req.Name,
		SigningPub:   req.SigningPub,
		MLKEMPub:     req.MLKEMPub,
		Role:         invite.Role,
		Environments: invite.Environments,
		JoinedAt:     time.Now().UTC(),
		InviteCode:   req.InviteCode,
	}

	// Create the add_member block (signed by US - the admin/member)
	head := teamChain.Head()
	if head == nil {
		pm.sendJoinRejection(peer, req.RequestID, "chain has no head")
		return
	}

	block, err := chain.NewBlock(head, chain.ActionAddMember, member, pm.daemon.identity)
	if err != nil {
		slog.Error("Failed to create add_member block", "error", err)
		pm.sendJoinRejection(peer, req.RequestID, "failed to create block")
		return
	}

	// Check if we can commit directly without approval
	// This is allowed when:
	// - SoloMode is enabled in policy, OR
	// - There's only 1 member (the founder) - no one else to approve
	policy := teamChain.Policy()
	memberCount := len(teamChain.Members())
	canCommitDirectly := (policy != nil && policy.SoloMode) || memberCount == 1

	if canCommitDirectly {
		if err := teamChain.AppendBlock(block); err != nil {
			slog.Error("Failed to append add_member block", "error", err)
			pm.sendJoinRejection(peer, req.RequestID, err.Error())
			return
		}

		// Save the chain
		chainPath := pm.daemon.paths.ChainFile(req.Team)
		if err := teamChain.Save(chainPath); err != nil {
			slog.Error("Failed to save chain after adding member", "error", err)
			pm.sendJoinRejection(peer, req.RequestID, "failed to save chain")
			return
		}

		slog.Info("Added new member to team",
			"team", req.Team,
			"member", req.Name,
			"role", invite.Role,
		)

		// Send the approval with the block
		blockJSON, _ := json.Marshal(block)
		approval := protocol.JoinApproved{
			RequestID: req.RequestID,
			Team:      req.Team,
			Block:     blockJSON,
		}

		respMsg, err := protocol.NewMessage(protocol.MsgJoinApproved, approval)
		if err != nil {
			slog.Error("Failed to create join approval message", "error", err)
			return
		}

		select {
		case peer.sendCh <- respMsg:
			slog.Info("Sent join approval", "peer", peer.Name, "team", req.Team)
		default:
			slog.Warn("Failed to send join approval - channel full")
		}
		return
	}

	// For non-solo mode, create a proposal (not implemented yet)
	pm.sendJoinRejection(peer, req.RequestID, "approval required - not implemented")
}

// sendJoinRejection sends a rejection message for a join request
func (pm *PeerManager) sendJoinRejection(peer *Peer, requestID, reason string) {
	rejection := protocol.Reject{
		RequestID: requestID,
		Reason:    reason,
	}

	msg, err := protocol.NewMessage(protocol.MsgReject, rejection)
	if err != nil {
		return
	}

	select {
	case peer.sendCh <- msg:
	default:
	}
}

// handleJoinApproved handles approval of our join request
func (pm *PeerManager) handleJoinApproved(peer *Peer, msg *protocol.Message) {
	var approval protocol.JoinApproved
	if err := msg.ParsePayload(&approval); err != nil {
		slog.Error("Failed to parse join approval", "error", err)
		return
	}

	slog.Info("Received join approval",
		"peer", peer.Name,
		"team", approval.Team,
	)

	// Parse the block
	var block chain.Block
	if err := json.Unmarshal(approval.Block, &block); err != nil {
		slog.Error("Failed to parse block from join approval", "error", err)
		return
	}

	// Get our chain
	teamChain := pm.daemon.GetChain(approval.Team)
	if teamChain == nil {
		slog.Error("Received join approval for unknown team", "team", approval.Team)
		return
	}

	// Append the block to our chain
	if err := teamChain.AppendBlock(&block); err != nil {
		slog.Error("Failed to append join block", "error", err)
		return
	}

	// Save the chain
	chainPath := pm.daemon.paths.ChainFile(approval.Team)
	if err := teamChain.Save(chainPath); err != nil {
		slog.Error("Failed to save chain after join", "error", err)
		return
	}

	slog.Info("Successfully joined team",
		"team", approval.Team,
		"blocks", teamChain.Len(),
	)

	// Broadcast event
	pm.daemon.BroadcastEvent(&Event{
		Event: "team.joined",
		Payload: mustMarshal(map[string]any{
			"team":      approval.Team,
			"from_peer": peer.Name,
		}),
	})
}

// forwardToTeam forwards a message to all peers in a team except the sender
func (pm *PeerManager) forwardToTeam(team string, msg *protocol.Message, exceptFingerprint string) {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	for fp, peer := range pm.peers {
		if fp == exceptFingerprint {
			continue
		}
		if peer.State != PeerStateConnected {
			continue
		}

		// Check if peer is in this team
		inTeam := false
		for _, t := range peer.sharedTeams {
			if t == team {
				inTeam = true
				break
			}
		}

		if inTeam {
			select {
			case peer.sendCh <- msg:
			default:
			}
		}
	}
}

// syncChainsWithPeer syncs all shared chains with a peer
func (pm *PeerManager) syncChainsWithPeer(peer *Peer) {
	for _, team := range peer.sharedTeams {
		c := pm.daemon.GetChain(team)
		if c == nil {
			continue
		}

		head := c.Head()
		if head == nil {
			continue
		}

		// Send our chain head
		chainHead := protocol.ChainHead{
			Team:  team,
			Index: head.Index,
			Hash:  head.Hash,
		}

		msg, _ := protocol.NewMessage(protocol.MsgChainHead, chainHead)
		select {
		case peer.sendCh <- msg:
		default:
		}
	}
}

// chainSyncLoop periodically syncs chains with all peers
func (pm *PeerManager) chainSyncLoop() {
	ticker := time.NewTicker(ChainSyncInterval)
	defer ticker.Stop()

	for {
		select {
		case <-pm.ctx.Done():
			return
		case <-ticker.C:
			pm.mu.RLock()
			for _, peer := range pm.peers {
				if peer.State == PeerStateConnected {
					go pm.syncChainsWithPeer(peer)
				}
			}
			pm.mu.RUnlock()
		}
	}
}

// opsChainSyncLoop periodically syncs ops chains (environment variables) with all peers
func (pm *PeerManager) opsChainSyncLoop() {
	// Use a slightly faster interval for ops chains since they change more frequently
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-pm.ctx.Done():
			return
		case <-ticker.C:
			pm.broadcastOpsHeads()
		}
	}
}

// broadcastOpsHeads broadcasts our ops chain heads to all connected peers
func (pm *PeerManager) broadcastOpsHeads() {
	mgr := pm.daemon.GetOpsChainManager()
	if mgr == nil {
		return
	}

	// Get all projects we have ops chains for
	projects, err := mgr.ListProjects()
	if err != nil {
		slog.Debug("Failed to list ops chain projects", "error", err)
		return
	}

	for _, project := range projects {
		envs, err := mgr.ListEnvironments(project)
		if err != nil {
			continue
		}

		for _, env := range envs {
			chain, err := mgr.LoadChain(project, env)
			if err != nil {
				continue
			}

			head := chain.Head()
			if head == nil {
				continue
			}

			// Create ops head message
			opsHead := protocol.OpsHead{
				Project:     project,
				Environment: env,
				Seq:         head.Seq,
				Hash:        head.Hash(),
			}

			msg, err := protocol.NewMessage(protocol.MsgOpsHead, opsHead)
			if err != nil {
				continue
			}

			// Send to all connected peers
			pm.mu.RLock()
			for _, peer := range pm.peers {
				if peer.State == PeerStateConnected {
					select {
					case peer.sendCh <- msg:
					default:
						// Channel full, skip this peer
					}
				}
			}
			pm.mu.RUnlock()
		}
	}
}

// disconnectPeer handles peer disconnection
func (pm *PeerManager) disconnectPeer(peer *Peer) {
	peer.mu.Lock()
	if peer.State == PeerStateDisconnected {
		peer.mu.Unlock()
		return
	}
	peer.State = PeerStateDisconnected
	peer.cancel()
	connAddr := peer.conn.RemoteAddr()
	if peer.conn != nil {
		peer.conn.Close()
	}
	peer.mu.Unlock()

	// Cleanup rate limiting state
	pm.rateLimiter.RemovePeer(peer.Fingerprint)
	pm.dropTracker.remove(peer.Fingerprint)

	// Release connection slot
	if connAddr != nil {
		pm.connLimiter.ReleaseConnection(connAddr)
	}

	slog.Info("Peer disconnected",
		"fingerprint", peer.Fingerprint[:min(8, len(peer.Fingerprint))],
		"name", peer.Name,
	)

	// Broadcast disconnection event
	pm.daemon.BroadcastEvent(&Event{
		Event: "peer.disconnected",
		Payload: mustMarshal(map[string]any{
			"fingerprint": peer.Fingerprint,
			"name":        peer.Name,
		}),
	})
}

// createHandshake creates our handshake message
func (pm *PeerManager) createHandshake() *protocol.Handshake {
	return protocol.NewHandshakeFromIdentity(pm.daemon.identity, pm.daemon.Teams())
}

// Stop stops the peer manager
func (pm *PeerManager) Stop() {
	pm.cancel()

	// Stop proposal store cleanup
	if pm.proposalStore != nil {
		pm.proposalStore.Stop()
	}

	// Stop mDNS
	if pm.mdns != nil {
		pm.mdns.Stop()
	}

	// Close listener
	if pm.listener != nil {
		pm.listener.Close()
	}

	// Close all peer connections
	pm.mu.Lock()
	for _, peer := range pm.peers {
		peer.cancel()
		if peer.conn != nil {
			peer.conn.Close()
		}
	}
	pm.mu.Unlock()
}

// Peers returns all peers
func (pm *PeerManager) Peers() []*PeerInfo {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	peers := make([]*PeerInfo, 0, len(pm.peers))
	for _, p := range pm.peers {
		p.mu.RLock()
		peers = append(peers, &PeerInfo{
			Name:        p.Name,
			Fingerprint: p.Fingerprint,
			Addr:        p.Addr,
			State:       p.State.String(),
			Connected:   p.State == PeerStateConnected,
			LastSeen:    p.LastSeen,
			Teams:       p.Teams,
			SharedTeams: p.sharedTeams,
		})
		p.mu.RUnlock()
	}
	return peers
}

// PeerCount returns the number of connected peers
func (pm *PeerManager) PeerCount() int {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	count := 0
	for _, p := range pm.peers {
		if p.State == PeerStateConnected {
			count++
		}
	}
	return count
}

// ListenAddr returns the P2P listener address
func (pm *PeerManager) ListenAddr() string {
	if pm.listener != nil {
		return pm.listener.Addr().String()
	}
	return ""
}

// AddPeer adds a manual peer by address
func (pm *PeerManager) AddPeer(addr string) error {
	// Generate a temporary fingerprint until we handshake
	tempFP := fmt.Sprintf("pending-%s", addr)
	go pm.connectToPeer(tempFP, "unknown", addr)
	return nil
}

// GetPeer returns a peer by fingerprint
func (pm *PeerManager) GetPeer(fingerprint string) *Peer {
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	return pm.peers[fingerprint]
}

// GetPeerByName returns a peer by name
func (pm *PeerManager) GetPeerByName(name string) *Peer {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	for _, peer := range pm.peers {
		if peer.Name == name {
			return peer
		}
	}
	return nil
}

// IsConnected checks if a peer is currently connected by hex pubkey
func (pm *PeerManager) IsConnected(pubkeyHex string) bool {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	// Match by fingerprint prefix (first 16 chars)
	prefix := pubkeyHex
	if len(prefix) > 16 {
		prefix = prefix[:16]
	}

	for _, peer := range pm.peers {
		if peer.State == PeerStateConnected && peer.Fingerprint == prefix {
			return true
		}
	}
	return false
}

// LastSeen returns when a peer was last seen (zero time if never)
func (pm *PeerManager) LastSeen(pubkeyHex string) time.Time {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	// Match by fingerprint prefix (first 16 chars)
	prefix := pubkeyHex
	if len(prefix) > 16 {
		prefix = prefix[:16]
	}

	for _, peer := range pm.peers {
		if peer.Fingerprint == prefix {
			return peer.LastSeen
		}
	}
	return time.Time{}
}

// BroadcastToTeam broadcasts a message to all connected peers in a team.
// For offline peers, if relay is configured for the project, the message
// is sent via the relay for later delivery.
func (pm *PeerManager) BroadcastToTeam(team string, msg *protocol.Message) {
	pm.mu.RLock()
	connectedFingerprints := make(map[string]bool)
	for _, peer := range pm.peers {
		if peer.State != PeerStateConnected {
			continue
		}

		for _, t := range peer.sharedTeams {
			if t == team {
				connectedFingerprints[peer.Fingerprint] = true
				select {
				case peer.sendCh <- msg:
				default:
				}
				break
			}
		}
	}
	pm.mu.RUnlock()

	// Send via relay to offline team members
	pm.sendToOfflineMembers(team, msg, connectedFingerprints)
}

// sendToOfflineMembers sends a message via relay to offline team members
func (pm *PeerManager) sendToOfflineMembers(team string, msg *protocol.Message, connectedFingerprints map[string]bool) {
	// Check if relay is configured for this project
	rm := pm.daemon.RelayManager()
	if rm == nil || !rm.IsProjectConnected(team) {
		return
	}

	// Get the chain to find all members
	c := pm.daemon.GetChain(team)
	if c == nil {
		return
	}

	// Check if relay is enabled for this project
	if !c.AllowRelay() || c.RelayURL() == "" {
		return
	}

	myFingerprint := pm.daemon.identity.Fingerprint()
	members := c.Members()

	for _, member := range members {
		fingerprint := crypto.PublicKeyFingerprint(member.SigningPub)

		// Skip ourselves
		if fingerprint == myFingerprint {
			continue
		}

		// Skip if already sent via P2P
		if connectedFingerprints[fingerprint] {
			continue
		}

		// Send via relay
		pubIdentity := &crypto.PublicIdentity{
			Name:       member.Name,
			MLKEMPub:   member.MLKEMPub,
			SigningPub: member.SigningPub,
		}

		go func(fp string, pub *crypto.PublicIdentity) {
			if err := rm.SendToOfflinePeer(team, fp, pub, msg); err != nil {
				slog.Debug("failed to send via relay",
					"team", team,
					"to", fp[:8],
					"error", err,
				)
			}
		}(fingerprint, pubIdentity)
	}
}

// HandleRelayMessage processes a message received via the relay.
// These messages are handled similarly to P2P messages but without a peer connection.
func (pm *PeerManager) HandleRelayMessage(project string, msg *protocol.Message) {
	slog.Debug("Processing relay message",
		"project", project,
		"type", msg.Type,
	)

	// For relay messages, we don't have a peer connection
	// Handle only message types that make sense without a connection
	switch msg.Type {
	case protocol.MsgChainHead:
		// Can't request blocks via relay (need bidirectional connection)
		// Just log for now
		slog.Debug("Received chain_head via relay, cannot request blocks without peer connection")

	case protocol.MsgBlocks:
		// Process blocks received via relay
		pm.handleBlocksFromRelay(project, msg)

	case protocol.MsgProposal:
		pm.handleProposalFromRelay(project, msg)

	case protocol.MsgApproval:
		pm.handleApprovalFromRelay(project, msg)

	case protocol.MsgOpsPush:
		pm.handleOpsPushFromRelay(project, msg)

	default:
		slog.Debug("Ignoring relay message type", "type", msg.Type)
	}
}

// handleBlocksFromRelay processes blocks received via relay
func (pm *PeerManager) handleBlocksFromRelay(project string, msg *protocol.Message) {
	var resp protocol.Blocks
	if err := msg.ParsePayload(&resp); err != nil {
		slog.Warn("Invalid blocks payload from relay", "error", err)
		return
	}

	c := pm.daemon.GetChain(resp.Team)
	if c == nil {
		slog.Debug("Received blocks for unknown team from relay", "team", resp.Team)
		return
	}

	var blocks []*chain.Block
	if err := json.Unmarshal(resp.Blocks, &blocks); err != nil {
		slog.Warn("Failed to unmarshal blocks from relay", "error", err)
		return
	}

	for _, block := range blocks {
		if err := c.AppendBlock(block); err != nil {
			slog.Debug("Failed to append block from relay", "error", err)
			continue
		}
		slog.Info("Appended block from relay",
			"team", resp.Team,
			"action", block.Action,
			"index", block.Index,
		)
	}

	// Save chain
	if err := c.Save(pm.daemon.paths.ChainFile(resp.Team)); err != nil {
		slog.Error("Failed to save chain", "team", resp.Team, "error", err)
	}
}

// handleProposalFromRelay processes a proposal received via relay
func (pm *PeerManager) handleProposalFromRelay(project string, msg *protocol.Message) {
	var proposal protocol.Proposal
	if err := msg.ParsePayload(&proposal); err != nil {
		slog.Warn("Invalid proposal payload from relay", "error", err)
		return
	}

	// Parse the block
	var block chain.Block
	if err := json.Unmarshal(proposal.Block, &block); err != nil {
		slog.Warn("Failed to parse proposal block from relay", "error", err)
		return
	}

	c := pm.daemon.GetChain(proposal.Team)
	if c == nil {
		slog.Debug("Proposal for unknown team from relay", "team", proposal.Team)
		return
	}

	// Store as pending proposal (same logic as P2P)
	hashHex := hex.EncodeToString(block.Hash)

	// Create pending proposal and add to store
	pending := &PendingProposal{
		Block:      &block,
		Team:       proposal.Team,
		ReceivedAt: time.Now(),
		Approvals:  make(map[string]protocol.Approval),
	}
	pm.proposalStore.Add(hashHex, pending)

	slog.Info("Received proposal via relay",
		"team", proposal.Team,
		"action", block.Action,
		"hash", hashHex[:8],
	)
}

// handleApprovalFromRelay processes an approval received via relay
func (pm *PeerManager) handleApprovalFromRelay(project string, msg *protocol.Message) {
	var approval protocol.Approval
	if err := msg.ParsePayload(&approval); err != nil {
		slog.Warn("Invalid approval payload from relay", "error", err)
		return
	}

	hashHex := hex.EncodeToString(approval.BlockHash)
	enhanced, ok := pm.proposalStore.Get(hashHex)
	if !ok {
		slog.Debug("Approval for unknown proposal from relay", "hash", hashHex[:8])
		return
	}
	pending := enhanced.PendingProposal

	// Add approval (same logic as P2P)
	pending.mu.Lock()
	pending.Approvals[hex.EncodeToString(approval.By)] = approval
	approvalCount := len(pending.Approvals)
	pending.mu.Unlock()

	slog.Info("Received approval via relay",
		"team", approval.Team,
		"hash", hashHex[:8],
		"approvals", approvalCount,
	)

	c := pm.daemon.GetChain(approval.Team)
	if c == nil {
		return
	}

	// Check if we now have sufficient approvals
	if c.HasSufficientApprovals(pending.Block) {
		if err := c.AppendBlock(pending.Block); err != nil {
			slog.Error("Failed to commit block with approvals from relay",
				"hash", hashHex[:8],
				"error", err,
			)
			return
		}

		slog.Info("Block committed with consensus (via relay)",
			"team", pending.Team,
			"action", pending.Block.Action,
			"index", pending.Block.Index,
		)

		// Save chain
		if err := c.Save(pm.daemon.paths.ChainFile(approval.Team)); err != nil {
			slog.Error("Failed to save chain", "team", approval.Team, "error", err)
		}
	}
}

// handleOpsPushFromRelay processes an ops push received via relay
func (pm *PeerManager) handleOpsPushFromRelay(project string, msg *protocol.Message) {
	var push protocol.OpsPush
	if err := msg.ParsePayload(&push); err != nil {
		slog.Warn("Invalid ops_push payload from relay", "error", err)
		return
	}

	slog.Info("Received ops_push via relay",
		"project", push.Project,
		"env", push.Environment,
		"count", len(push.Operations),
	)

	// Get ops chain manager
	ocm := pm.daemon.GetOpsChainManager()
	if ocm == nil {
		slog.Warn("Ops chain manager not initialized")
		return
	}

	// Convert protocol operations to ExportedOps for ImportOps
	// This ensures plaintext values are properly cached
	exportedOps := make([]*opschain.ExportedOp, 0, len(push.Operations))
	for _, op := range push.Operations {
		opsOp := &opschain.Operation{
			Seq:            op.Seq,
			Timestamp:      time.Unix(0, op.Timestamp),
			Author:         op.Author,
			Op:             opschain.OpType(op.Op),
			Key:            op.Key,
			EncryptedValue: op.EncryptedValue,
			PrevHash:       op.PrevHash,
			Signature:      op.Signature,
		}

		exportedOps = append(exportedOps, &opschain.ExportedOp{
			Op:             opsOp,
			PlaintextValue: op.Value, // The plaintext value sent with the push
		})
	}

	// Use ImportOps which properly handles value caching
	merged, conflict, err := ocm.ImportOps(push.Project, push.Environment, exportedOps)
	if err != nil {
		slog.Error("Failed to import ops from relay",
			"project", push.Project,
			"env", push.Environment,
			"error", err,
		)
		return
	}

	if conflict != nil {
		slog.Warn("Conflict detected in relay ops",
			"project", push.Project,
			"env", push.Environment,
			"seq", conflict.Seq,
		)
	}

	slog.Debug("Imported ops from relay",
		"project", push.Project,
		"env", push.Environment,
		"merged", merged,
	)
}

// Broadcast sends a message to all connected peers
func (pm *PeerManager) Broadcast(msg *protocol.Message) {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	for _, peer := range pm.peers {
		if peer.State != PeerStateConnected {
			continue
		}

		select {
		case peer.sendCh <- msg:
		default:
			// Channel full, skip this peer
		}
	}
}

// SendToPeer sends a message to a specific peer
func (pm *PeerManager) SendToPeer(fingerprint string, msg *protocol.Message) error {
	pm.mu.RLock()
	peer := pm.peers[fingerprint]
	pm.mu.RUnlock()

	if peer == nil || peer.State != PeerStateConnected {
		return fmt.Errorf("peer not connected: %s", fingerprint)
	}

	select {
	case peer.sendCh <- msg:
		return nil
	default:
		return fmt.Errorf("send buffer full")
	}
}

// SavePeers persists the current saved peers to disk
func (pm *PeerManager) SavePeers() error {
	if pm.daemon == nil || pm.daemon.paths == nil {
		return fmt.Errorf("daemon paths not initialized")
	}

	pm.mu.RLock()
	peers := make([]*SavedPeer, 0, len(pm.savedPeers))
	for _, sp := range pm.savedPeers {
		peers = append(peers, sp)
	}
	pm.mu.RUnlock()

	file := &SavedPeersFile{
		Version: 1,
		Peers:   peers,
	}

	data, err := json.MarshalIndent(file, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal peers: %w", err)
	}

	if err := os.WriteFile(pm.daemon.paths.PeersFile, data, 0600); err != nil {
		return fmt.Errorf("write peers file: %w", err)
	}

	slog.Debug("Saved peers to disk", "count", len(peers))
	return nil
}

// LoadPeers loads saved peers from disk
func (pm *PeerManager) LoadPeers() error {
	if pm.daemon == nil || pm.daemon.paths == nil {
		return fmt.Errorf("daemon paths not initialized")
	}

	data, err := os.ReadFile(pm.daemon.paths.PeersFile)
	if err != nil {
		if os.IsNotExist(err) {
			return nil // No saved peers yet
		}
		return fmt.Errorf("read peers file: %w", err)
	}

	var file SavedPeersFile
	if err := json.Unmarshal(data, &file); err != nil {
		return fmt.Errorf("unmarshal peers: %w", err)
	}

	pm.mu.Lock()
	for _, sp := range file.Peers {
		pm.savedPeers[sp.Fingerprint] = sp
	}
	pm.mu.Unlock()

	slog.Debug("Loaded saved peers", "count", len(file.Peers))
	return nil
}

// ReconnectSavedPeers attempts to reconnect to all saved peers
func (pm *PeerManager) ReconnectSavedPeers() {
	pm.mu.RLock()
	peers := make([]*SavedPeer, 0, len(pm.savedPeers))
	for _, sp := range pm.savedPeers {
		peers = append(peers, sp)
	}
	pm.mu.RUnlock()

	if len(peers) == 0 {
		return
	}

	slog.Info("Reconnecting to saved peers", "count", len(peers))

	for _, sp := range peers {
		go pm.connectToPeer(sp.Fingerprint, sp.Name, sp.Addr)
	}
}

// SavePeer adds a peer to the saved peers list and persists to disk
func (pm *PeerManager) SavePeer(fingerprint, name, addr string) error {
	pm.mu.Lock()
	pm.savedPeers[fingerprint] = &SavedPeer{
		Name:        name,
		Fingerprint: fingerprint,
		Addr:        addr,
		AddedAt:     time.Now(),
	}
	pm.mu.Unlock()

	return pm.SavePeers()
}

// ForgetPeer removes a peer from saved peers and persists to disk
func (pm *PeerManager) ForgetPeer(fingerprint string) error {
	pm.mu.Lock()
	delete(pm.savedPeers, fingerprint)
	pm.mu.Unlock()

	return pm.SavePeers()
}

// UpdateSavedPeerLastSeen updates the last seen time for a saved peer
func (pm *PeerManager) UpdateSavedPeerLastSeen(fingerprint string) {
	pm.mu.Lock()
	if sp, exists := pm.savedPeers[fingerprint]; exists {
		sp.LastSeen = time.Now()
	}
	pm.mu.Unlock()
}

// GetSavedPeers returns a copy of all saved peers
func (pm *PeerManager) GetSavedPeers() []*SavedPeer {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	peers := make([]*SavedPeer, 0, len(pm.savedPeers))
	for _, sp := range pm.savedPeers {
		// Make a copy
		copy := *sp
		peers = append(peers, &copy)
	}
	return peers
}

// IsSavedPeer checks if a peer is in the saved peers list
func (pm *PeerManager) IsSavedPeer(fingerprint string) bool {
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	_, exists := pm.savedPeers[fingerprint]
	return exists
}

// Utility functions

func findSharedTeams(a, b []string) []string {
	teamSet := make(map[string]bool)
	for _, t := range a {
		teamSet[t] = true
	}

	var shared []string
	for _, t := range b {
		if teamSet[t] {
			shared = append(shared, t)
		}
	}
	return shared
}

func mustMarshal(v any) json.RawMessage {
	data, _ := json.Marshal(v)
	return data
}

// CreateProposal creates a new proposal and broadcasts it to peers
func (pm *PeerManager) CreateProposal(team string, block *chain.Block) error {
	c := pm.daemon.GetChain(team)
	if c == nil {
		return fmt.Errorf("team not found: %s", team)
	}

	// Check if block already has sufficient approvals (e.g., bootstrap phase)
	if c.HasSufficientApprovals(block) {
		// Append directly
		if err := c.AppendBlock(block); err != nil {
			return fmt.Errorf("append block: %w", err)
		}
		pm.saveChain(team, c)

		// Broadcast the committed block
		pm.broadcastCommittedBlock(team, block)
		return nil
	}

	// Store as pending proposal
	hashHex := hex.EncodeToString(block.Hash)
	proposal := &PendingProposal{
		Block:      block,
		Team:       team,
		ReceivedAt: time.Now(),
		Approvals:  make(map[string]protocol.Approval),
	}
	if err := pm.proposalStore.Add(hashHex, proposal); err != nil {
		return fmt.Errorf("store proposal: %w", err)
	}
	pm.daemon.metrics.ProposalsCreated.Add(1)

	// Broadcast proposal to peers
	blockJSON, err := json.Marshal(block)
	if err != nil {
		return fmt.Errorf("marshal block: %w", err)
	}

	prop := protocol.Proposal{
		Team:  team,
		Block: blockJSON,
	}

	msg, err := protocol.NewMessage(protocol.MsgProposal, prop)
	if err != nil {
		return fmt.Errorf("create message: %w", err)
	}

	pm.BroadcastToTeam(team, msg)

	slog.Info("Created proposal",
		"team", team,
		"action", block.Action,
		"index", block.Index,
		"hash", hashHex[:8],
		"required", c.RequiredApprovals(block),
	)

	return nil
}

// GetPendingProposals returns all pending proposals for a team
func (pm *PeerManager) GetPendingProposals(team string) []*PendingProposal {
	enhanced := pm.proposalStore.ListForTeam(team)
	proposals := make([]*PendingProposal, 0, len(enhanced))
	for _, p := range enhanced {
		proposals = append(proposals, p.PendingProposal)
	}
	return proposals
}

// GetAllPendingProposals returns all pending proposals
func (pm *PeerManager) GetAllPendingProposals() []*PendingProposal {
	enhanced := pm.proposalStore.List()
	proposals := make([]*PendingProposal, 0, len(enhanced))
	for _, p := range enhanced {
		proposals = append(proposals, p.PendingProposal)
	}
	return proposals
}

// GetProposal returns a pending proposal by hash
func (pm *PeerManager) GetProposal(hashHex string) *PendingProposal {
	proposal, _ := pm.proposalStore.GetLegacy(hashHex)
	return proposal
}

// ApproveProposal approves a pending proposal and broadcasts the approval
func (pm *PeerManager) ApproveProposal(hashHex string, approver *chain.Approval) error {
	pending, exists := pm.proposalStore.GetLegacy(hashHex)
	if !exists {
		return fmt.Errorf("proposal not found: %s", hashHex)
	}

	c := pm.daemon.GetChain(pending.Team)
	if c == nil {
		return fmt.Errorf("team not found: %s", pending.Team)
	}

	// Verify approval
	if !pending.Block.VerifyApproval(approver) {
		return fmt.Errorf("invalid approval signature")
	}

	// Add approval to pending proposal
	pending.mu.Lock()
	approverKey := hex.EncodeToString(approver.By)
	if _, alreadyApproved := pending.Approvals[approverKey]; alreadyApproved {
		pending.mu.Unlock()
		return fmt.Errorf("already approved")
	}

	// Convert to protocol approval
	protoApproval := protocol.Approval{
		Team:      pending.Team,
		BlockHash: pending.Block.Hash,
		By:        approver.By,
		SigAlgo:   approver.SigAlgo,
		Signature: approver.Signature,
		Timestamp: approver.Timestamp,
	}
	pending.Approvals[approverKey] = protoApproval

	// Add to block's approvals
	pending.Block.Approvals = append(pending.Block.Approvals, *approver)
	approvalCount := len(pending.Block.Approvals)
	pending.mu.Unlock()

	slog.Info("Added approval to proposal",
		"hash", hashHex[:8],
		"approvals", approvalCount,
		"required", c.RequiredApprovals(pending.Block),
	)

	// Broadcast approval to peers
	msg, err := protocol.NewMessage(protocol.MsgApproval, protoApproval)
	if err == nil {
		pm.BroadcastToTeam(pending.Team, msg)
	}

	// Check if we now have sufficient approvals
	if c.HasSufficientApprovals(pending.Block) {
		if err := c.AppendBlock(pending.Block); err != nil {
			slog.Error("Failed to commit block with sufficient approvals",
				"hash", hashHex[:8],
				"error", err,
			)
			return fmt.Errorf("commit block: %w", err)
		}

		slog.Info("Block committed with consensus",
			"team", pending.Team,
			"action", pending.Block.Action,
			"index", pending.Block.Index,
			"approvals", approvalCount,
		)

		// Save chain
		pm.saveChain(pending.Team, c)

		// Remove from pending
		pm.proposalStore.Remove(hashHex)

		// Record block committed metric
		pm.daemon.metrics.BlocksCommitted.Add(1)

		// Broadcast the committed block
		pm.broadcastCommittedBlock(pending.Team, pending.Block)

		// Notify via IPC
		pm.daemon.BroadcastEvent(&Event{
			Event: "chain.block_committed",
			Payload: mustMarshal(map[string]any{
				"team":      pending.Team,
				"action":    pending.Block.Action,
				"index":     pending.Block.Index,
				"approvals": approvalCount,
			}),
		})
	}

	return nil
}

// CleanupExpiredProposals removes proposals older than the given duration
// Deprecated: This is now handled automatically by the ProposalStore
func (pm *PeerManager) CleanupExpiredProposals(maxAge time.Duration) int {
	// Now handled automatically by ProposalStore cleanup goroutine
	// Kept for API compatibility
	return 0
}

// GetProjectPeers returns peers who might have ops for a project
// We return all connected peers if we're a member of the project
// (membership verification happens at the ops level)
func (pm *PeerManager) GetProjectPeers(project string) []*Peer {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	// First check if we're a member of this project
	weAreMember := false
	for _, team := range pm.daemon.Teams() {
		if team == project {
			weAreMember = true
			break
		}
	}

	var result []*Peer
	for _, peer := range pm.peers {
		if peer.State != PeerStateConnected {
			continue
		}

		// If the peer advertises this project, include them
		for _, team := range peer.Teams {
			if team == project {
				result = append(result, peer)
				break
			}
		}
	}

	// If we're a member but found no peers advertising the project,
	// return all connected peers as fallback (peer mDNS may be stale)
	if weAreMember && len(result) == 0 {
		for _, peer := range pm.peers {
			if peer.State == PeerStateConnected {
				result = append(result, peer)
			}
		}
	}

	return result
}

// Send sends a message to a specific peer
func (pm *PeerManager) Send(peer *Peer, msg *protocol.Message) error {
	if peer == nil {
		return fmt.Errorf("peer is nil")
	}

	select {
	case peer.sendCh <- msg:
		return nil
	case <-time.After(5 * time.Second):
		return fmt.Errorf("send timeout")
	}
}

// handleOpsHead handles ops chain head announcements
func (pm *PeerManager) handleOpsHead(peer *Peer, msg *protocol.Message) {
	var head protocol.OpsHead
	if err := msg.ParsePayload(&head); err != nil {
		slog.Warn("Invalid ops_head payload", "peer", peer.Fingerprint[:8], "error", err)
		return
	}

	slog.Debug("Received ops chain head",
		"peer", peer.Fingerprint[:8],
		"project", head.Project,
		"environment", head.Environment,
		"seq", head.Seq,
	)

	// Get our ops chain manager
	mgr := pm.daemon.GetOpsChainManager()
	if mgr == nil {
		slog.Debug("Ops chain manager not initialized")
		return
	}

	// Load our chain and compare
	ourChain, err := mgr.LoadChain(head.Project, head.Environment)
	if err != nil {
		slog.Debug("Cannot load ops chain", "error", err)
		return
	}

	ourHead := ourChain.Head()
	ourSeq := uint64(0)
	if ourHead != nil {
		ourSeq = ourHead.Seq
	}

	// If they have more operations, request them
	if head.Seq > ourSeq {
		pm.requestOps(peer, head.Project, head.Environment, ourSeq+1)
	}
}

// requestOps requests operations from a peer
func (pm *PeerManager) requestOps(peer *Peer, project, environment string, fromSeq uint64) {
	req := protocol.OpsGetOps{
		RequestID:   fmt.Sprintf("ops-%d", time.Now().UnixNano()),
		Project:     project,
		Environment: environment,
		FromSeq:     fromSeq,
	}

	msg, err := protocol.NewMessage(protocol.MsgOpsGetOps, req)
	if err != nil {
		slog.Error("Failed to create ops request", "error", err)
		return
	}

	select {
	case peer.sendCh <- msg:
		slog.Debug("Sent ops request",
			"peer", peer.Fingerprint[:8],
			"project", project,
			"environment", environment,
			"from_seq", fromSeq,
		)
	default:
		slog.Warn("Failed to send ops request - channel full", "peer", peer.Fingerprint[:8])
	}
}

// handleOpsGetOps handles requests for operations from a peer
func (pm *PeerManager) handleOpsGetOps(peer *Peer, msg *protocol.Message) {
	var req protocol.OpsGetOps
	if err := msg.ParsePayload(&req); err != nil {
		slog.Warn("Invalid ops_get_ops payload", "peer", peer.Fingerprint[:8], "error", err)
		return
	}

	slog.Debug("Received ops request",
		"peer", peer.Fingerprint[:8],
		"project", req.Project,
		"environment", req.Environment,
		"from_seq", req.FromSeq,
	)

	mgr := pm.daemon.GetOpsChainManager()
	if mgr == nil {
		slog.Debug("Ops chain manager not initialized")
		return
	}

	// Export ops from the requested sequence
	exported, err := mgr.ExportRange(req.Project, req.Environment, req.FromSeq)
	if err != nil {
		slog.Warn("Failed to export ops", "error", err)
		return
	}

	// Convert to wire format
	wireOps := make([]protocol.OpsOperation, 0, len(exported))
	for _, exp := range exported {
		wireOps = append(wireOps, protocol.OpsOperation{
			Seq:            exp.Op.Seq,
			Timestamp:      exp.Op.Timestamp.UnixNano(),
			Author:         exp.Op.Author,
			Op:             string(exp.Op.Op),
			Key:            exp.Op.Key,
			EncryptedValue: exp.Op.EncryptedValue, // Original encrypted value (for signature verification)
			Value:          exp.PlaintextValue,    // Plaintext (for recipient to cache)
			PrevHash:       exp.Op.PrevHash,
			Signature:      exp.Op.Signature,
		})
	}

	// Send response
	resp := protocol.OpsOps{
		RequestID:   req.RequestID,
		Project:     req.Project,
		Environment: req.Environment,
		Operations:  wireOps,
	}

	respMsg, err := protocol.NewMessage(protocol.MsgOpsOps, resp)
	if err != nil {
		slog.Error("Failed to create ops response", "error", err)
		return
	}

	select {
	case peer.sendCh <- respMsg:
		slog.Debug("Sent ops response",
			"peer", peer.Fingerprint[:8],
			"project", req.Project,
			"environment", req.Environment,
			"count", len(wireOps),
		)
	default:
		slog.Warn("Failed to send ops response - channel full", "peer", peer.Fingerprint[:8])
	}
}

// handleOpsOps handles operations received from a peer
func (pm *PeerManager) handleOpsOps(peer *Peer, msg *protocol.Message) {
	var resp protocol.OpsOps
	if err := msg.ParsePayload(&resp); err != nil {
		slog.Warn("Invalid ops_ops payload", "peer", peer.Fingerprint[:8], "error", err)
		return
	}

	slog.Debug("Received operations",
		"peer", peer.Fingerprint[:8],
		"project", resp.Project,
		"environment", resp.Environment,
		"count", len(resp.Operations),
	)

	if len(resp.Operations) == 0 {
		return
	}

	mgr := pm.daemon.GetOpsChainManager()
	if mgr == nil {
		slog.Debug("Ops chain manager not initialized")
		return
	}

	// Convert wire format to exported ops
	incoming := make([]*opschain.ExportedOp, 0, len(resp.Operations))
	for _, wireOp := range resp.Operations {
		op := &opschain.Operation{
			Seq:            wireOp.Seq,
			Timestamp:      time.Unix(0, wireOp.Timestamp),
			Author:         wireOp.Author,
			Op:             opschain.OpType(wireOp.Op),
			Key:            wireOp.Key,
			EncryptedValue: wireOp.EncryptedValue, // Original encrypted value
			PrevHash:       wireOp.PrevHash,
			Signature:      wireOp.Signature,
		}
		incoming = append(incoming, &opschain.ExportedOp{
			Op:             op,
			PlaintextValue: wireOp.Value, // Plaintext for caching
		})
	}

	// Import into our chain (stores original ops, caches plaintext values)
	merged, conflict, err := mgr.ImportOps(resp.Project, resp.Environment, incoming)
	if err != nil {
		slog.Error("Failed to import ops", "error", err)
		return
	}

	if conflict != nil {
		slog.Warn("Ops chain conflict detected",
			"project", resp.Project,
			"environment", resp.Environment,
			"seq", conflict.Seq,
		)
		// Broadcast conflict event
		pm.daemon.BroadcastEvent(&Event{
			Event: "opschain.conflict",
			Payload: mustMarshal(map[string]any{
				"project":     resp.Project,
				"environment": resp.Environment,
				"seq":         conflict.Seq,
			}),
		})
		return
	}

	if merged > 0 {
		slog.Info("Merged operations from peer",
			"peer", peer.Fingerprint[:8],
			"project", resp.Project,
			"environment", resp.Environment,
			"merged", merged,
		)

		// Broadcast update event
		pm.daemon.BroadcastEvent(&Event{
			Event: "opschain.synced",
			Payload: mustMarshal(map[string]any{
				"project":     resp.Project,
				"environment": resp.Environment,
				"merged":      merged,
				"from":        peer.Name,
			}),
		})
	}
}

// handleOpsPush handles operations pushed from a peer
func (pm *PeerManager) handleOpsPush(peer *Peer, msg *protocol.Message) {
	var push protocol.OpsPush
	if err := msg.ParsePayload(&push); err != nil {
		slog.Warn("Invalid ops_push payload", "peer", peer.Fingerprint[:8], "error", err)
		return
	}

	slog.Debug("Received ops push",
		"peer", peer.Fingerprint[:8],
		"project", push.Project,
		"environment", push.Environment,
		"count", len(push.Operations),
	)

	if len(push.Operations) == 0 {
		// Ack empty push
		pm.sendOpsAck(peer, push.RequestID, 0, 0, "")
		return
	}

	mgr := pm.daemon.GetOpsChainManager()
	if mgr == nil {
		pm.sendOpsAck(peer, push.RequestID, 0, 0, "ops chain manager not initialized")
		return
	}

	// Convert wire format to exported ops
	incoming := make([]*opschain.ExportedOp, 0, len(push.Operations))
	for _, wireOp := range push.Operations {
		op := &opschain.Operation{
			Seq:            wireOp.Seq,
			Timestamp:      time.Unix(0, wireOp.Timestamp),
			Author:         wireOp.Author,
			Op:             opschain.OpType(wireOp.Op),
			Key:            wireOp.Key,
			EncryptedValue: wireOp.EncryptedValue, // Original encrypted value
			PrevHash:       wireOp.PrevHash,
			Signature:      wireOp.Signature,
		}
		incoming = append(incoming, &opschain.ExportedOp{
			Op:             op,
			PlaintextValue: wireOp.Value, // Plaintext for caching
		})
	}

	// Import into our chain (stores original ops, caches plaintext values)
	merged, conflict, err := mgr.ImportOps(push.Project, push.Environment, incoming)
	if err != nil {
		slog.Error("Failed to import pushed ops", "error", err)
		pm.sendOpsAck(peer, push.RequestID, 0, 0, err.Error())
		return
	}

	if conflict != nil {
		slog.Warn("Ops chain conflict on push",
			"project", push.Project,
			"environment", push.Environment,
			"seq", conflict.Seq,
		)
		pm.sendOpsAck(peer, push.RequestID, 0, 0, fmt.Sprintf("conflict at seq %d", conflict.Seq))

		// Broadcast conflict event
		pm.daemon.BroadcastEvent(&Event{
			Event: "opschain.conflict",
			Payload: mustMarshal(map[string]any{
				"project":     push.Project,
				"environment": push.Environment,
				"seq":         conflict.Seq,
			}),
		})
		return
	}

	// Get new head seq
	chain, _ := mgr.LoadChain(push.Project, push.Environment)
	newHeadSeq := uint64(0)
	if chain != nil {
		if head := chain.Head(); head != nil {
			newHeadSeq = head.Seq
		}
	}

	// Send ack
	pm.sendOpsAck(peer, push.RequestID, merged, newHeadSeq, "")

	if merged > 0 {
		slog.Info("Received ops push from peer",
			"peer", peer.Fingerprint[:8],
			"project", push.Project,
			"environment", push.Environment,
			"merged", merged,
		)

		// Broadcast update event
		pm.daemon.BroadcastEvent(&Event{
			Event: "opschain.synced",
			Payload: mustMarshal(map[string]any{
				"project":     push.Project,
				"environment": push.Environment,
				"merged":      merged,
				"from":        peer.Name,
			}),
		})
	}
}

// sendOpsAck sends an ops acknowledgement
func (pm *PeerManager) sendOpsAck(peer *Peer, requestID string, received int, newHeadSeq uint64, errMsg string) {
	ack := protocol.OpsAck{
		RequestID:  requestID,
		Received:   received,
		NewHeadSeq: newHeadSeq,
		Error:      errMsg,
	}

	msg, err := protocol.NewMessage(protocol.MsgOpsAck, ack)
	if err != nil {
		return
	}

	select {
	case peer.sendCh <- msg:
	default:
	}
}
