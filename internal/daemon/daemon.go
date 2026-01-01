package daemon

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"envctl.dev/go/envctl/internal/chain"
	"envctl.dev/go/envctl/internal/config"
	"envctl.dev/go/envctl/internal/crypto"
	"envctl.dev/go/envctl/internal/opschain"
	"envctl.dev/go/envctl/internal/protocol"
	"envctl.dev/go/envctl/internal/relay"
)

// Daemon is the main envctl daemon
type Daemon struct {
	mu sync.RWMutex

	identity       *crypto.Identity
	paths          *config.Paths
	chains         map[string]*chain.Chain
	ipcServer      *IPCServer
	peerManager    *PeerManager
	webServer      *WebServer
	logBuffer      *LogBuffer
	metrics        *Metrics
	startTime      time.Time
	ctx            context.Context
	cancel         context.CancelFunc
	agent            *Agent
	pendingSecrets   *PendingQueue
	incomingRequests *RequestQueue
	sleepWatcher     *SleepWatcher
	notifier         *NotificationService
	agentConfig      AgentConfig
	leaseManager     *LeaseManager
	opsChainManager  *opschain.Manager
	relayManager     *relay.Manager
	relayConfig      *config.RelayConfig
}

// Status represents the daemon's current status
type Status struct {
	Running       bool      `json:"running"`
	PID           int       `json:"pid"`
	Uptime        string    `json:"uptime"`
	StartTime     time.Time `json:"start_time"`
	Identity      string    `json:"identity"`
	Fingerprint   string    `json:"fingerprint"`
	P2PAddr       string    `json:"p2p_addr"`
	PeerCount     int       `json:"peer_count"`
	TeamCount     int       `json:"team_count"`
	AgentUnlocked bool      `json:"agent_unlocked"`
	PendingCount  int       `json:"pending_count"`
}

// Options configures the daemon
type Options struct {
	Paths             *config.Paths
	Identity          *crypto.Identity
	P2PPort           int
	WebPort           int
	WebEnabled        bool
	AgentConfig       AgentConfig
	NotifyEnabled     bool
	LockOnSleep       bool
	RelayConfig       *config.RelayConfig
}

// New creates a new daemon instance
func New(opts *Options) (*Daemon, error) {
	ctx, cancel := context.WithCancel(context.Background())

	// Create log buffer for capturing logs
	logBuffer := NewLogBuffer(LogBufferSize)

	// Set up logging with buffer
	baseHandler := slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	})
	bufferedHandler := NewBufferedHandler(logBuffer, baseHandler)
	slog.SetDefault(slog.New(bufferedHandler))

	// Set up agent config with defaults if not provided
	agentCfg := opts.AgentConfig
	if agentCfg.Timeout == 0 && agentCfg.IdleTimeout == 0 {
		agentCfg = DefaultAgentConfig()
	}

	d := &Daemon{
		identity:       opts.Identity,
		paths:          opts.Paths,
		chains:         make(map[string]*chain.Chain),
		logBuffer:      logBuffer,
		metrics:        NewMetrics(),
		startTime:      time.Now(),
		ctx:            ctx,
		cancel:         cancel,
		agent:            NewAgent(agentCfg),
		pendingSecrets:   NewPendingQueue(1*time.Hour, 100),
		incomingRequests: NewRequestQueue(15*time.Minute, 100),
		notifier:         NewNotificationService(opts.NotifyEnabled),
		agentConfig:    agentCfg,
	}

	// Create lease manager (needs daemon reference for cleanup events)
	d.leaseManager = NewLeaseManager(opts.Paths.LeasesFile, d)

	// Create ops chain manager
	d.opsChainManager = opschain.NewManager(
		opts.Paths.ChainsDir,
		opts.Paths.TempDir,
		opts.Identity,
	)

	// Create relay manager (always, so projects can enable relay)
	relayConfig := opts.RelayConfig
	if relayConfig == nil {
		relayConfig = &config.RelayConfig{} // Empty config is fine
	}
	d.relayConfig = relayConfig
	d.relayManager = relay.NewManager(opts.Identity, relayConfig)
	// Message handler will be set after peer manager is created

	// Set up agent callbacks
	d.agent.SetCallbacks(d.onAgentLock, d.onAgentUnlock)

	// Auto-unlock agent with the identity we already have
	// Pass 0 timeout so it never expires - the daemon runs unlocked
	// as long as it's running. Use keychain for passphrase-free startup.
	if opts.Identity != nil {
		d.agent.Unlock(opts.Identity, 0)
	}

	// Load existing chains
	if err := d.loadChains(); err != nil {
		cancel()
		return nil, fmt.Errorf("load chains: %w", err)
	}

	// Create IPC server
	d.ipcServer = NewIPCServer(opts.Paths.SocketPath, d)

	// Create peer manager
	p2pPort := opts.P2PPort
	if p2pPort == 0 {
		p2pPort = 7834
	}
	d.peerManager = NewPeerManager(d, p2pPort)

	// Set up relay message handler now that peer manager exists
	if d.relayManager != nil {
		d.relayManager.SetMessageHandler(d.handleRelayMessage)
	}

	// Create web server if enabled
	if opts.WebEnabled {
		webPort := opts.WebPort
		if webPort == 0 {
			webPort = 7835
		}
		d.webServer = NewWebServer(d, webPort)
	}

	// Register additional IPC handlers
	handlers := NewHandlers(d)
	handlers.RegisterHandlers()

	return d, nil
}

// loadChains loads all chain files
func (d *Daemon) loadChains() error {
	entries, err := os.ReadDir(d.paths.ChainsDir)
	if os.IsNotExist(err) {
		return nil // No chains yet
	}
	if err != nil {
		return err
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		name := entry.Name()
		if len(name) < 6 || name[len(name)-6:] != ".chain" {
			continue
		}

		// Skip backup files
		if len(name) > 8 && name[len(name)-8:] == ".chain.1" {
			continue
		}

		teamName := name[:len(name)-6]
		chainPath := d.paths.ChainFile(teamName)

		c, recovered, err := chain.TryLoadWithRecovery(chainPath)
		if err != nil {
			slog.Warn("Failed to load chain", "team", teamName, "error", err)
			continue
		}

		if recovered {
			slog.Info("Recovered chain from backup", "team", teamName)
		}

		d.chains[teamName] = c
		slog.Info("Loaded chain", "team", teamName, "blocks", c.Len())
	}

	return nil
}

// Start starts the daemon
func (d *Daemon) Start() error {
	slog.Info("Starting daemon",
		"identity", d.identity.Name,
		"fingerprint", d.identity.Fingerprint(),
	)

	// Write PID file
	if d.paths.PIDFile != "" {
		if err := os.WriteFile(d.paths.PIDFile, []byte(fmt.Sprintf("%d", os.Getpid())), 0600); err != nil {
			slog.Warn("Failed to write PID file", "error", err)
		}
	}

	// Start IPC server
	if err := d.ipcServer.Start(d.ctx); err != nil {
		return fmt.Errorf("start IPC server: %w", err)
	}

	// Start peer manager
	if err := d.peerManager.Start(d.ctx); err != nil {
		return fmt.Errorf("start peer manager: %w", err)
	}

	// Load saved peers and attempt to reconnect
	if err := d.peerManager.LoadPeers(); err != nil {
		slog.Warn("Failed to load saved peers", "error", err)
	} else {
		// Reconnect in background after a short delay to allow TLS setup to complete
		go func() {
			time.Sleep(2 * time.Second)
			d.peerManager.ReconnectSavedPeers()
		}()
	}

	// Start web server if enabled
	if d.webServer != nil {
		if err := d.webServer.Start(d.ctx); err != nil {
			return fmt.Errorf("start web server: %w", err)
		}
	}

	// Start sleep watcher if configured
	if d.agentConfig.LockOnSleep {
		d.sleepWatcher = NewSleepWatcher(func() {
			d.agent.Lock()
		})
		d.sleepWatcher.Start()
	}

	// Start lease manager
	d.leaseManager.Start()

	// Connect to relays for projects that have relay configured
	if d.relayManager != nil {
		d.connectProjectRelays()
	}

	slog.Info("Daemon started")

	return nil
}

// Run runs the daemon until interrupted
func (d *Daemon) Run() error {
	if err := d.Start(); err != nil {
		return err
	}

	// Wait for shutdown signal
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	select {
	case sig := <-sigChan:
		slog.Info("Received signal, shutting down", "signal", sig)
	case <-d.ctx.Done():
	}

	return d.Stop()
}

// Stop stops the daemon gracefully
func (d *Daemon) Stop() error {
	slog.Info("Stopping daemon")

	d.cancel()

	// Stop relay manager
	if d.relayManager != nil {
		if err := d.relayManager.Stop(); err != nil {
			slog.Warn("Failed to stop relay manager", "error", err)
		}
	}

	// Stop lease manager
	if d.leaseManager != nil {
		d.leaseManager.Stop()
	}

	// Stop sleep watcher
	if d.sleepWatcher != nil {
		d.sleepWatcher.Stop()
	}

	// Lock agent
	if d.agent != nil {
		d.agent.Lock()
	}

	// Stop web server
	if d.webServer != nil {
		d.webServer.Stop()
	}

	// Stop IPC server
	d.ipcServer.Stop()

	// Stop peer manager
	d.peerManager.Stop()

	// Save chains
	d.mu.RLock()
	for name, c := range d.chains {
		if err := c.Save(d.paths.ChainFile(name)); err != nil {
			slog.Error("Failed to save chain", "team", name, "error", err)
		}
	}
	d.mu.RUnlock()

	// Remove PID file
	if d.paths.PIDFile != "" {
		os.Remove(d.paths.PIDFile)
	}

	slog.Info("Daemon stopped")
	return nil
}

// Status returns the daemon's current status
func (d *Daemon) Status() *Status {
	d.mu.RLock()
	defer d.mu.RUnlock()

	uptime := time.Since(d.startTime)

	return &Status{
		Running:       true,
		PID:           os.Getpid(),
		Uptime:        uptime.Round(time.Second).String(),
		StartTime:     d.startTime,
		Identity:      d.identity.Name,
		Fingerprint:   d.identity.Fingerprint(),
		P2PAddr:       d.peerManager.ListenAddr(),
		PeerCount:     d.peerManager.PeerCount(),
		TeamCount:     len(d.chains),
		AgentUnlocked: d.agent.IsUnlocked(),
		PendingCount:  d.pendingSecrets.Count(),
	}
}

// Identity returns the daemon's identity
func (d *Daemon) Identity() *crypto.Identity {
	return d.identity
}

// GetChain returns a team's chain
func (d *Daemon) GetChain(teamName string) *chain.Chain {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.chains[teamName]
}

// AddChain adds a new team chain
func (d *Daemon) AddChain(teamName string, c *chain.Chain) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if _, exists := d.chains[teamName]; exists {
		return fmt.Errorf("team already exists: %s", teamName)
	}

	d.chains[teamName] = c

	// Save chain
	if err := c.Save(d.paths.ChainFile(teamName)); err != nil {
		return fmt.Errorf("save chain: %w", err)
	}

	return nil
}

// Teams returns all team names
func (d *Daemon) Teams() []string {
	d.mu.RLock()
	defer d.mu.RUnlock()

	teams := make([]string, 0, len(d.chains))
	for name := range d.chains {
		teams = append(teams, name)
	}
	return teams
}

// ReloadChains reloads all chain files from disk
func (d *Daemon) ReloadChains() error {
	d.mu.Lock()
	defer d.mu.Unlock()

	// Clear existing chains
	d.chains = make(map[string]*chain.Chain)

	// Reload from disk
	entries, err := os.ReadDir(d.paths.ChainsDir)
	if os.IsNotExist(err) {
		slog.Info("No chains directory, nothing to reload")
		return nil
	}
	if err != nil {
		return err
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		name := entry.Name()
		if len(name) < 6 || name[len(name)-6:] != ".chain" {
			continue
		}

		// Skip backup files
		if len(name) > 8 && name[len(name)-8:] == ".chain.1" {
			continue
		}

		teamName := name[:len(name)-6]
		chainPath := d.paths.ChainFile(teamName)

		c, recovered, err := chain.TryLoadWithRecovery(chainPath)
		if err != nil {
			slog.Warn("Failed to load chain", "team", teamName, "error", err)
			continue
		}

		if recovered {
			slog.Info("Recovered chain from backup", "team", teamName)
		}

		d.chains[teamName] = c
		slog.Info("Loaded chain", "team", teamName, "blocks", c.Len())
	}

	slog.Info("Chains reloaded", "count", len(d.chains))

	// Broadcast reload event to clients
	d.ipcServer.BroadcastEvent(&Event{
		Event: "chains.reloaded",
	})

	return nil
}

// PeerManager returns the peer manager
func (d *Daemon) PeerManager() *PeerManager {
	return d.peerManager
}

// BroadcastEvent broadcasts an event to all IPC clients
func (d *Daemon) BroadcastEvent(event *Event) {
	if d.ipcServer != nil {
		d.ipcServer.BroadcastEvent(event)
	}
}

// LogBuffer returns the daemon's log buffer
func (d *Daemon) LogBuffer() *LogBuffer {
	return d.logBuffer
}

// Agent returns the agent
func (d *Daemon) Agent() *Agent {
	return d.agent
}

// PendingSecrets returns the pending secrets queue
func (d *Daemon) PendingSecrets() *PendingQueue {
	return d.pendingSecrets
}

// IncomingRequests returns the incoming request queue
func (d *Daemon) IncomingRequests() *RequestQueue {
	return d.incomingRequests
}

// Notifier returns the notification service
func (d *Daemon) Notifier() *NotificationService {
	return d.notifier
}

// Metrics returns the metrics collector
func (d *Daemon) Metrics() *Metrics {
	return d.metrics
}

// LeaseManager returns the lease manager
func (d *Daemon) LeaseManager() *LeaseManager {
	return d.leaseManager
}

// GetOpsChainManager returns the ops chain manager
func (d *Daemon) GetOpsChainManager() *opschain.Manager {
	return d.opsChainManager
}

// RelayManager returns the relay manager
func (d *Daemon) RelayManager() *relay.Manager {
	return d.relayManager
}

// connectProjectRelays connects to relays for all projects that have relay configured
func (d *Daemon) connectProjectRelays() {
	d.mu.RLock()
	defer d.mu.RUnlock()

	for name, c := range d.chains {
		relayURL := c.RelayURL()
		if relayURL == "" || !c.AllowRelay() {
			continue
		}

		go func(project, url string) {
			if err := d.relayManager.ConnectProject(project, url); err != nil {
				slog.Warn("Failed to connect to relay", "project", project, "url", url, "error", err)
			}
		}(name, relayURL)
	}
}

// ConnectProjectRelay connects to the relay for a specific project
func (d *Daemon) ConnectProjectRelay(project string) error {
	if d.relayManager == nil {
		return fmt.Errorf("relay not enabled")
	}

	c := d.GetChain(project)
	if c == nil {
		return fmt.Errorf("project not found: %s", project)
	}

	relayURL := c.RelayURL()
	if relayURL == "" {
		return fmt.Errorf("no relay configured for project %s", project)
	}

	if !c.AllowRelay() {
		return fmt.Errorf("relay not enabled for project %s", project)
	}

	return d.relayManager.ConnectProject(project, relayURL)
}

// MetricsSnapshot returns a point-in-time snapshot of all metrics
func (d *Daemon) MetricsSnapshot() *MetricsSnapshot {
	return d.metrics.Snapshot(func() GaugeMetrics {
		d.mu.RLock()
		defer d.mu.RUnlock()

		chainLengths := make(map[string]int, len(d.chains))
		for name, c := range d.chains {
			chainLengths[name] = c.Len()
		}

		return GaugeMetrics{
			ConnectedPeers:   d.peerManager.PeerCount(),
			PendingProposals: d.peerManager.proposalStore.Count(),
			TeamCount:        len(d.chains),
			ChainLengths:     chainLengths,
		}
	})
}

// AgentStatus returns the current agent status with pending count
func (d *Daemon) AgentStatus() AgentStatus {
	status := d.agent.Status()
	status.PendingCount = d.pendingSecrets.Count()
	return status
}

// onAgentLock is called when the agent locks
func (d *Daemon) onAgentLock() {
	slog.Info("agent locked, pending secrets will be queued")

	// Broadcast lock event to IPC clients
	d.BroadcastEvent(&Event{
		Event: "agent.locked",
	})
}

// onAgentUnlock is called when the agent unlocks
func (d *Daemon) onAgentUnlock() {
	// Process pending secrets
	pending := d.pendingSecrets.Drain()
	if len(pending) > 0 {
		slog.Info("processing pending secrets", "count", len(pending))
		for _, p := range pending {
			d.processPendingSecret(p)
		}
	}

	// Broadcast unlock event to IPC clients
	payload, _ := json.Marshal(map[string]any{
		"pending_processed": len(pending),
	})
	d.BroadcastEvent(&Event{
		Event:   "agent.unlocked",
		Payload: payload,
	})
}

// processPendingSecret processes a single pending secret
func (d *Daemon) processPendingSecret(p PendingSecret) {
	// Decrypt the secret payload
	plaintext, err := d.agent.Decrypt(p.Payload)
	if err != nil {
		slog.Error("failed to decrypt pending secret",
			"peer", p.Peer,
			"project", p.Project,
			"env", p.Env,
			"error", err,
		)
		return
	}

	// Store the decrypted secret
	if err := d.storeSecret(p.Project, p.Env, plaintext); err != nil {
		slog.Error("failed to store secret",
			"peer", p.Peer,
			"project", p.Project,
			"env", p.Env,
			"error", err,
		)
		return
	}

	slog.Info("stored secret from peer",
		"peer", p.Peer,
		"project", p.Project,
		"env", p.Env,
		"size", len(plaintext),
	)

	// Broadcast event to IPC clients
	eventPayload, _ := json.Marshal(map[string]any{
		"team": p.Project,
		"env":  p.Env,
		"from": p.Peer,
	})
	d.BroadcastEvent(&Event{
		Event:   "secret.stored",
		Payload: eventPayload,
	})
}

// storeSecret stores decrypted secret data to the daemon's secrets cache
func (d *Daemon) storeSecret(team, env string, plaintext []byte) error {
	// Ensure the team secrets directory exists
	teamDir := d.paths.TeamSecretsDir(team)
	if err := os.MkdirAll(teamDir, 0700); err != nil {
		return fmt.Errorf("create team secrets dir: %w", err)
	}

	// Re-encrypt the plaintext for our own identity (self-encryption for storage)
	ciphertext, err := crypto.EncryptForIdentity(plaintext, d.identity.Public())
	if err != nil {
		return fmt.Errorf("re-encrypt for storage: %w", err)
	}

	// Write to the secrets cache file
	secretPath := d.paths.SecretFile(team, env)
	if err := os.WriteFile(secretPath, ciphertext, 0600); err != nil {
		return fmt.Errorf("write secret file: %w", err)
	}

	return nil
}

// LoadCachedSecret loads a cached secret from the daemon's secrets directory
func (d *Daemon) LoadCachedSecret(team, env string) (map[string]string, error) {
	secretPath := d.paths.SecretFile(team, env)

	ciphertext, err := os.ReadFile(secretPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil // No cached secret
		}
		return nil, fmt.Errorf("read secret file: %w", err)
	}

	// Decrypt using our identity
	plaintext, err := crypto.DecryptWithIdentity(ciphertext, d.identity)
	if err != nil {
		return nil, fmt.Errorf("decrypt secret: %w", err)
	}

	// Parse the decrypted data as EncryptedEnv format
	var envData struct {
		Version   int               `json:"version"`
		Variables map[string]string `json:"variables"`
	}
	if err := json.Unmarshal(plaintext, &envData); err != nil {
		return nil, fmt.Errorf("parse secret data: %w", err)
	}

	return envData.Variables, nil
}

// ListCachedEnvs returns the list of cached environments for a team
func (d *Daemon) ListCachedEnvs(team string) ([]string, error) {
	teamDir := d.paths.TeamSecretsDir(team)

	entries, err := os.ReadDir(teamDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}

	var envs []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if filepath.Ext(name) == ".enc" {
			envs = append(envs, name[:len(name)-4])
		}
	}

	return envs, nil
}

// QueuePendingSecret queues a secret for later processing when agent is locked
func (d *Daemon) QueuePendingSecret(peer, project, env string, payload []byte) {
	d.pendingSecrets.Add(peer, project, env, payload)

	// Send notification
	if d.notifier != nil {
		d.notifier.Notify(
			"envctl - Secrets Pending",
			fmt.Sprintf("Received secrets from %s (agent locked). Unlock to process.", peer),
		)
	}
}

// loadIdentityWithPassphrase loads and decrypts the identity using the given passphrase
func (d *Daemon) loadIdentityWithPassphrase(passphrase []byte) (*crypto.Identity, error) {
	// Load from software identity file
	if d.paths.SoftwareIdentityExists() {
		identity, err := crypto.LoadEncrypted(d.paths.IdentityFile, passphrase)
		if err != nil {
			return nil, fmt.Errorf("decrypt identity: %w", err)
		}
		return identity, nil
	}

	// YubiKey identity doesn't use passphrase for decryption
	// (it uses PIN which is cached separately)
	if d.paths.YubiKeyIdentityExists() {
		return nil, fmt.Errorf("YubiKey identity requires PIN, not passphrase")
	}

	return nil, fmt.Errorf("no identity found")
}

// handleRelayMessage processes a message received via the relay.
// Messages received via relay are processed the same as P2P messages.
func (d *Daemon) handleRelayMessage(project string, msg *protocol.Message) error {
	slog.Debug("received relay message",
		"project", project,
		"type", msg.Type,
	)

	// Verify message signature if signed
	if msg.IsSigned() {
		if err := msg.Verify(); err != nil {
			return fmt.Errorf("invalid message signature: %w", err)
		}
	}

	// Route to peer manager for processing
	// The peer manager handles all protocol message types
	d.peerManager.HandleRelayMessage(project, msg)

	return nil
}
