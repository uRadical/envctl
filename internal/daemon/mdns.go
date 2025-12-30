package daemon

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/grandcat/zeroconf"
)

const (
	// MDNSServiceType is the mDNS service type for envctl
	MDNSServiceType = "_envctl._tcp"

	// MDNSDomain is the mDNS domain
	MDNSDomain = "local."

	// MDNSBrowseInterval is how often to scan for new peers
	MDNSBrowseInterval = 30 * time.Second
)

// DiscoveredPeer represents a peer found via mDNS
type DiscoveredPeer struct {
	Name        string
	Fingerprint string
	Host        string
	Port        int
	IPs         []net.IP
	Teams       []string
	DiscoveredAt time.Time
}

// MDNSService handles mDNS service discovery and advertising
type MDNSService struct {
	instanceName string
	port         int
	fingerprint  string
	name         string
	teams        []string

	mu        sync.RWMutex
	running   bool
	server    *zeroconf.Server
	peers     map[string]*DiscoveredPeer // fingerprint -> peer
	callbacks []func(*DiscoveredPeer)

	ctx    context.Context
	cancel context.CancelFunc
}

// NewMDNSService creates a new mDNS service
func NewMDNSService(instanceName string, port int, fingerprint, name string, teams []string) *MDNSService {
	ctx, cancel := context.WithCancel(context.Background())
	return &MDNSService{
		instanceName: instanceName,
		port:         port,
		fingerprint:  fingerprint,
		name:         name,
		teams:        teams,
		peers:        make(map[string]*DiscoveredPeer),
		callbacks:    make([]func(*DiscoveredPeer), 0),
		ctx:          ctx,
		cancel:       cancel,
	}
}

// Start starts the mDNS service (advertising + discovery)
func (m *MDNSService) Start() error {
	m.mu.Lock()
	if m.running {
		m.mu.Unlock()
		return nil
	}
	m.running = true
	m.mu.Unlock()

	slog.Info("mDNS service starting",
		"instance", m.instanceName,
		"fingerprint", m.fingerprint[:min(8, len(m.fingerprint))],
		"port", m.port,
	)

	// Start advertising our service
	if err := m.startAdvertising(); err != nil {
		slog.Warn("Failed to start mDNS advertising", "error", err)
		// Continue anyway - discovery can still work
	}

	// Start discovery in background
	go m.discoveryLoop()

	return nil
}

// startAdvertising registers our service via mDNS
func (m *MDNSService) startAdvertising() error {
	// Build TXT records
	txt := []string{
		fmt.Sprintf("fp=%s", m.fingerprint),
		fmt.Sprintf("name=%s", m.name),
		fmt.Sprintf("v=%s", "1"),
	}

	// Add teams (shortened to fit TXT record limits)
	if len(m.teams) > 0 {
		teamsStr := strings.Join(m.teams, ",")
		if len(teamsStr) > 200 { // Keep it reasonable
			teamsStr = teamsStr[:200]
		}
		txt = append(txt, fmt.Sprintf("teams=%s", teamsStr))
	}

	// Register the service - passing nil for interfaces uses all available
	server, err := zeroconf.Register(
		m.instanceName,       // Instance name (e.g., "alice-macbook")
		MDNSServiceType,      // Service type
		MDNSDomain,           // Domain
		m.port,               // Port
		txt,                  // TXT records
		nil,                  // Network interfaces (nil = all)
	)
	if err != nil {
		return fmt.Errorf("register mDNS service: %w", err)
	}

	m.mu.Lock()
	m.server = server
	m.mu.Unlock()

	slog.Info("mDNS service registered",
		"instance", m.instanceName,
		"port", m.port,
		"txt", txt,
	)

	return nil
}

// discoveryLoop continuously browses for peers
func (m *MDNSService) discoveryLoop() {
	// Initial discovery
	m.doBrowse()

	ticker := time.NewTicker(MDNSBrowseInterval)
	defer ticker.Stop()

	for {
		select {
		case <-m.ctx.Done():
			return
		case <-ticker.C:
			m.doBrowse()
		}
	}
}

// doBrowse performs a single mDNS browse
func (m *MDNSService) doBrowse() {
	// Create resolver
	resolver, err := zeroconf.NewResolver(nil)
	if err != nil {
		slog.Debug("Failed to create mDNS resolver", "error", err)
		return
	}

	// Browse for 5 seconds
	entries := make(chan *zeroconf.ServiceEntry)
	browseCtx, cancel := context.WithTimeout(m.ctx, 5*time.Second)
	defer cancel()

	go func() {
		for entry := range entries {
			m.handleDiscoveredEntry(entry)
		}
	}()

	if err := resolver.Browse(browseCtx, MDNSServiceType, MDNSDomain, entries); err != nil {
		slog.Debug("mDNS browse error", "error", err)
	}

	<-browseCtx.Done()
}

// handleDiscoveredEntry processes a discovered mDNS entry
func (m *MDNSService) handleDiscoveredEntry(entry *zeroconf.ServiceEntry) {
	// Parse TXT records
	var fingerprint, name, teamsStr string
	for _, txt := range entry.Text {
		if strings.HasPrefix(txt, "fp=") {
			fingerprint = txt[3:]
		} else if strings.HasPrefix(txt, "name=") {
			name = txt[5:]
		} else if strings.HasPrefix(txt, "teams=") {
			teamsStr = txt[6:]
		}
	}

	// Skip if no fingerprint or it's us
	if fingerprint == "" || fingerprint == m.fingerprint {
		return
	}

	// Parse teams
	var teams []string
	if teamsStr != "" {
		teams = strings.Split(teamsStr, ",")
	}

	// Build IP list
	ips := make([]net.IP, 0, len(entry.AddrIPv4)+len(entry.AddrIPv6))
	ips = append(ips, entry.AddrIPv4...)
	ips = append(ips, entry.AddrIPv6...)

	// Prefer IPv4 for the host
	host := entry.HostName
	if len(entry.AddrIPv4) > 0 {
		host = entry.AddrIPv4[0].String()
	} else if len(entry.AddrIPv6) > 0 {
		host = entry.AddrIPv6[0].String()
	}

	peer := &DiscoveredPeer{
		Name:         name,
		Fingerprint:  fingerprint,
		Host:         host,
		Port:         entry.Port,
		IPs:          ips,
		Teams:        teams,
		DiscoveredAt: time.Now(),
	}

	// Check if this is a new peer
	m.mu.Lock()
	existing, exists := m.peers[fingerprint]
	m.peers[fingerprint] = peer
	callbacks := m.callbacks
	m.mu.Unlock()

	if !exists {
		slog.Info("mDNS discovered new peer",
			"fingerprint", fingerprint[:min(8, len(fingerprint))],
			"name", name,
			"addr", fmt.Sprintf("%s:%d", host, entry.Port),
			"teams", teams,
		)

		// Notify callbacks
		for _, cb := range callbacks {
			go cb(peer)
		}
	} else if existing.Port != peer.Port || existing.Host != peer.Host {
		slog.Debug("mDNS peer info updated",
			"fingerprint", fingerprint[:min(8, len(fingerprint))],
			"name", name,
			"addr", fmt.Sprintf("%s:%d", host, entry.Port),
		)
	}
}

// OnPeerDiscovered registers a callback for peer discovery
func (m *MDNSService) OnPeerDiscovered(callback func(*DiscoveredPeer)) {
	m.mu.Lock()
	m.callbacks = append(m.callbacks, callback)
	m.mu.Unlock()
}

// GetPeers returns all discovered peers
func (m *MDNSService) GetPeers() []*DiscoveredPeer {
	m.mu.RLock()
	defer m.mu.RUnlock()

	peers := make([]*DiscoveredPeer, 0, len(m.peers))
	for _, p := range m.peers {
		peers = append(peers, p)
	}
	return peers
}

// UpdateTeams updates the teams list and re-registers
func (m *MDNSService) UpdateTeams(teams []string) {
	m.mu.Lock()
	m.teams = teams
	server := m.server
	m.mu.Unlock()

	// Shutdown old registration and re-register with new teams
	if server != nil {
		server.Shutdown()
	}

	if err := m.startAdvertising(); err != nil {
		slog.Warn("Failed to re-register mDNS with updated teams", "error", err)
	}
}

// Stop stops the mDNS service
func (m *MDNSService) Stop() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if !m.running {
		return nil
	}

	m.running = false
	m.cancel()

	if m.server != nil {
		m.server.Shutdown()
		m.server = nil
	}

	slog.Info("mDNS service stopped")
	return nil
}

// getLocalIPs returns local IP addresses suitable for mDNS
func getLocalIPs() ([]net.IP, error) {
	var ips []net.IP

	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("get interfaces: %w", err)
	}

	for _, iface := range ifaces {
		// Skip loopback and down interfaces
		if iface.Flags&net.FlagLoopback != 0 || iface.Flags&net.FlagUp == 0 {
			continue
		}

		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}

		for _, addr := range addrs {
			if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
				// Prefer IPv4, but include IPv6 too
				if ipnet.IP.To4() != nil || ipnet.IP.To16() != nil {
					ips = append(ips, ipnet.IP)
				}
			}
		}
	}

	return ips, nil
}

// getSystemHostname gets the system hostname, sanitized for mDNS
func getSystemHostname() string {
	hostname, err := os.Hostname()
	if err != nil {
		return "envctl"
	}

	// Sanitize for mDNS (alphanumeric and hyphens only)
	var sanitized strings.Builder
	for _, c := range strings.ToLower(hostname) {
		if (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' {
			sanitized.WriteRune(c)
		}
	}

	if sanitized.Len() == 0 {
		return "envctl"
	}

	return sanitized.String()
}
