package daemon

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/fs"
	"log/slog"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/websocket"
	"envctl.dev/go/envctl/internal/audit"
	"envctl.dev/go/envctl/internal/chain"
)

// UIFilesystem is set from main package with embedded UI files
var UIFilesystem fs.FS

// WebServer handles HTTP and WebSocket connections
type WebServer struct {
	daemon   *Daemon
	server   *http.Server
	upgrader websocket.Upgrader
	clients  map[*websocket.Conn]bool
}

// NewWebServer creates a new web server
func NewWebServer(daemon *Daemon, port int) *WebServer {
	ws := &WebServer{
		daemon:  daemon,
		clients: make(map[*websocket.Conn]bool),
		upgrader: websocket.Upgrader{
			CheckOrigin: func(r *http.Request) bool {
				return true // Allow all origins for localhost
			},
		},
	}

	mux := http.NewServeMux()

	// API routes
	mux.HandleFunc("/api/status", ws.handleStatus)
	mux.HandleFunc("/api/metrics", ws.handleMetrics)
	mux.HandleFunc("/api/peers", ws.handlePeers)
	mux.HandleFunc("/api/teams", ws.handleTeams)
	mux.HandleFunc("/api/team/members", ws.handleTeamMembers)
	mux.HandleFunc("/api/projects", ws.handleProjects)
	mux.HandleFunc("/api/projects/", ws.handleProjectDetail)
	mux.HandleFunc("/api/requests", ws.handleRequests)
	mux.HandleFunc("/api/audit", ws.handleAudit)
	mux.HandleFunc("/api/logs", ws.handleLogs)
	mux.HandleFunc("/api/logs/stats", ws.handleLogStats)

	// WebSocket
	mux.HandleFunc("/ws", ws.handleWebSocket)

	// Static files
	if UIFilesystem != nil {
		mux.Handle("/", http.FileServer(http.FS(UIFilesystem)))
	} else {
		slog.Warn("UI filesystem not initialized")
		mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/html")
			w.Write([]byte("<html><body><h1>envctl</h1><p>Web UI not available</p></body></html>"))
		})
	}

	ws.server = &http.Server{
		Addr:         fmt.Sprintf("127.0.0.1:%d", port),
		Handler:      mux,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
	}

	return ws
}

// Start starts the web server
func (ws *WebServer) Start(ctx context.Context) error {
	slog.Info("Web server starting", "addr", ws.server.Addr)

	go func() {
		if err := ws.server.ListenAndServe(); err != http.ErrServerClosed {
			slog.Error("Web server error", "error", err)
		}
	}()

	return nil
}

// Stop stops the web server
func (ws *WebServer) Stop() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ws.server.Shutdown(ctx)
}

// API Handlers

func (ws *WebServer) handleStatus(w http.ResponseWriter, r *http.Request) {
	ws.jsonResponse(w, ws.daemon.Status())
}

func (ws *WebServer) handleMetrics(w http.ResponseWriter, r *http.Request) {
	ws.jsonResponse(w, ws.daemon.MetricsSnapshot())
}

func (ws *WebServer) handlePeers(w http.ResponseWriter, r *http.Request) {
	if r.Method == "POST" {
		var body struct {
			Addr string `json:"addr"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			ws.errorResponse(w, http.StatusBadRequest, "Invalid request body")
			return
		}
		if err := ws.daemon.PeerManager().AddPeer(body.Addr); err != nil {
			ws.errorResponse(w, http.StatusInternalServerError, err.Error())
			return
		}
		ws.jsonResponse(w, map[string]bool{"ok": true})
		return
	}

	ws.jsonResponse(w, ws.daemon.PeerManager().Peers())
}

func (ws *WebServer) handleTeams(w http.ResponseWriter, r *http.Request) {
	teamNames := ws.daemon.Teams()

	type teamInfo struct {
		Name         string   `json:"name"`
		MemberCount  int      `json:"member_count"`
		BlockCount   int      `json:"block_count"`
		Environments []string `json:"environments"`
		Dissolved    bool     `json:"dissolved"`
	}

	teams := make([]teamInfo, 0, len(teamNames))
	for _, name := range teamNames {
		chain := ws.daemon.GetChain(name)
		if chain == nil {
			continue
		}
		policy := chain.Policy()
		var envs []string
		if policy != nil {
			envs = policy.Environments
		}
		teams = append(teams, teamInfo{
			Name:         name,
			MemberCount:  chain.MemberCount(),
			BlockCount:   chain.Len(),
			Environments: envs,
			Dissolved:    chain.IsDissolved(),
		})
	}

	ws.jsonResponse(w, teams)
}

func (ws *WebServer) handleTeamMembers(w http.ResponseWriter, r *http.Request) {
	teamName := r.URL.Query().Get("team")
	if teamName == "" {
		// Get first team
		teams := ws.daemon.Teams()
		if len(teams) == 0 {
			ws.jsonResponse(w, []interface{}{})
			return
		}
		teamName = teams[0]
	}

	chain := ws.daemon.GetChain(teamName)
	if chain == nil {
		ws.errorResponse(w, http.StatusNotFound, "Team not found")
		return
	}

	ws.jsonResponse(w, chain.Members())
}

func (ws *WebServer) handleProjects(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		ws.errorResponse(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	teamNames := ws.daemon.Teams()

	type projectInfo struct {
		Name         string   `json:"name"`
		MemberCount  int      `json:"member_count"`
		BlockCount   int      `json:"block_count"`
		Environments []string `json:"environments"`
		Dissolved    bool     `json:"dissolved"`
	}

	projects := make([]projectInfo, 0, len(teamNames))
	for _, name := range teamNames {
		chain := ws.daemon.GetChain(name)
		if chain == nil {
			continue
		}
		policy := chain.Policy()
		var envs []string
		if policy != nil {
			envs = policy.Environments
		}
		projects = append(projects, projectInfo{
			Name:         name,
			MemberCount:  chain.MemberCount(),
			BlockCount:   chain.Len(),
			Environments: envs,
			Dissolved:    chain.IsDissolved(),
		})
	}

	// Sort by name
	sort.Slice(projects, func(i, j int) bool {
		return projects[i].Name < projects[j].Name
	})

	ws.jsonResponse(w, projects)
}

func (ws *WebServer) handleProjectDetail(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		ws.errorResponse(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	// Extract project name from path: /api/projects/{name}/members
	path := strings.TrimPrefix(r.URL.Path, "/api/projects/")
	parts := strings.Split(path, "/")

	if len(parts) < 1 || parts[0] == "" {
		ws.errorResponse(w, http.StatusBadRequest, "project name required")
		return
	}

	projectName := parts[0]

	chain := ws.daemon.GetChain(projectName)
	if chain == nil {
		ws.errorResponse(w, http.StatusNotFound, "project not found")
		return
	}

	// Check if requesting members
	if len(parts) >= 2 && parts[1] == "members" {
		ws.handleProjectMembers(w, r, projectName, chain)
		return
	}

	// Return project info
	policy := chain.Policy()
	var envs []string
	if policy != nil {
		envs = policy.Environments
	}

	ws.jsonResponse(w, map[string]interface{}{
		"name":         projectName,
		"member_count": chain.MemberCount(),
		"block_count":  chain.Len(),
		"environments": envs,
		"dissolved":    chain.IsDissolved(),
	})
}

func (ws *WebServer) handleProjectMembers(w http.ResponseWriter, r *http.Request, projectName string, c *chain.Chain) {
	members := c.Members()

	type memberWithStatus struct {
		Name         string    `json:"name"`
		Fingerprint  string    `json:"fingerprint"`
		Role         string    `json:"role"`
		Environments []string  `json:"environments"`
		Online       bool      `json:"online"`
		LastSeen     time.Time `json:"last_seen,omitempty"`
	}

	result := make([]memberWithStatus, 0, len(members))

	// Our own signing key for comparison
	ourPubkey := ws.daemon.Identity().SigningPublicKey()

	for _, m := range members {
		pubkeyHex := hex.EncodeToString(m.SigningPub)

		// Compute fingerprint from signing public key
		hash := sha256.Sum256(m.SigningPub)
		fingerprint := fmt.Sprintf("%x", hash[:8])

		// Check if this member is connected as a peer
		online := ws.daemon.PeerManager().IsConnected(pubkeyHex)
		lastSeen := ws.daemon.PeerManager().LastSeen(pubkeyHex)

		// Check if this is ourselves (always online)
		if hex.EncodeToString(m.SigningPub) == hex.EncodeToString(ourPubkey) {
			online = true
			lastSeen = time.Now()
		}

		result = append(result, memberWithStatus{
			Name:         m.Name,
			Fingerprint:  fingerprint,
			Role:         string(m.Role),
			Environments: m.Environments,
			Online:       online,
			LastSeen:     lastSeen,
		})
	}

	// Sort: online first, then by name
	sort.Slice(result, func(i, j int) bool {
		if result[i].Online != result[j].Online {
			return result[i].Online // Online members first
		}
		return result[i].Name < result[j].Name
	})

	ws.jsonResponse(w, result)
}

func (ws *WebServer) handleRequests(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		// List all incoming requests
		requests := ws.daemon.IncomingRequests().List()

		type requestInfo struct {
			ID          string    `json:"id"`
			Team        string    `json:"team"`
			Env         string    `json:"env"`
			From        string    `json:"from"`
			Fingerprint string    `json:"fingerprint"`
			ReceivedAt  time.Time `json:"received_at"`
		}

		result := make([]requestInfo, 0, len(requests))
		for _, req := range requests {
			result = append(result, requestInfo{
				ID:          req.ID,
				Team:        req.Team,
				Env:         req.Env,
				From:        req.From,
				Fingerprint: req.Fingerprint,
				ReceivedAt:  req.ReceivedAt,
			})
		}

		// Sort by received time (newest first)
		sort.Slice(result, func(i, j int) bool {
			return result[i].ReceivedAt.After(result[j].ReceivedAt)
		})

		ws.jsonResponse(w, result)

	case http.MethodPost:
		// Approve or deny a request
		var body struct {
			ID     string `json:"id"`
			Action string `json:"action"` // "approve" or "deny"
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			ws.errorResponse(w, http.StatusBadRequest, "invalid request body")
			return
		}

		req, ok := ws.daemon.IncomingRequests().Get(body.ID)
		if !ok {
			ws.errorResponse(w, http.StatusNotFound, "request not found")
			return
		}

		if body.Action == "deny" {
			ws.daemon.IncomingRequests().Remove(body.ID)
			ws.jsonResponse(w, map[string]interface{}{
				"status": "denied",
				"id":     body.ID,
			})
			return
		}

		if body.Action != "approve" {
			ws.errorResponse(w, http.StatusBadRequest, "action must be 'approve' or 'deny'")
			return
		}

		// For approval, we need to send the environment to the requester
		// This requires finding the peer and sending them the env
		// For now, just acknowledge the approval
		ws.daemon.IncomingRequests().Remove(body.ID)

		ws.jsonResponse(w, map[string]interface{}{
			"status": "approved",
			"id":     body.ID,
			"team":   req.Team,
			"env":    req.Env,
			"to":     req.From,
		})

	default:
		ws.errorResponse(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (ws *WebServer) handleAudit(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		ws.errorResponse(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	opts := audit.QueryOpts{
		Limit: 500,
	}

	q := r.URL.Query()

	if level := q.Get("level"); level != "" {
		opts.Level = strings.ToUpper(level)
	}

	if category := q.Get("category"); category != "" {
		opts.Category = category
	}

	if project := q.Get("project"); project != "" {
		opts.Project = project
	}

	if search := q.Get("search"); search != "" {
		opts.Search = search
	}

	if since := q.Get("since"); since != "" {
		if t, err := time.Parse(time.RFC3339, since); err == nil {
			opts.Since = &t
		}
	}

	if until := q.Get("until"); until != "" {
		if t, err := time.Parse(time.RFC3339, until); err == nil {
			opts.Until = &t
		}
	}

	if limit := q.Get("limit"); limit != "" {
		if n, err := strconv.Atoi(limit); err == nil && n > 0 && n <= 5000 {
			opts.Limit = n
		}
	}

	events := audit.Default().Query(opts)
	categories := audit.Default().CategoryCounts()

	ws.jsonResponse(w, map[string]any{
		"events":     events,
		"count":      len(events),
		"categories": categories,
	})
}

func (ws *WebServer) handleLogs(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		ws.errorResponse(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	opts := QueryOpts{
		Limit: 500, // Default limit
	}

	// Parse query parameters
	q := r.URL.Query()

	if level := q.Get("level"); level != "" {
		opts.Level = strings.ToUpper(level)
	}

	if since := q.Get("since"); since != "" {
		t, err := time.Parse(time.RFC3339, since)
		if err == nil {
			opts.Since = &t
		}
	}

	if until := q.Get("until"); until != "" {
		t, err := time.Parse(time.RFC3339, until)
		if err == nil {
			opts.Until = &t
		}
	}

	if limit := q.Get("limit"); limit != "" {
		if n, err := strconv.Atoi(limit); err == nil && n > 0 && n <= 5000 {
			opts.Limit = n
		}
	}

	entries := ws.daemon.LogBuffer().Query(opts)

	ws.jsonResponse(w, map[string]any{
		"entries": entries,
		"count":   len(entries),
		"total":   ws.daemon.LogBuffer().Count(),
	})
}

func (ws *WebServer) handleLogStats(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		ws.errorResponse(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	// Count by level
	all := ws.daemon.LogBuffer().Query(QueryOpts{})

	stats := map[string]int{
		"total": len(all),
		"debug": 0,
		"info":  0,
		"warn":  0,
		"error": 0,
	}

	for _, entry := range all {
		switch entry.Level {
		case "DEBUG":
			stats["debug"]++
		case "INFO":
			stats["info"]++
		case "WARN":
			stats["warn"]++
		case "ERROR":
			stats["error"]++
		}
	}

	ws.jsonResponse(w, stats)
}

// WebSocket handling

func (ws *WebServer) handleWebSocket(w http.ResponseWriter, r *http.Request) {
	conn, err := ws.upgrader.Upgrade(w, r, nil)
	if err != nil {
		slog.Error("WebSocket upgrade failed", "error", err)
		return
	}

	ws.clients[conn] = true
	defer func() {
		delete(ws.clients, conn)
		conn.Close()
	}()

	// Keep connection alive
	for {
		_, _, err := conn.ReadMessage()
		if err != nil {
			break
		}
	}
}

// BroadcastEvent sends an event to all WebSocket clients
func (ws *WebServer) BroadcastEvent(event string, payload interface{}) {
	data := map[string]interface{}{
		"event":   event,
		"payload": payload,
	}

	msg, err := json.Marshal(data)
	if err != nil {
		return
	}

	for client := range ws.clients {
		client.WriteMessage(websocket.TextMessage, msg)
	}
}

// Helper methods

func (ws *WebServer) jsonResponse(w http.ResponseWriter, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(data)
}

func (ws *WebServer) errorResponse(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]string{"error": message})
}

// corsMiddleware adds CORS headers (for development)
func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if origin != "" && strings.HasPrefix(origin, "http://localhost") {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		}

		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusNoContent)
			return
		}

		next.ServeHTTP(w, r)
	})
}
