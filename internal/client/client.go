package client

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"uradical.io/go/envctl/internal/config"
)

// Client is an IPC client for communicating with the daemon
type Client struct {
	conn    net.Conn
	reader  *bufio.Reader
	writer  *bufio.Writer
	mu      sync.Mutex
	reqID   uint64
	timeout time.Duration
}

// Request represents an IPC request
type Request struct {
	ID     string          `json:"id"`
	Method string          `json:"method"`
	Params json.RawMessage `json:"params,omitempty"`
}

// Response represents an IPC response
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

// Progress represents progress information
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

// Status represents daemon status
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

// Connect creates a new IPC client connected to the daemon
func Connect() (*Client, error) {
	paths, err := config.GetPaths()
	if err != nil {
		return nil, fmt.Errorf("get paths: %w", err)
	}

	return ConnectTo(paths.SocketPath)
}

// ConnectTo creates a new IPC client connected to a specific socket
func ConnectTo(socketPath string) (*Client, error) {
	var network string
	var address string

	if runtime.GOOS == "windows" {
		network = "tcp"
		address = "127.0.0.1:7836"
	} else {
		network = "unix"
		address = socketPath
	}

	conn, err := net.DialTimeout(network, address, 5*time.Second)
	if err != nil {
		return nil, fmt.Errorf("connect to daemon: %w", err)
	}

	return &Client{
		conn:    conn,
		reader:  bufio.NewReader(conn),
		writer:  bufio.NewWriter(conn),
		timeout: 30 * time.Second,
	}, nil
}

// Close closes the client connection
func (c *Client) Close() error {
	return c.conn.Close()
}

// Call makes an IPC call and returns the result
func (c *Client) Call(method string, params interface{}) (json.RawMessage, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Generate request ID
	id := fmt.Sprintf("%d", atomic.AddUint64(&c.reqID, 1))

	// Encode params
	var paramsJSON json.RawMessage
	if params != nil {
		var err error
		paramsJSON, err = json.Marshal(params)
		if err != nil {
			return nil, fmt.Errorf("marshal params: %w", err)
		}
	}

	// Create request
	req := Request{
		ID:     id,
		Method: method,
		Params: paramsJSON,
	}

	// Set deadline
	c.conn.SetDeadline(time.Now().Add(c.timeout))
	defer c.conn.SetDeadline(time.Time{})

	// Send request
	encoder := json.NewEncoder(c.writer)
	if err := encoder.Encode(req); err != nil {
		return nil, fmt.Errorf("send request: %w", err)
	}
	if err := c.writer.Flush(); err != nil {
		return nil, fmt.Errorf("flush: %w", err)
	}

	// Read response
	decoder := json.NewDecoder(c.reader)
	var resp Response
	if err := decoder.Decode(&resp); err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	// Check for error
	if resp.Error != nil {
		return nil, fmt.Errorf("%s (code %d)", resp.Error.Message, resp.Error.Code)
	}

	return resp.Result, nil
}

// CallResult makes an IPC call and unmarshals the result
func (c *Client) CallResult(method string, params interface{}, result interface{}) error {
	raw, err := c.Call(method, params)
	if err != nil {
		return err
	}

	if result != nil {
		if err := json.Unmarshal(raw, result); err != nil {
			return fmt.Errorf("unmarshal result: %w", err)
		}
	}

	return nil
}

// Status gets the daemon status
func (c *Client) Status() (*Status, error) {
	var status Status
	if err := c.CallResult("status", nil, &status); err != nil {
		return nil, err
	}
	return &status, nil
}

// Subscribe subscribes to events
func (c *Client) Subscribe() error {
	_, err := c.Call("subscribe", nil)
	return err
}

// ReadEvent reads the next event (blocking)
func (c *Client) ReadEvent() (*Event, error) {
	decoder := json.NewDecoder(c.reader)
	var event Event
	if err := decoder.Decode(&event); err != nil {
		return nil, err
	}
	return &event, nil
}

// IsRunning checks if the daemon is running by attempting to connect
func IsRunning() bool {
	client, err := Connect()
	if err != nil {
		return false
	}
	defer client.Close()

	_, err = client.Status()
	return err == nil
}

// Ping checks if the daemon is responsive
func (c *Client) Ping() error {
	_, err := c.Status()
	return err
}

// SetTimeout sets the request timeout
func (c *Client) SetTimeout(d time.Duration) {
	c.mu.Lock()
	c.timeout = d
	c.mu.Unlock()
}

// ErrDaemonNotRunning is returned when the daemon is not running
var ErrDaemonNotRunning = errors.New("daemon is not running")

// RequireDaemon returns an error if the daemon is not running
func RequireDaemon() error {
	if !IsRunning() {
		return ErrDaemonNotRunning
	}
	return nil
}

// BroadcastKeyRotation broadcasts a key rotation announcement to peers
func (c *Client) BroadcastKeyRotation(ann any) error {
	_, err := c.Call("identity.broadcast_rotation", ann)
	return err
}

// ReloadChains tells the daemon to reload chain files from disk
func (c *Client) ReloadChains() error {
	_, err := c.Call("chains.reload", nil)
	return err
}

// NotifyChainChange tells the daemon to reload chains if running (ignores errors if daemon not running)
func NotifyChainChange() {
	client, err := Connect()
	if err != nil {
		return // Daemon not running, that's fine
	}
	defer client.Close()
	client.ReloadChains()
}

// Lease represents an active environment lease
type Lease struct {
	ID          string    `json:"id"`
	ProjectDir  string    `json:"project_dir"`
	ProjectName string    `json:"project_name"`
	Environment string    `json:"environment"`
	DotEnvPath  string    `json:"dotenv_path"`
	GrantedAt   time.Time `json:"granted_at"`
	ExpiresAt   time.Time `json:"expires_at"`
	TTL         string    `json:"ttl"`
}

// LeaseGrant registers a new environment lease with TTL
func (c *Client) LeaseGrant(projectDir, projectName, env, dotEnvPath string, ttl time.Duration) (*Lease, error) {
	params := map[string]any{
		"project_dir":  projectDir,
		"project_name": projectName,
		"environment":  env,
		"dotenv_path":  dotEnvPath,
		"ttl_seconds":  ttl.Seconds(),
	}
	var lease Lease
	if err := c.CallResult("lease.grant", params, &lease); err != nil {
		return nil, err
	}
	return &lease, nil
}

// LeaseRevoke immediately revokes a lease and cleans up the .env
func (c *Client) LeaseRevoke(projectDir, env string) error {
	params := map[string]any{
		"project_dir": projectDir,
		"environment": env,
	}
	_, err := c.Call("lease.revoke", params)
	return err
}

// LeaseExtend extends an existing lease
func (c *Client) LeaseExtend(projectDir, env string, extension time.Duration) (*Lease, error) {
	params := map[string]any{
		"project_dir":     projectDir,
		"environment":     env,
		"extend_seconds":  extension.Seconds(),
	}
	var lease Lease
	if err := c.CallResult("lease.extend", params, &lease); err != nil {
		return nil, err
	}
	return &lease, nil
}

// LeaseGet gets an active lease by project and environment
func (c *Client) LeaseGet(projectDir, env string) (*Lease, error) {
	params := map[string]any{
		"project_dir": projectDir,
		"environment": env,
	}
	var lease Lease
	if err := c.CallResult("lease.get", params, &lease); err != nil {
		return nil, err
	}
	return &lease, nil
}

// LeaseList lists all active leases
func (c *Client) LeaseList() ([]*Lease, error) {
	var leases []*Lease
	if err := c.CallResult("lease.list", nil, &leases); err != nil {
		return nil, err
	}
	return leases, nil
}
