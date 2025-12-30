package protocol

import (
	"bytes"
	"crypto/ed25519"
	"encoding/binary"
	"encoding/json"
	"errors"
	"time"
)

// Version information
const (
	ProtocolVersion    = "1.0.0"
	MinProtocolVersion = "1.0.0"
)

// MessageType identifies the type of P2P message
type MessageType string

const (
	MsgHandshake       MessageType = "handshake"
	MsgChainHead       MessageType = "chain_head"
	MsgGetBlocks       MessageType = "get_blocks"
	MsgBlocks          MessageType = "blocks"
	MsgProposal        MessageType = "proposal"
	MsgApproval        MessageType = "approval"
	MsgRequest         MessageType = "request"          // Env request
	MsgOffer           MessageType = "offer"            // Env offer
	MsgPayload         MessageType = "payload"          // Encrypted env
	MsgAck             MessageType = "ack"
	MsgEnvUpdated      MessageType = "env_updated"      // Staleness notification
	MsgReject          MessageType = "reject"
	MsgPing            MessageType = "ping"
	MsgPong            MessageType = "pong"
	MsgChainRequest    MessageType = "chain_request"    // Request chain by invite code
	MsgChainResponse   MessageType = "chain_response"   // Full chain response
	MsgJoinRequest     MessageType = "join_request"     // New member wants to join
	MsgJoinApproved    MessageType = "join_approved"    // Join request was approved

	// Ops chain messages
	MsgOpsHead         MessageType = "ops_head"         // Announce ops chain head
	MsgOpsGetOps       MessageType = "ops_get_ops"      // Request operations from peer
	MsgOpsOps          MessageType = "ops_ops"          // Operations response
	MsgOpsPush         MessageType = "ops_push"         // Push operations to peer
	MsgOpsAck          MessageType = "ops_ack"          // Acknowledge ops receipt
)

// Message is a P2P protocol message
type Message struct {
	Type      MessageType     `json:"type"`
	Timestamp time.Time       `json:"timestamp"`
	Payload   json.RawMessage `json:"payload"`
	From      []byte          `json:"from,omitempty"`      // Sender's Ed25519 public key
	Nonce     uint64          `json:"nonce,omitempty"`     // Monotonic sequence number for replay protection
	Signature []byte          `json:"signature,omitempty"` // Ed25519 signature over (Type || Timestamp || Nonce || Payload)
}

// NewMessage creates a new message with the given payload
func NewMessage(msgType MessageType, payload interface{}) (*Message, error) {
	data, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}

	return &Message{
		Type:      msgType,
		Timestamp: time.Now().UTC(),
		Payload:   data,
	}, nil
}

// ParsePayload unmarshals the message payload
func (m *Message) ParsePayload(v interface{}) error {
	return json.Unmarshal(m.Payload, v)
}

// SigningData returns the canonical bytes to be signed for this message.
// Format: Type (length-prefixed) || Timestamp (Unix nano, 8 bytes) || Nonce (8 bytes) || Payload
func (m *Message) SigningData() []byte {
	var buf bytes.Buffer

	// Write type as length-prefixed string
	typeBytes := []byte(m.Type)
	binary.Write(&buf, binary.BigEndian, uint32(len(typeBytes)))
	buf.Write(typeBytes)

	// Write timestamp as Unix nanoseconds (8 bytes, big-endian)
	binary.Write(&buf, binary.BigEndian, m.Timestamp.UnixNano())

	// Write nonce (8 bytes, big-endian)
	binary.Write(&buf, binary.BigEndian, m.Nonce)

	// Write payload
	buf.Write(m.Payload)

	return buf.Bytes()
}

// Sign signs the message with the given Ed25519 private key and sets From/Signature fields.
func (m *Message) Sign(privateKey ed25519.PrivateKey) {
	m.From = privateKey.Public().(ed25519.PublicKey)
	m.Signature = ed25519.Sign(privateKey, m.SigningData())
}

// Verify verifies the message signature against the From public key.
// Returns nil if valid, error otherwise.
func (m *Message) Verify() error {
	if len(m.From) != ed25519.PublicKeySize {
		return errors.New("missing or invalid sender public key")
	}
	if len(m.Signature) != ed25519.SignatureSize {
		return errors.New("missing or invalid signature")
	}

	if !ed25519.Verify(m.From, m.SigningData(), m.Signature) {
		return errors.New("invalid message signature")
	}

	return nil
}

// VerifyFrom verifies the signature and that the message is from the expected sender.
func (m *Message) VerifyFrom(expectedPubKey []byte) error {
	if err := m.Verify(); err != nil {
		return err
	}

	if !bytes.Equal(m.From, expectedPubKey) {
		return errors.New("message sender does not match expected peer")
	}

	return nil
}

// IsSigned returns true if the message has signature fields set.
func (m *Message) IsSigned() bool {
	return len(m.From) > 0 && len(m.Signature) > 0
}

// PeerAddr represents how to reach a peer
type PeerAddr struct {
	Type   string `json:"type"`   // "direct", "mdns", "relay" (future)
	Addr   string `json:"addr"`   // host:port or other address
	Pubkey []byte `json:"pubkey"` // signing public key
}

// Handshake is exchanged when peers connect
type Handshake struct {
	Version    string     `json:"version"`
	MinVersion string     `json:"min_version"`
	Pubkey     []byte     `json:"pubkey"`     // Signing public key (identity)
	MLKEMPub   []byte     `json:"mlkem_pub"`  // ML-KEM public key
	Name       string     `json:"name"`
	Teams      []string   `json:"teams"`      // Teams this peer belongs to
	Addresses  []PeerAddr `json:"addresses"`  // How to reach this peer
}

// NewHandshake creates a handshake message
func NewHandshake(name string, pubkey, mlkemPub []byte, teams []string) *Handshake {
	return &Handshake{
		Version:    ProtocolVersion,
		MinVersion: MinProtocolVersion,
		Pubkey:     pubkey,
		MLKEMPub:   mlkemPub,
		Name:       name,
		Teams:      teams,
	}
}

// ChainHead represents the head of a team's chain
type ChainHead struct {
	Team   string `json:"team"`
	Index  uint64 `json:"index"`
	Hash   []byte `json:"hash"`
}

// GetBlocks requests blocks from a peer
type GetBlocks struct {
	Team        string `json:"team"`
	StartIndex  uint64 `json:"start_index"`
	MaxBlocks   int    `json:"max_blocks,omitempty"`
	ForConflict bool   `json:"for_conflict,omitempty"` // True if requesting for conflict resolution
}

// Blocks is a response containing requested blocks
type Blocks struct {
	Team        string          `json:"team"`
	Blocks      json.RawMessage `json:"blocks"` // []*chain.Block
	ForConflict bool            `json:"for_conflict,omitempty"` // True if this is for conflict resolution
}

// Proposal is a new block proposal
type Proposal struct {
	Team  string          `json:"team"`
	Block json.RawMessage `json:"block"`
}

// Approval is an approval for a proposal
type Approval struct {
	Team      string    `json:"team"`
	BlockHash []byte    `json:"block_hash"`
	By        []byte    `json:"by"`      // Approver's public key
	SigAlgo   string    `json:"sig_algo"`
	Signature []byte    `json:"signature"`
	Timestamp time.Time `json:"timestamp"`
}

// EnvRequest is a request for environment variables
type EnvRequest struct {
	ID        string    `json:"id"`
	Team      string    `json:"team"`
	Env       string    `json:"env"`
	From      []byte    `json:"from"`     // Requester's public key
	Timestamp time.Time `json:"timestamp"`
}

// EnvOffer is an offer to share environment variables
type EnvOffer struct {
	RequestID string   `json:"request_id"`
	Team      string   `json:"team"`
	Env       string   `json:"env"`
	From      []byte   `json:"from"`      // Sender's public key
	VarCount  int      `json:"var_count"` // Number of variables
}

// EnvPayload is the encrypted environment data
type EnvPayload struct {
	RequestID  string `json:"request_id"`
	Team       string `json:"team"`
	Env        string `json:"env"`
	From       []byte `json:"from"`
	Ciphertext []byte `json:"ciphertext"` // Encrypted for recipient
}

// EnvUpdated notifies a peer that their env is stale
type EnvUpdated struct {
	Team      string    `json:"team"`
	Env       string    `json:"env"`
	UpdatedBy []byte    `json:"updated_by"` // Who updated it
	Timestamp time.Time `json:"timestamp"`
}

// Reject indicates a request was rejected
type Reject struct {
	RequestID string `json:"request_id,omitempty"`
	Reason    string `json:"reason"`
	Code      string `json:"code,omitempty"`
}

// Common rejection codes
const (
	RejectCodeNotMember      = "not_member"
	RejectCodeNoAccess       = "no_access"
	RejectCodeVersionMismatch = "version_mismatch"
	RejectCodeInvalidRequest = "invalid_request"
	RejectCodeRateLimited    = "rate_limited"
)

// Ack acknowledges receipt of a message
type Ack struct {
	MessageID string `json:"message_id,omitempty"`
	RequestID string `json:"request_id,omitempty"`
}

// ChainRequest requests a chain by invite code
type ChainRequest struct {
	RequestID  string `json:"request_id"`
	InviteCode string `json:"invite_code"` // Normalized invite code
	PubKeyHash string `json:"pubkey_hash"` // SHA256 of requester's signing pubkey
}

// ChainResponse contains a full chain for a new joiner
type ChainResponse struct {
	RequestID   string          `json:"request_id"`
	Team        string          `json:"team"`
	Found       bool            `json:"found"`
	Blocks      json.RawMessage `json:"blocks,omitempty"` // Full chain
	Error       string          `json:"error,omitempty"`
}

// JoinRequest is sent by a new member to join after receiving the chain
type JoinRequest struct {
	RequestID  string `json:"request_id"`
	Team       string `json:"team"`
	InviteCode string `json:"invite_code"`
	Name       string `json:"name"`       // Display name
	SigningPub []byte `json:"signing_pub"` // Ed25519 public key
	MLKEMPub   []byte `json:"mlkem_pub"`   // ML-KEM public key
}

// JoinApproved indicates the join was successful
type JoinApproved struct {
	RequestID string          `json:"request_id"`
	Team      string          `json:"team"`
	Block     json.RawMessage `json:"block"` // The member-add block
}

// OpsHead announces the head of an ops chain
type OpsHead struct {
	Project     string `json:"project"`
	Environment string `json:"environment"`
	Seq         uint64 `json:"seq"`       // Head sequence number
	Hash        []byte `json:"hash"`      // Head operation hash
}

// OpsGetOps requests operations from a peer
type OpsGetOps struct {
	RequestID   string `json:"request_id"`
	Project     string `json:"project"`
	Environment string `json:"environment"`
	FromSeq     uint64 `json:"from_seq"` // Start from this sequence
}

// OpsOperation represents a single operation for wire transfer
// We send both the original encrypted value (for signature verification) and
// the plaintext value (for the recipient to cache, since they can't decrypt it)
type OpsOperation struct {
	Seq            uint64 `json:"seq"`
	Timestamp      int64  `json:"timestamp"` // Unix nano
	Author         []byte `json:"author"`
	Op             string `json:"op"` // "set" or "delete"
	Key            string `json:"key"`
	EncryptedValue []byte `json:"encrypted_value,omitempty"` // Original encrypted value (for signature verification)
	Value          string `json:"value,omitempty"`           // Plaintext value (for recipient to cache)
	PrevHash       []byte `json:"prev_hash,omitempty"`
	Signature      []byte `json:"signature"`
}

// OpsOps is a response containing operations
type OpsOps struct {
	RequestID   string          `json:"request_id"`
	Project     string          `json:"project"`
	Environment string          `json:"environment"`
	Operations  []OpsOperation  `json:"operations"`
}

// OpsPush pushes operations to a peer
type OpsPush struct {
	RequestID   string          `json:"request_id"`
	Project     string          `json:"project"`
	Environment string          `json:"environment"`
	Operations  []OpsOperation  `json:"operations"`
}

// OpsAck acknowledges receipt of operations
type OpsAck struct {
	RequestID   string `json:"request_id"`
	Received    int    `json:"received"`    // Number of ops received
	NewHeadSeq  uint64 `json:"new_head_seq"`
	Error       string `json:"error,omitempty"`
}
