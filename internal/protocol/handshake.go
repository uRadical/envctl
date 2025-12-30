package protocol

import (
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"uradical.io/go/envctl/internal/crypto"
)

// HandshakeTimeout is the maximum time allowed for a handshake
const HandshakeTimeout = 30 * time.Second

// WriteMessage writes a message to a connection
func WriteMessage(conn net.Conn, msg *Message) error {
	framer := NewFramer(nil, conn)
	return framer.WriteMessage(msg)
}

// ReadMessage reads a message from a connection
func ReadMessage(conn net.Conn) (*Message, error) {
	framer := NewFramer(conn, nil)
	return framer.ReadMessage()
}

// WriteMessageTo writes a message to a writer
func WriteMessageTo(w io.Writer, msg *Message) error {
	framer := NewFramer(nil, w)
	return framer.WriteMessage(msg)
}

// ReadMessageFrom reads a message from a reader
func ReadMessageFrom(r io.Reader) (*Message, error) {
	framer := NewFramer(r, nil)
	return framer.ReadMessage()
}

// NewHandshakeFromIdentity creates a handshake from an identity and team list
func NewHandshakeFromIdentity(identity *crypto.Identity, teams []string) *Handshake {
	return &Handshake{
		Version:    ProtocolVersion,
		MinVersion: MinProtocolVersion,
		Pubkey:     identity.SigningPublicKey(),
		MLKEMPub:   identity.MLKEMPublicKey(),
		Name:       identity.Name,
		Teams:      teams,
		Addresses:  nil, // Will be set by caller if needed
	}
}

// Compatible checks if this handshake is compatible with another
func (h *Handshake) Compatible(other *Handshake) error {
	if other == nil {
		return errors.New("nil handshake")
	}

	// Check version compatibility
	if !isVersionCompatible(h.Version, other.MinVersion) {
		return fmt.Errorf("our version %s is below their minimum %s", h.Version, other.MinVersion)
	}

	if !isVersionCompatible(other.Version, h.MinVersion) {
		return fmt.Errorf("their version %s is below our minimum %s", other.Version, h.MinVersion)
	}

	// Check for required fields
	if len(other.Pubkey) == 0 {
		return errors.New("missing public key")
	}

	if len(other.MLKEMPub) == 0 {
		return errors.New("missing ML-KEM public key")
	}

	if other.Name == "" {
		return errors.New("missing name")
	}

	return nil
}

// SharedTeams returns the teams that both handshakes have in common
func (h *Handshake) SharedTeams(other *Handshake) []string {
	if other == nil {
		return nil
	}

	teamSet := make(map[string]bool)
	for _, t := range h.Teams {
		teamSet[t] = true
	}

	shared := make([]string, 0)
	for _, t := range other.Teams {
		if teamSet[t] {
			shared = append(shared, t)
		}
	}

	return shared
}

// PerformHandshake performs a handshake with a peer over a connection
func PerformHandshake(conn net.Conn, ours *Handshake) (*Handshake, error) {
	// Set handshake deadline
	conn.SetDeadline(time.Now().Add(HandshakeTimeout))
	defer conn.SetDeadline(time.Time{})

	// Create message with our handshake
	msg, err := NewMessage(MsgHandshake, ours)
	if err != nil {
		return nil, fmt.Errorf("create handshake message: %w", err)
	}

	// Send our handshake
	if err := WriteMessage(conn, msg); err != nil {
		return nil, fmt.Errorf("send handshake: %w", err)
	}

	// Receive their handshake
	theirMsg, err := ReadMessage(conn)
	if err != nil {
		return nil, fmt.Errorf("receive handshake: %w", err)
	}

	if theirMsg.Type != MsgHandshake {
		return nil, fmt.Errorf("expected handshake, got %s", theirMsg.Type)
	}

	var theirs Handshake
	if err := theirMsg.ParsePayload(&theirs); err != nil {
		return nil, fmt.Errorf("parse handshake: %w", err)
	}

	// Check compatibility
	if err := ours.Compatible(&theirs); err != nil {
		// Send reject message
		reject, _ := NewMessage(MsgReject, Reject{
			Reason: err.Error(),
			Code:   RejectCodeVersionMismatch,
		})
		WriteMessage(conn, reject)
		return nil, fmt.Errorf("incompatible: %w", err)
	}

	return &theirs, nil
}

// isVersionCompatible checks if version meets minimum requirement
// Uses proper semantic versioning comparison
func isVersionCompatible(version, minVersion string) bool {
	v, err := parseVersion(version)
	if err != nil {
		return false
	}
	min, err := parseVersion(minVersion)
	if err != nil {
		return false
	}
	return v.Compare(min) >= 0
}

// Version represents a semantic version
type Version struct {
	Major int
	Minor int
	Patch int
}

// parseVersion parses a version string like "1.2.3"
func parseVersion(s string) (Version, error) {
	var v Version
	parts := strings.Split(s, ".")
	if len(parts) < 1 || len(parts) > 3 {
		return v, fmt.Errorf("invalid version format: %s", s)
	}

	var err error
	if v.Major, err = parseVersionPart(parts[0]); err != nil {
		return v, err
	}

	if len(parts) >= 2 {
		if v.Minor, err = parseVersionPart(parts[1]); err != nil {
			return v, err
		}
	}

	if len(parts) >= 3 {
		if v.Patch, err = parseVersionPart(parts[2]); err != nil {
			return v, err
		}
	}

	return v, nil
}

// parseVersionPart parses a single version part, stripping any suffix
func parseVersionPart(s string) (int, error) {
	// Strip any suffix like "-beta", "-rc1", etc.
	for i, c := range s {
		if c < '0' || c > '9' {
			s = s[:i]
			break
		}
	}
	if s == "" {
		return 0, nil
	}

	n := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, fmt.Errorf("invalid version number: %s", s)
		}
		n = n*10 + int(c-'0')
	}
	return n, nil
}

// Compare compares two versions
// Returns -1 if v < other, 0 if equal, 1 if v > other
func (v Version) Compare(other Version) int {
	if v.Major != other.Major {
		if v.Major < other.Major {
			return -1
		}
		return 1
	}
	if v.Minor != other.Minor {
		if v.Minor < other.Minor {
			return -1
		}
		return 1
	}
	if v.Patch != other.Patch {
		if v.Patch < other.Patch {
			return -1
		}
		return 1
	}
	return 0
}

// String returns the version as a string
func (v Version) String() string {
	return fmt.Sprintf("%d.%d.%d", v.Major, v.Minor, v.Patch)
}

// AddAddress adds an address to the handshake
func (h *Handshake) AddAddress(addrType, addr string, pubkey []byte) {
	h.Addresses = append(h.Addresses, PeerAddr{
		Type:   addrType,
		Addr:   addr,
		Pubkey: pubkey,
	})
}

// GetAddress returns the first address of a given type
func (h *Handshake) GetAddress(addrType string) *PeerAddr {
	for i := range h.Addresses {
		if h.Addresses[i].Type == addrType {
			return &h.Addresses[i]
		}
	}
	return nil
}

// Clone returns a deep copy of the handshake
func (h *Handshake) Clone() *Handshake {
	clone := *h

	clone.Pubkey = make([]byte, len(h.Pubkey))
	copy(clone.Pubkey, h.Pubkey)

	clone.MLKEMPub = make([]byte, len(h.MLKEMPub))
	copy(clone.MLKEMPub, h.MLKEMPub)

	clone.Teams = make([]string, len(h.Teams))
	copy(clone.Teams, h.Teams)

	clone.Addresses = make([]PeerAddr, len(h.Addresses))
	for i, addr := range h.Addresses {
		clone.Addresses[i] = addr
		clone.Addresses[i].Pubkey = make([]byte, len(addr.Pubkey))
		copy(clone.Addresses[i].Pubkey, addr.Pubkey)
	}

	return &clone
}
