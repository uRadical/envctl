package protocol

import (
	"bytes"
	"testing"
	"time"
)

func TestFramerWriteRead(t *testing.T) {
	// Create a buffer for read/write
	buf := &bytes.Buffer{}
	framer := NewFramer(buf, buf)

	// Create a test message
	msg, err := NewMessage(MsgPing, struct{}{})
	if err != nil {
		t.Fatalf("Failed to create message: %v", err)
	}

	// Write the message
	if err := framer.WriteMessage(msg); err != nil {
		t.Fatalf("Failed to write message: %v", err)
	}

	// Read it back
	framer2 := NewFramer(bytes.NewReader(buf.Bytes()), nil)
	readMsg, err := framer2.ReadMessage()
	if err != nil {
		t.Fatalf("Failed to read message: %v", err)
	}

	// Verify
	if readMsg.Type != MsgPing {
		t.Errorf("Expected type %s, got %s", MsgPing, readMsg.Type)
	}
}

func TestFramerRoundTrip(t *testing.T) {
	testCases := []struct {
		name    string
		msgType MessageType
		payload interface{}
	}{
		{
			name:    "ping",
			msgType: MsgPing,
			payload: struct{}{},
		},
		{
			name:    "handshake",
			msgType: MsgHandshake,
			payload: &Handshake{
				Version:    ProtocolVersion,
				MinVersion: MinProtocolVersion,
				Pubkey:     []byte("test-pubkey-1234567890abcdef"),
				MLKEMPub:   []byte("test-mlkem-pub-key-bytes"),
				Name:       "alice",
				Teams:      []string{"team1", "team2"},
			},
		},
		{
			name:    "chain_head",
			msgType: MsgChainHead,
			payload: ChainHead{
				Team:  "myteam",
				Index: 42,
				Hash:  []byte("block-hash-here"),
			},
		},
		{
			name:    "get_blocks",
			msgType: MsgGetBlocks,
			payload: GetBlocks{
				Team:       "myteam",
				StartIndex: 10,
				MaxBlocks:  50,
			},
		},
		{
			name:    "env_request",
			msgType: MsgRequest,
			payload: EnvRequest{
				ID:        "req-123",
				Team:      "myteam",
				Env:       "dev",
				From:      []byte("requester-pubkey"),
				Timestamp: time.Now().UTC(),
			},
		},
		{
			name:    "reject",
			msgType: MsgReject,
			payload: Reject{
				RequestID: "req-123",
				Reason:    "not a member",
				Code:      RejectCodeNotMember,
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			buf := &bytes.Buffer{}
			framer := NewFramer(buf, buf)

			// Create and write message
			msg, err := NewMessage(tc.msgType, tc.payload)
			if err != nil {
				t.Fatalf("Failed to create message: %v", err)
			}

			if err := framer.WriteMessage(msg); err != nil {
				t.Fatalf("Failed to write message: %v", err)
			}

			// Read it back
			framer2 := NewFramer(bytes.NewReader(buf.Bytes()), nil)
			readMsg, err := framer2.ReadMessage()
			if err != nil {
				t.Fatalf("Failed to read message: %v", err)
			}

			// Verify type
			if readMsg.Type != tc.msgType {
				t.Errorf("Expected type %s, got %s", tc.msgType, readMsg.Type)
			}
		})
	}
}

func TestFramerLargeMessage(t *testing.T) {
	buf := &bytes.Buffer{}
	framer := NewFramer(buf, buf)

	// Create a large payload (but under limit)
	largeData := make([]byte, 1024*1024) // 1 MB
	for i := range largeData {
		largeData[i] = byte(i % 256)
	}

	msg, err := NewMessage(MsgPayload, EnvPayload{
		RequestID:  "large-req",
		Team:       "team",
		Env:        "prod",
		From:       []byte("sender"),
		Ciphertext: largeData,
	})
	if err != nil {
		t.Fatalf("Failed to create message: %v", err)
	}

	if err := framer.WriteMessage(msg); err != nil {
		t.Fatalf("Failed to write large message: %v", err)
	}

	// Read it back
	framer2 := NewFramer(bytes.NewReader(buf.Bytes()), nil)
	readMsg, err := framer2.ReadMessage()
	if err != nil {
		t.Fatalf("Failed to read large message: %v", err)
	}

	if readMsg.Type != MsgPayload {
		t.Errorf("Expected type %s, got %s", MsgPayload, readMsg.Type)
	}
}

func TestFramerMessageTooLarge(t *testing.T) {
	buf := &bytes.Buffer{}

	// Try to write a message that's too large
	// We'll manually write an oversized length prefix
	tooLargeLen := MaxMessageSize + 1
	lenBuf := make([]byte, 4)
	lenBuf[0] = byte(tooLargeLen >> 24)
	lenBuf[1] = byte(tooLargeLen >> 16)
	lenBuf[2] = byte(tooLargeLen >> 8)
	lenBuf[3] = byte(tooLargeLen)
	buf.Write(lenBuf)
	buf.Write(make([]byte, 100)) // Some dummy data

	// Try to read it
	framer := NewFramer(bytes.NewReader(buf.Bytes()), nil)
	_, err := framer.ReadMessage()
	if err != ErrMessageTooLarge {
		t.Errorf("Expected ErrMessageTooLarge, got %v", err)
	}
}

func TestNewMessage(t *testing.T) {
	msg, err := NewMessage(MsgPing, nil)
	if err != nil {
		t.Fatalf("Failed to create message: %v", err)
	}

	if msg.Type != MsgPing {
		t.Errorf("Expected type %s, got %s", MsgPing, msg.Type)
	}

	if msg.Timestamp.IsZero() {
		t.Error("Expected non-zero timestamp")
	}
}

func TestHandshakeCompatibility(t *testing.T) {
	ours := &Handshake{
		Version:    "1.0.0",
		MinVersion: "1.0.0",
		Pubkey:     []byte("our-pubkey"),
		MLKEMPub:   []byte("our-mlkem-pub"),
		Name:       "alice",
		Teams:      []string{"team1"},
	}

	theirs := &Handshake{
		Version:    "1.0.0",
		MinVersion: "1.0.0",
		Pubkey:     []byte("their-pubkey"),
		MLKEMPub:   []byte("their-mlkem-pub"),
		Name:       "bob",
		Teams:      []string{"team1", "team2"},
	}

	// Should be compatible
	if err := ours.Compatible(theirs); err != nil {
		t.Errorf("Expected compatible, got error: %v", err)
	}

	// Test shared teams
	shared := ours.SharedTeams(theirs)
	if len(shared) != 1 || shared[0] != "team1" {
		t.Errorf("Expected shared teams [team1], got %v", shared)
	}
}

func TestHandshakeIncompatible(t *testing.T) {
	ours := &Handshake{
		Version:    "1.0.0",
		MinVersion: "1.0.0",
		Pubkey:     []byte("our-pubkey"),
		MLKEMPub:   []byte("our-mlkem-pub"),
		Name:       "alice",
	}

	// Missing public key
	incomplete := &Handshake{
		Version:    "1.0.0",
		MinVersion: "1.0.0",
		Name:       "bob",
	}

	if err := ours.Compatible(incomplete); err == nil {
		t.Error("Expected error for missing public key")
	}

	// Missing ML-KEM key
	incomplete2 := &Handshake{
		Version:    "1.0.0",
		MinVersion: "1.0.0",
		Pubkey:     []byte("their-pubkey"),
		Name:       "bob",
	}

	if err := ours.Compatible(incomplete2); err == nil {
		t.Error("Expected error for missing ML-KEM key")
	}

	// Version too old
	oldVersion := &Handshake{
		Version:    "0.5.0",
		MinVersion: "0.5.0",
		Pubkey:     []byte("their-pubkey"),
		MLKEMPub:   []byte("their-mlkem-pub"),
		Name:       "bob",
	}

	if err := ours.Compatible(oldVersion); err == nil {
		t.Error("Expected error for incompatible version")
	}
}

func TestHandshakeClone(t *testing.T) {
	original := &Handshake{
		Version:    ProtocolVersion,
		MinVersion: MinProtocolVersion,
		Pubkey:     []byte("test-pubkey"),
		MLKEMPub:   []byte("test-mlkem"),
		Name:       "alice",
		Teams:      []string{"team1", "team2"},
		Addresses: []PeerAddr{
			{Type: "direct", Addr: "192.168.1.1:7834"},
		},
	}

	clone := original.Clone()

	// Modify original
	original.Name = "modified"
	original.Pubkey[0] = 0xFF
	original.Teams[0] = "modified-team"

	// Clone should be unchanged
	if clone.Name != "alice" {
		t.Errorf("Clone name was modified")
	}
	if clone.Pubkey[0] == 0xFF {
		t.Errorf("Clone pubkey was modified")
	}
	if clone.Teams[0] != "team1" {
		t.Errorf("Clone teams was modified")
	}
}
