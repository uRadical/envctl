package protocol

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"
)

func TestMessageSign(t *testing.T) {
	// Generate a key pair
	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	// Create a message
	msg, err := NewMessage(MsgPing, struct{}{})
	if err != nil {
		t.Fatalf("NewMessage: %v", err)
	}

	// Sign the message
	msg.Sign(privKey)

	// Check that From and Signature are set
	if len(msg.From) == 0 {
		t.Error("From should be set after signing")
	}
	if len(msg.Signature) == 0 {
		t.Error("Signature should be set after signing")
	}

	// Verify From matches the public key
	if string(msg.From) != string(pubKey) {
		t.Error("From should match the public key")
	}

	// Check IsSigned returns true
	if !msg.IsSigned() {
		t.Error("IsSigned should return true")
	}
}

func TestMessageVerify(t *testing.T) {
	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	// Create and sign a message
	msg, _ := NewMessage(MsgChainHead, ChainHead{
		Team:  "test-team",
		Index: 42,
		Hash:  []byte("testhash"),
	})
	msg.Sign(privKey)

	// Verify should succeed
	if err := msg.Verify(); err != nil {
		t.Errorf("Verify should succeed: %v", err)
	}

	// VerifyFrom should succeed with correct key
	if err := msg.VerifyFrom(pubKey); err != nil {
		t.Errorf("VerifyFrom should succeed: %v", err)
	}
}

func TestMessageVerifyFrom_WrongKey(t *testing.T) {
	_, privKey, _ := ed25519.GenerateKey(rand.Reader)
	otherPubKey, _, _ := ed25519.GenerateKey(rand.Reader)

	msg, _ := NewMessage(MsgPing, struct{}{})
	msg.Sign(privKey)

	// VerifyFrom should fail with wrong key
	if err := msg.VerifyFrom(otherPubKey); err == nil {
		t.Error("VerifyFrom should fail with wrong public key")
	}
}

func TestMessageVerify_TamperedPayload(t *testing.T) {
	_, privKey, _ := ed25519.GenerateKey(rand.Reader)

	msg, _ := NewMessage(MsgChainHead, ChainHead{
		Team:  "test-team",
		Index: 42,
		Hash:  []byte("testhash"),
	})
	msg.Sign(privKey)

	// Tamper with the payload
	msg.Payload = []byte(`{"team":"hacked","index":999}`)

	// Verify should fail
	if err := msg.Verify(); err == nil {
		t.Error("Verify should fail with tampered payload")
	}
}

func TestMessageVerify_TamperedTimestamp(t *testing.T) {
	_, privKey, _ := ed25519.GenerateKey(rand.Reader)

	msg, _ := NewMessage(MsgPing, struct{}{})
	msg.Sign(privKey)

	// Tamper with the timestamp
	msg.Timestamp = time.Now().Add(time.Hour)

	// Verify should fail
	if err := msg.Verify(); err == nil {
		t.Error("Verify should fail with tampered timestamp")
	}
}

func TestMessageVerify_TamperedType(t *testing.T) {
	_, privKey, _ := ed25519.GenerateKey(rand.Reader)

	msg, _ := NewMessage(MsgPing, struct{}{})
	msg.Sign(privKey)

	// Tamper with the type
	msg.Type = MsgPong

	// Verify should fail
	if err := msg.Verify(); err == nil {
		t.Error("Verify should fail with tampered type")
	}
}

func TestMessageVerify_NoSignature(t *testing.T) {
	msg, _ := NewMessage(MsgPing, struct{}{})

	// Verify should fail without signature
	if err := msg.Verify(); err == nil {
		t.Error("Verify should fail without signature")
	}

	// IsSigned should return false
	if msg.IsSigned() {
		t.Error("IsSigned should return false")
	}
}

func TestMessageSigningData_Deterministic(t *testing.T) {
	// Create two messages with same content
	ts := time.Now().UTC()
	msg1 := &Message{
		Type:      MsgChainHead,
		Timestamp: ts,
		Payload:   []byte(`{"team":"test"}`),
	}
	msg2 := &Message{
		Type:      MsgChainHead,
		Timestamp: ts,
		Payload:   []byte(`{"team":"test"}`),
	}

	data1 := msg1.SigningData()
	data2 := msg2.SigningData()

	if string(data1) != string(data2) {
		t.Error("SigningData should be deterministic")
	}
}

func TestMessageSigningData_DifferentForDifferentContent(t *testing.T) {
	ts := time.Now().UTC()

	// Different types
	msg1 := &Message{Type: MsgPing, Timestamp: ts, Payload: []byte(`{}`)}
	msg2 := &Message{Type: MsgPong, Timestamp: ts, Payload: []byte(`{}`)}
	if string(msg1.SigningData()) == string(msg2.SigningData()) {
		t.Error("Different types should produce different signing data")
	}

	// Different payloads
	msg3 := &Message{Type: MsgPing, Timestamp: ts, Payload: []byte(`{"a":1}`)}
	msg4 := &Message{Type: MsgPing, Timestamp: ts, Payload: []byte(`{"a":2}`)}
	if string(msg3.SigningData()) == string(msg4.SigningData()) {
		t.Error("Different payloads should produce different signing data")
	}

	// Different timestamps
	msg5 := &Message{Type: MsgPing, Timestamp: ts, Payload: []byte(`{}`)}
	msg6 := &Message{Type: MsgPing, Timestamp: ts.Add(time.Second), Payload: []byte(`{}`)}
	if string(msg5.SigningData()) == string(msg6.SigningData()) {
		t.Error("Different timestamps should produce different signing data")
	}

	// Different nonces
	msg7 := &Message{Type: MsgPing, Timestamp: ts, Payload: []byte(`{}`), Nonce: 1}
	msg8 := &Message{Type: MsgPing, Timestamp: ts, Payload: []byte(`{}`), Nonce: 2}
	if string(msg7.SigningData()) == string(msg8.SigningData()) {
		t.Error("Different nonces should produce different signing data")
	}
}

func TestMessageVerify_TamperedNonce(t *testing.T) {
	_, privKey, _ := ed25519.GenerateKey(rand.Reader)

	msg, _ := NewMessage(MsgPing, struct{}{})
	msg.Nonce = 42
	msg.Sign(privKey)

	// Verify should succeed with original nonce
	if err := msg.Verify(); err != nil {
		t.Errorf("Verify should succeed: %v", err)
	}

	// Tamper with the nonce
	msg.Nonce = 999

	// Verify should fail
	if err := msg.Verify(); err == nil {
		t.Error("Verify should fail with tampered nonce")
	}
}

func TestMessageNonce_IncludedInSignature(t *testing.T) {
	_, privKey, _ := ed25519.GenerateKey(rand.Reader)

	// Create two identical messages with different nonces
	msg1, _ := NewMessage(MsgPing, struct{}{})
	msg1.Nonce = 1
	msg1.Sign(privKey)

	msg2, _ := NewMessage(MsgPing, struct{}{})
	msg2.Nonce = 2
	msg2.Timestamp = msg1.Timestamp // Use same timestamp
	msg2.Sign(privKey)

	// Signatures should be different
	if string(msg1.Signature) == string(msg2.Signature) {
		t.Error("Different nonces should produce different signatures")
	}

	// Both should verify independently
	if err := msg1.Verify(); err != nil {
		t.Errorf("msg1 should verify: %v", err)
	}
	if err := msg2.Verify(); err != nil {
		t.Errorf("msg2 should verify: %v", err)
	}

	// Swapping nonces should break verification
	msg1.Nonce = 2
	if err := msg1.Verify(); err == nil {
		t.Error("Swapped nonce should break verification")
	}
}

func TestMessageSigningData_NonceIncluded(t *testing.T) {
	ts := time.Now().UTC()

	// Message with nonce = 0 (default)
	msg1 := &Message{Type: MsgPing, Timestamp: ts, Payload: []byte(`{}`), Nonce: 0}

	// Message with nonce = 1
	msg2 := &Message{Type: MsgPing, Timestamp: ts, Payload: []byte(`{}`), Nonce: 1}

	data1 := msg1.SigningData()
	data2 := msg2.SigningData()

	if string(data1) == string(data2) {
		t.Error("Nonce should be included in signing data even when 0 vs non-zero")
	}
}
