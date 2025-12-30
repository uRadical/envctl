// Package opschain implements an append-only operations chain for secrets storage.
// Similar to git's commit model, operations are hash-linked and signed, providing
// a complete audit trail and enabling conflict detection during sync.
package opschain

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// OpType represents the type of operation
type OpType string

const (
	// OpSet sets or updates a key's value
	OpSet OpType = "set"
	// OpDelete removes a key
	OpDelete OpType = "delete"
)

// Operation represents a single operation in the chain.
// Operations are hash-linked, signed, and encrypted to self for storage.
type Operation struct {
	// Seq is the sequence number in the chain (0-indexed)
	Seq uint64 `json:"seq"`

	// Timestamp is when the operation was created (UTC)
	Timestamp time.Time `json:"timestamp"`

	// Author is the signing public key of who created this operation
	Author []byte `json:"author"`

	// Op is the operation type (set or delete)
	Op OpType `json:"op"`

	// Key is the variable name (plaintext for filtering/conflict detection)
	Key string `json:"key"`

	// EncryptedValue is the value encrypted to self using ML-KEM.
	// Empty for delete operations.
	EncryptedValue []byte `json:"encrypted_value,omitempty"`

	// PrevHash is the SHA256 hash of the previous operation (nil for seq 0)
	PrevHash []byte `json:"prev_hash,omitempty"`

	// Signature is the Ed25519 signature of the canonical message
	Signature []byte `json:"signature"`
}

// CurrentVersion is the format version for operation serialization
const CurrentVersion = 1

// SerializedOperation is the wire/storage format for an operation
type SerializedOperation struct {
	Version   uint8      `json:"version"`
	Operation *Operation `json:"operation"`
}

// SigningMessage returns the canonical bytes to be signed.
// This ensures consistent signature verification across implementations.
func (op *Operation) SigningMessage() []byte {
	var buf bytes.Buffer

	// Version byte
	buf.WriteByte(CurrentVersion)

	// Seq (8 bytes, big endian)
	seqBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(seqBytes, op.Seq)
	buf.Write(seqBytes)

	// Timestamp (RFC3339)
	buf.WriteString(op.Timestamp.UTC().Format(time.RFC3339Nano))
	buf.WriteByte(0) // null separator

	// Author (pubkey bytes)
	buf.Write(op.Author)

	// Op type
	buf.WriteString(string(op.Op))
	buf.WriteByte(0) // null separator

	// Key
	buf.WriteString(op.Key)
	buf.WriteByte(0) // null separator

	// EncryptedValue (length-prefixed)
	lenBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(lenBytes, uint32(len(op.EncryptedValue)))
	buf.Write(lenBytes)
	buf.Write(op.EncryptedValue)

	// PrevHash
	buf.Write(op.PrevHash)

	return buf.Bytes()
}

// Hash computes the SHA256 hash of the operation.
// Used for chain linking (next operation's PrevHash).
func (op *Operation) Hash() []byte {
	h := sha256.New()

	// Include all fields including signature
	h.Write(op.SigningMessage())
	h.Write(op.Signature)

	return h.Sum(nil)
}

// Validate performs basic validation on the operation
func (op *Operation) Validate() error {
	if op.Op != OpSet && op.Op != OpDelete {
		return fmt.Errorf("invalid operation type: %s", op.Op)
	}

	if op.Key == "" {
		return errors.New("key is required")
	}

	if op.Op == OpSet && len(op.EncryptedValue) == 0 {
		return errors.New("encrypted value is required for set operation")
	}

	if len(op.Author) == 0 {
		return errors.New("author is required")
	}

	if len(op.Signature) == 0 {
		return errors.New("signature is required")
	}

	// Seq 0 should not have PrevHash
	if op.Seq == 0 && len(op.PrevHash) != 0 {
		return errors.New("first operation should not have prev_hash")
	}

	// Seq > 0 should have PrevHash
	if op.Seq > 0 && len(op.PrevHash) == 0 {
		return errors.New("prev_hash is required for seq > 0")
	}

	return nil
}

// Serialize serializes the operation to JSON bytes
func (op *Operation) Serialize() ([]byte, error) {
	s := SerializedOperation{
		Version:   CurrentVersion,
		Operation: op,
	}
	return json.Marshal(s)
}

// DeserializeOperation deserializes an operation from JSON bytes
func DeserializeOperation(data []byte) (*Operation, error) {
	var s SerializedOperation
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, fmt.Errorf("unmarshal operation: %w", err)
	}

	if s.Version != CurrentVersion {
		return nil, fmt.Errorf("unsupported operation version: %d (expected %d)", s.Version, CurrentVersion)
	}

	if s.Operation == nil {
		return nil, errors.New("operation is nil")
	}

	return s.Operation, nil
}

// Clone creates a deep copy of the operation
func (op *Operation) Clone() *Operation {
	clone := &Operation{
		Seq:       op.Seq,
		Timestamp: op.Timestamp,
		Op:        op.Op,
		Key:       op.Key,
	}

	if len(op.Author) > 0 {
		clone.Author = make([]byte, len(op.Author))
		copy(clone.Author, op.Author)
	}

	if len(op.EncryptedValue) > 0 {
		clone.EncryptedValue = make([]byte, len(op.EncryptedValue))
		copy(clone.EncryptedValue, op.EncryptedValue)
	}

	if len(op.PrevHash) > 0 {
		clone.PrevHash = make([]byte, len(op.PrevHash))
		copy(clone.PrevHash, op.PrevHash)
	}

	if len(op.Signature) > 0 {
		clone.Signature = make([]byte, len(op.Signature))
		copy(clone.Signature, op.Signature)
	}

	return clone
}

// AuthorFingerprint returns a short fingerprint of the author's public key
func (op *Operation) AuthorFingerprint() string {
	if len(op.Author) < 8 {
		return ""
	}
	hash := sha256.Sum256(op.Author)
	return fmt.Sprintf("%x", hash[:8])
}
