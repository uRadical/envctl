package opschain

import (
	"bytes"
	"testing"
	"time"
)

func TestOperation_SigningMessage(t *testing.T) {
	op := &Operation{
		Seq:            1,
		Timestamp:      time.Date(2024, 1, 15, 10, 30, 0, 0, time.UTC),
		Author:         bytes.Repeat([]byte{0xab}, 32),
		Op:             OpSet,
		Key:            "TEST_KEY",
		EncryptedValue: []byte("encrypted_value"),
		PrevHash:       bytes.Repeat([]byte{0xcd}, 32),
	}

	msg := op.SigningMessage()

	// Verify message is deterministic
	msg2 := op.SigningMessage()
	if !bytes.Equal(msg, msg2) {
		t.Error("SigningMessage should be deterministic")
	}

	// Different timestamp should produce different message
	op2 := *op
	op2.Timestamp = time.Date(2024, 1, 15, 10, 31, 0, 0, time.UTC)
	msg3 := op2.SigningMessage()
	if bytes.Equal(msg, msg3) {
		t.Error("Different timestamp should produce different message")
	}
}

func TestOperation_Hash(t *testing.T) {
	op := &Operation{
		Seq:            0,
		Timestamp:      time.Date(2024, 1, 15, 10, 30, 0, 0, time.UTC),
		Author:         bytes.Repeat([]byte{0xab}, 32),
		Op:             OpSet,
		Key:            "TEST_KEY",
		EncryptedValue: []byte("encrypted_value"),
		Signature:      bytes.Repeat([]byte{0xef}, 64),
	}

	hash := op.Hash()

	// Hash should be 32 bytes (SHA256)
	if len(hash) != 32 {
		t.Errorf("Hash should be 32 bytes, got %d", len(hash))
	}

	// Hash should be deterministic
	hash2 := op.Hash()
	if !bytes.Equal(hash, hash2) {
		t.Error("Hash should be deterministic")
	}

	// Different key should produce different hash
	op2 := *op
	op2.Key = "OTHER_KEY"
	hash3 := op2.Hash()
	if bytes.Equal(hash, hash3) {
		t.Error("Different key should produce different hash")
	}
}

func TestOperation_Validate(t *testing.T) {
	tests := []struct {
		name    string
		op      *Operation
		wantErr bool
	}{
		{
			name: "valid set operation",
			op: &Operation{
				Seq:            0,
				Op:             OpSet,
				Key:            "TEST",
				EncryptedValue: []byte("value"),
				Author:         bytes.Repeat([]byte{0xab}, 32),
				Signature:      bytes.Repeat([]byte{0xef}, 64),
			},
			wantErr: false,
		},
		{
			name: "valid delete operation",
			op: &Operation{
				Seq:       1,
				Op:        OpDelete,
				Key:       "TEST",
				Author:    bytes.Repeat([]byte{0xab}, 32),
				Signature: bytes.Repeat([]byte{0xef}, 64),
				PrevHash:  bytes.Repeat([]byte{0xcd}, 32),
			},
			wantErr: false,
		},
		{
			name: "missing key",
			op: &Operation{
				Seq:            0,
				Op:             OpSet,
				Key:            "",
				EncryptedValue: []byte("value"),
				Author:         bytes.Repeat([]byte{0xab}, 32),
				Signature:      bytes.Repeat([]byte{0xef}, 64),
			},
			wantErr: true,
		},
		{
			name: "set without value",
			op: &Operation{
				Seq:       0,
				Op:        OpSet,
				Key:       "TEST",
				Author:    bytes.Repeat([]byte{0xab}, 32),
				Signature: bytes.Repeat([]byte{0xef}, 64),
			},
			wantErr: true,
		},
		{
			name: "missing author",
			op: &Operation{
				Seq:            0,
				Op:             OpSet,
				Key:            "TEST",
				EncryptedValue: []byte("value"),
				Signature:      bytes.Repeat([]byte{0xef}, 64),
			},
			wantErr: true,
		},
		{
			name: "missing signature",
			op: &Operation{
				Seq:            0,
				Op:             OpSet,
				Key:            "TEST",
				EncryptedValue: []byte("value"),
				Author:         bytes.Repeat([]byte{0xab}, 32),
			},
			wantErr: true,
		},
		{
			name: "first op with prev_hash",
			op: &Operation{
				Seq:            0,
				Op:             OpSet,
				Key:            "TEST",
				EncryptedValue: []byte("value"),
				Author:         bytes.Repeat([]byte{0xab}, 32),
				Signature:      bytes.Repeat([]byte{0xef}, 64),
				PrevHash:       bytes.Repeat([]byte{0xcd}, 32),
			},
			wantErr: true,
		},
		{
			name: "non-first op without prev_hash",
			op: &Operation{
				Seq:            1,
				Op:             OpSet,
				Key:            "TEST",
				EncryptedValue: []byte("value"),
				Author:         bytes.Repeat([]byte{0xab}, 32),
				Signature:      bytes.Repeat([]byte{0xef}, 64),
			},
			wantErr: true,
		},
		{
			name: "invalid op type",
			op: &Operation{
				Seq:            0,
				Op:             OpType("invalid"),
				Key:            "TEST",
				EncryptedValue: []byte("value"),
				Author:         bytes.Repeat([]byte{0xab}, 32),
				Signature:      bytes.Repeat([]byte{0xef}, 64),
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.op.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestOperation_Serialize(t *testing.T) {
	op := &Operation{
		Seq:            42,
		Timestamp:      time.Date(2024, 1, 15, 10, 30, 0, 0, time.UTC),
		Author:         bytes.Repeat([]byte{0xab}, 32),
		Op:             OpSet,
		Key:            "TEST_KEY",
		EncryptedValue: []byte("encrypted_value"),
		PrevHash:       bytes.Repeat([]byte{0xcd}, 32),
		Signature:      bytes.Repeat([]byte{0xef}, 64),
	}

	data, err := op.Serialize()
	if err != nil {
		t.Fatalf("Serialize() error = %v", err)
	}

	// Deserialize
	op2, err := DeserializeOperation(data)
	if err != nil {
		t.Fatalf("DeserializeOperation() error = %v", err)
	}

	// Verify fields
	if op2.Seq != op.Seq {
		t.Errorf("Seq = %d, want %d", op2.Seq, op.Seq)
	}
	if op2.Key != op.Key {
		t.Errorf("Key = %s, want %s", op2.Key, op.Key)
	}
	if op2.Op != op.Op {
		t.Errorf("Op = %s, want %s", op2.Op, op.Op)
	}
	if !bytes.Equal(op2.Author, op.Author) {
		t.Error("Author mismatch")
	}
	if !bytes.Equal(op2.EncryptedValue, op.EncryptedValue) {
		t.Error("EncryptedValue mismatch")
	}
	if !bytes.Equal(op2.PrevHash, op.PrevHash) {
		t.Error("PrevHash mismatch")
	}
	if !bytes.Equal(op2.Signature, op.Signature) {
		t.Error("Signature mismatch")
	}
}

func TestOperation_Clone(t *testing.T) {
	op := &Operation{
		Seq:            42,
		Timestamp:      time.Date(2024, 1, 15, 10, 30, 0, 0, time.UTC),
		Author:         bytes.Repeat([]byte{0xab}, 32),
		Op:             OpSet,
		Key:            "TEST_KEY",
		EncryptedValue: []byte("encrypted_value"),
		PrevHash:       bytes.Repeat([]byte{0xcd}, 32),
		Signature:      bytes.Repeat([]byte{0xef}, 64),
	}

	clone := op.Clone()

	// Modify original
	op.Key = "MODIFIED"
	op.Author[0] = 0x00

	// Clone should be unaffected
	if clone.Key != "TEST_KEY" {
		t.Error("Clone Key was modified")
	}
	if clone.Author[0] != 0xab {
		t.Error("Clone Author was modified")
	}
}

func TestOperation_AuthorFingerprint(t *testing.T) {
	op := &Operation{
		Author: bytes.Repeat([]byte{0xab}, 32),
	}

	fp := op.AuthorFingerprint()
	if len(fp) == 0 {
		t.Error("Fingerprint should not be empty")
	}

	// Fingerprint should be deterministic
	fp2 := op.AuthorFingerprint()
	if fp != fp2 {
		t.Error("Fingerprint should be deterministic")
	}

	// Different author should produce different fingerprint
	op2 := &Operation{
		Author: bytes.Repeat([]byte{0xcd}, 32),
	}
	fp3 := op2.AuthorFingerprint()
	if fp == fp3 {
		t.Error("Different authors should have different fingerprints")
	}
}
