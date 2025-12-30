package opschain

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"
)

func TestVerifier_VerifySignature(t *testing.T) {
	// Generate a key pair
	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}

	v := NewVerifier()

	// Create a properly signed operation
	op := &Operation{
		Seq:            0,
		Timestamp:      time.Now().UTC(),
		Author:         pubKey,
		Op:             OpSet,
		Key:            "TEST",
		EncryptedValue: []byte("value"),
	}

	// Sign it
	msg := op.SigningMessage()
	op.Signature = ed25519.Sign(privKey, msg)

	// Verify should pass
	err = v.VerifySignature(op)
	if err != nil {
		t.Errorf("VerifySignature() error = %v", err)
	}

	// Modify the key after signing
	op.Key = "MODIFIED"
	err = v.VerifySignature(op)
	if err == nil {
		t.Error("VerifySignature() should fail for modified operation")
	}
}

func TestVerifier_VerifySignature_InvalidSizes(t *testing.T) {
	v := NewVerifier()

	// Test invalid sizes - all should fail due to size checks
	tests := []struct {
		name      string
		authorLen int
		sigLen    int
	}{
		{"short author", 16, 64},
		{"long author", 48, 64},
		{"short signature", 32, 32},
		{"long signature", 32, 128},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			op := &Operation{
				Seq:            0,
				Timestamp:      time.Now().UTC(),
				Author:         make([]byte, tt.authorLen),
				Op:             OpSet,
				Key:            "TEST",
				EncryptedValue: []byte("value"),
				Signature:      make([]byte, tt.sigLen),
			}

			err := v.VerifySignature(op)
			if err == nil {
				t.Error("Expected error for invalid sizes")
			}
		})
	}
}

func TestVerifier_VerifyAuthor(t *testing.T) {
	v := NewVerifier()

	author1 := bytes.Repeat([]byte{0xab}, 32)
	author2 := bytes.Repeat([]byte{0xcd}, 32)

	op := &Operation{
		Author: author1,
	}

	// No restrictions - should pass
	err := v.VerifyAuthor(op)
	if err != nil {
		t.Errorf("VerifyAuthor() without restrictions error = %v", err)
	}

	// Add authorized author
	v.AddAuthorizedAuthor(author1)

	// Authorized author should pass
	err = v.VerifyAuthor(op)
	if err != nil {
		t.Errorf("VerifyAuthor() for authorized author error = %v", err)
	}

	// Unauthorized author should fail
	op.Author = author2
	err = v.VerifyAuthor(op)
	if err == nil {
		t.Error("VerifyAuthor() should fail for unauthorized author")
	}
}

func TestVerifier_VerifyChainLink(t *testing.T) {
	v := NewVerifier()

	// First operation (no previous)
	op1 := &Operation{
		Seq:            0,
		Author:         bytes.Repeat([]byte{0xab}, 32),
		Op:             OpSet,
		Key:            "TEST",
		EncryptedValue: []byte("value"),
		Signature:      bytes.Repeat([]byte{0xef}, 64),
	}

	err := v.VerifyChainLink(op1, nil)
	if err != nil {
		t.Errorf("VerifyChainLink() for first op error = %v", err)
	}

	// Second operation with correct prev_hash
	op2 := &Operation{
		Seq:            1,
		Author:         bytes.Repeat([]byte{0xab}, 32),
		Op:             OpSet,
		Key:            "TEST2",
		EncryptedValue: []byte("value2"),
		PrevHash:       op1.Hash(),
		Signature:      bytes.Repeat([]byte{0xef}, 64),
	}

	err = v.VerifyChainLink(op2, op1)
	if err != nil {
		t.Errorf("VerifyChainLink() for second op error = %v", err)
	}

	// Wrong prev_hash
	op2.PrevHash = bytes.Repeat([]byte{0x00}, 32)
	err = v.VerifyChainLink(op2, op1)
	if err == nil {
		t.Error("VerifyChainLink() should fail for wrong prev_hash")
	}

	// Sequence gap
	op3 := &Operation{
		Seq:            5, // Should be 2
		Author:         bytes.Repeat([]byte{0xab}, 32),
		Op:             OpSet,
		Key:            "TEST3",
		EncryptedValue: []byte("value3"),
		PrevHash:       op2.Hash(),
		Signature:      bytes.Repeat([]byte{0xef}, 64),
	}
	err = v.VerifyChainLink(op3, op2)
	if err == nil {
		t.Error("VerifyChainLink() should fail for sequence gap")
	}
}

func TestVerifier_VerifyChain(t *testing.T) {
	pubKey, privKey, _ := ed25519.GenerateKey(rand.Reader)
	v := NewVerifier()

	// Build a valid chain
	ops := make([]*Operation, 3)
	for i := 0; i < 3; i++ {
		var prevHash []byte
		if i > 0 {
			prevHash = ops[i-1].Hash()
		}

		ops[i] = &Operation{
			Seq:            uint64(i),
			Timestamp:      time.Date(2024, 1, 15, 10, 30, i, 0, time.UTC),
			Author:         pubKey,
			Op:             OpSet,
			Key:            "TEST",
			EncryptedValue: []byte("value"),
			PrevHash:       prevHash,
		}
		msg := ops[i].SigningMessage()
		ops[i].Signature = ed25519.Sign(privKey, msg)
	}

	// Verify chain
	err := v.VerifyChain(ops)
	if err != nil {
		t.Errorf("VerifyChain() error = %v", err)
	}

	// Corrupt middle operation
	ops[1].Key = "CORRUPTED"
	err = v.VerifyChain(ops)
	if err == nil {
		t.Error("VerifyChain() should fail for corrupted chain")
	}
}

func TestVerifySignatureOnly(t *testing.T) {
	pubKey, privKey, _ := ed25519.GenerateKey(rand.Reader)

	op := &Operation{
		Seq:            0,
		Timestamp:      time.Now().UTC(),
		Author:         pubKey,
		Op:             OpSet,
		Key:            "TEST",
		EncryptedValue: []byte("value"),
	}
	msg := op.SigningMessage()
	op.Signature = ed25519.Sign(privKey, msg)

	// Should pass
	err := VerifySignatureOnly(op)
	if err != nil {
		t.Errorf("VerifySignatureOnly() error = %v", err)
	}

	// Corrupt signature
	op.Signature[0] ^= 0xff
	err = VerifySignatureOnly(op)
	if err == nil {
		t.Error("VerifySignatureOnly() should fail for corrupted signature")
	}
}
