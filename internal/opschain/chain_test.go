package opschain

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestChain_Basic(t *testing.T) {
	chain := NewChain("test-project", "dev")

	if chain.Project != "test-project" {
		t.Errorf("Project = %s, want test-project", chain.Project)
	}
	if chain.Environment != "dev" {
		t.Errorf("Environment = %s, want dev", chain.Environment)
	}
	if chain.Len() != 0 {
		t.Errorf("Len = %d, want 0", chain.Len())
	}
	if chain.Head() != nil {
		t.Error("Head should be nil for empty chain")
	}
	if chain.HeadHash() != nil {
		t.Error("HeadHash should be nil for empty chain")
	}
	if chain.NextSeq() != 0 {
		t.Errorf("NextSeq = %d, want 0", chain.NextSeq())
	}
}

func TestChain_AppendWithoutVerification(t *testing.T) {
	chain := NewChain("test-project", "dev")

	op := &Operation{
		Seq:            0,
		Timestamp:      time.Now().UTC(),
		Author:         bytes.Repeat([]byte{0xab}, 32),
		Op:             OpSet,
		Key:            "TEST",
		EncryptedValue: []byte("value"),
		Signature:      bytes.Repeat([]byte{0xef}, 64),
	}

	err := chain.AppendWithoutVerification(op)
	if err != nil {
		t.Fatalf("AppendWithoutVerification() error = %v", err)
	}

	if chain.Len() != 1 {
		t.Errorf("Len = %d, want 1", chain.Len())
	}
	if chain.Head() != op {
		t.Error("Head should be the appended op")
	}
	if chain.NextSeq() != 1 {
		t.Errorf("NextSeq = %d, want 1", chain.NextSeq())
	}

	// Try to append with wrong sequence
	op2 := &Operation{
		Seq:            5, // Wrong!
		Timestamp:      time.Now().UTC(),
		Author:         bytes.Repeat([]byte{0xab}, 32),
		Op:             OpSet,
		Key:            "TEST2",
		EncryptedValue: []byte("value2"),
		PrevHash:       op.Hash(),
		Signature:      bytes.Repeat([]byte{0xef}, 64),
	}

	err = chain.AppendWithoutVerification(op2)
	if err == nil {
		t.Error("Should fail with wrong sequence number")
	}
}

func TestChain_Get(t *testing.T) {
	chain := NewChain("test-project", "dev")

	op := &Operation{
		Seq:            0,
		Timestamp:      time.Now().UTC(),
		Author:         bytes.Repeat([]byte{0xab}, 32),
		Op:             OpSet,
		Key:            "TEST",
		EncryptedValue: []byte("value"),
		Signature:      bytes.Repeat([]byte{0xef}, 64),
	}

	_ = chain.AppendWithoutVerification(op)

	if chain.Get(0) != op {
		t.Error("Get(0) should return the op")
	}
	if chain.Get(1) != nil {
		t.Error("Get(1) should return nil")
	}
	if chain.Get(100) != nil {
		t.Error("Get(100) should return nil")
	}
}

func TestChain_Range(t *testing.T) {
	chain := NewChain("test-project", "dev")

	for i := 0; i < 5; i++ {
		var prevHash []byte
		if i > 0 {
			prevHash = chain.Head().Hash()
		}

		op := &Operation{
			Seq:            uint64(i),
			Timestamp:      time.Now().UTC(),
			Author:         bytes.Repeat([]byte{0xab}, 32),
			Op:             OpSet,
			Key:            "TEST",
			EncryptedValue: []byte("value"),
			PrevHash:       prevHash,
			Signature:      bytes.Repeat([]byte{0xef}, 64),
		}
		_ = chain.AppendWithoutVerification(op)
	}

	ops := chain.Range(2)
	if len(ops) != 3 {
		t.Errorf("Range(2) returned %d ops, want 3", len(ops))
	}
	if ops[0].Seq != 2 {
		t.Errorf("First op Seq = %d, want 2", ops[0].Seq)
	}

	ops = chain.Range(10)
	if ops != nil {
		t.Error("Range(10) should return nil")
	}
}

func TestChain_SaveLoad(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "test.opschain.json")

	chain := NewChain("test-project", "dev")

	for i := 0; i < 3; i++ {
		var prevHash []byte
		if i > 0 {
			prevHash = chain.Head().Hash()
		}

		op := &Operation{
			Seq:            uint64(i),
			Timestamp:      time.Date(2024, 1, 15, 10, 30, i, 0, time.UTC),
			Author:         bytes.Repeat([]byte{0xab}, 32),
			Op:             OpSet,
			Key:            "TEST",
			EncryptedValue: []byte("value"),
			PrevHash:       prevHash,
			Signature:      bytes.Repeat([]byte{0xef}, 64),
		}
		_ = chain.AppendWithoutVerification(op)
	}

	// Save
	err := chain.Save(path)
	if err != nil {
		t.Fatalf("Save() error = %v", err)
	}

	// Verify file exists
	if _, err := os.Stat(path); os.IsNotExist(err) {
		t.Fatal("Chain file was not created")
	}

	// Load
	loaded, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if loaded.Project != chain.Project {
		t.Errorf("Project = %s, want %s", loaded.Project, chain.Project)
	}
	if loaded.Environment != chain.Environment {
		t.Errorf("Environment = %s, want %s", loaded.Environment, chain.Environment)
	}
	if loaded.Len() != chain.Len() {
		t.Errorf("Len = %d, want %d", loaded.Len(), chain.Len())
	}

	// Verify operations
	for i := 0; i < loaded.Len(); i++ {
		op := chain.Get(uint64(i))
		loadedOp := loaded.Get(uint64(i))

		if loadedOp.Seq != op.Seq {
			t.Errorf("Op %d: Seq = %d, want %d", i, loadedOp.Seq, op.Seq)
		}
		if loadedOp.Key != op.Key {
			t.Errorf("Op %d: Key = %s, want %s", i, loadedOp.Key, op.Key)
		}
	}
}

func TestChain_LoadOrCreate(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "nonexistent.json")

	// Should create new chain
	chain, err := LoadOrCreate(path, "project", "env")
	if err != nil {
		t.Fatalf("LoadOrCreate() error = %v", err)
	}
	if chain.Project != "project" {
		t.Error("Project should be set")
	}
	if chain.Len() != 0 {
		t.Error("New chain should be empty")
	}
}

func TestChain_Merge(t *testing.T) {
	// Create base chain
	chain := NewChain("project", "dev")
	op1 := &Operation{
		Seq:            0,
		Timestamp:      time.Now().UTC(),
		Author:         bytes.Repeat([]byte{0xab}, 32),
		Op:             OpSet,
		Key:            "KEY1",
		EncryptedValue: []byte("value1"),
		Signature:      bytes.Repeat([]byte{0xef}, 64),
	}
	_ = chain.AppendWithoutVerification(op1)

	op2 := &Operation{
		Seq:            1,
		Timestamp:      time.Now().UTC(),
		Author:         bytes.Repeat([]byte{0xab}, 32),
		Op:             OpSet,
		Key:            "KEY2",
		EncryptedValue: []byte("value2"),
		PrevHash:       op1.Hash(),
		Signature:      bytes.Repeat([]byte{0xef}, 64),
	}
	_ = chain.AppendWithoutVerification(op2)

	// Create incoming chain with additional ops
	incoming := NewChain("project", "dev")
	_ = incoming.AppendWithoutVerification(op1.Clone())
	_ = incoming.AppendWithoutVerification(op2.Clone())

	op3 := &Operation{
		Seq:            2,
		Timestamp:      time.Now().UTC(),
		Author:         bytes.Repeat([]byte{0xab}, 32),
		Op:             OpSet,
		Key:            "KEY3",
		EncryptedValue: []byte("value3"),
		PrevHash:       op2.Hash(),
		Signature:      bytes.Repeat([]byte{0xef}, 64),
	}
	_ = incoming.AppendWithoutVerification(op3)

	// Merge
	merged, conflict, err := chain.Merge(incoming, nil)
	if err != nil {
		t.Fatalf("Merge() error = %v", err)
	}
	if conflict != nil {
		t.Fatalf("Unexpected conflict: %v", conflict)
	}
	if merged != 1 {
		t.Errorf("Merged = %d, want 1", merged)
	}
	if chain.Len() != 3 {
		t.Errorf("Chain length = %d, want 3", chain.Len())
	}
}

func TestChain_Merge_Conflict(t *testing.T) {
	// Create base chain
	chain := NewChain("project", "dev")
	op1 := &Operation{
		Seq:            0,
		Timestamp:      time.Now().UTC(),
		Author:         bytes.Repeat([]byte{0xab}, 32),
		Op:             OpSet,
		Key:            "KEY1",
		EncryptedValue: []byte("value1"),
		Signature:      bytes.Repeat([]byte{0xef}, 64),
	}
	_ = chain.AppendWithoutVerification(op1)

	// Our op2
	ourOp2 := &Operation{
		Seq:            1,
		Timestamp:      time.Now().UTC(),
		Author:         bytes.Repeat([]byte{0xab}, 32),
		Op:             OpSet,
		Key:            "OUR_KEY",
		EncryptedValue: []byte("our_value"),
		PrevHash:       op1.Hash(),
		Signature:      bytes.Repeat([]byte{0xef}, 64),
	}
	_ = chain.AppendWithoutVerification(ourOp2)

	// Create incoming chain with different op2
	incoming := NewChain("project", "dev")
	_ = incoming.AppendWithoutVerification(op1.Clone())

	theirOp2 := &Operation{
		Seq:            1,
		Timestamp:      time.Now().UTC(),
		Author:         bytes.Repeat([]byte{0xcd}, 32), // Different author
		Op:             OpSet,
		Key:            "THEIR_KEY",
		EncryptedValue: []byte("their_value"),
		PrevHash:       op1.Hash(),
		Signature:      bytes.Repeat([]byte{0x12}, 64),
	}
	_ = incoming.AppendWithoutVerification(theirOp2)

	// Merge should detect conflict
	merged, conflict, err := chain.Merge(incoming, nil)
	if err != nil {
		t.Fatalf("Merge() error = %v", err)
	}
	if conflict == nil {
		t.Fatal("Expected conflict")
	}
	if merged != 0 {
		t.Errorf("Merged = %d, want 0", merged)
	}
	if conflict.Seq != 1 {
		t.Errorf("Conflict Seq = %d, want 1", conflict.Seq)
	}
	if conflict.OurOp.Key != "OUR_KEY" {
		t.Errorf("OurOp Key = %s, want OUR_KEY", conflict.OurOp.Key)
	}
	if conflict.TheirOp.Key != "THEIR_KEY" {
		t.Errorf("TheirOp Key = %s, want THEIR_KEY", conflict.TheirOp.Key)
	}
}

func TestChain_Merge_ProjectMismatch(t *testing.T) {
	chain := NewChain("project1", "dev")
	incoming := NewChain("project2", "dev")

	_, _, err := chain.Merge(incoming, nil)
	if err == nil {
		t.Error("Expected error for project mismatch")
	}
}

func TestConflict_String(t *testing.T) {
	conflict := &Conflict{
		Seq: 5,
		OurOp: &Operation{
			Key: "OUR_KEY",
		},
		TheirOp: &Operation{
			Key: "THEIR_KEY",
		},
	}

	s := conflict.String()
	if s == "" {
		t.Error("String() should not be empty")
	}
}

func TestChainPath(t *testing.T) {
	path := ChainPath("/base/chains", "myproject", "production")
	expected := "/base/chains/myproject/production.json"
	if path != expected {
		t.Errorf("ChainPath = %s, want %s", path, expected)
	}
}
