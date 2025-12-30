package crypto

import (
	"bytes"
	"testing"
)

func TestIdentityBackupRoundTrip(t *testing.T) {
	// Generate a new identity
	original, err := GenerateIdentity("test-user")
	if err != nil {
		t.Fatalf("Failed to generate identity: %v", err)
	}

	// Export to entropy
	entropy, err := original.ToEntropy()
	if err != nil {
		t.Fatalf("ToEntropy failed: %v", err)
	}

	// Verify entropy is 32 bytes
	if len(entropy) != 32 {
		t.Errorf("Expected 32 bytes entropy, got %d", len(entropy))
	}

	// Convert to mnemonic
	mnemonic, err := EntropyToMnemonic(entropy)
	if err != nil {
		t.Fatalf("EntropyToMnemonic failed: %v", err)
	}

	// Verify 24 words
	words := MnemonicToWords(mnemonic)
	if len(words) != 24 {
		t.Errorf("Expected 24 words, got %d", len(words))
	}

	// Recover entropy from mnemonic
	recoveredEntropy, err := MnemonicToEntropy(mnemonic)
	if err != nil {
		t.Fatalf("MnemonicToEntropy failed: %v", err)
	}

	// Verify entropy matches
	if !bytes.Equal(entropy, recoveredEntropy) {
		t.Errorf("Entropy mismatch after mnemonic round-trip")
	}

	// Reconstruct identity from entropy
	recovered, err := IdentityFromEntropy(recoveredEntropy, "recovered-user")
	if err != nil {
		t.Fatalf("IdentityFromEntropy failed: %v", err)
	}

	// Verify fingerprint matches (same signing key)
	if original.Fingerprint() != recovered.Fingerprint() {
		t.Errorf("Fingerprint mismatch:\n  original:  %s\n  recovered: %s",
			original.Fingerprint(), recovered.Fingerprint())
	}

	// Verify signing keys match
	if !bytes.Equal(original.SigningPublicKey(), recovered.SigningPublicKey()) {
		t.Errorf("Signing public key mismatch")
	}

	// Note: ML-KEM keys will NOT match because the original identity
	// was generated with random ML-KEM keys, but IdentityFromEntropy
	// derives them deterministically. This is expected - the paper
	// backup only preserves the Ed25519 key.
	// For new identities created after implementing paper backup,
	// we would need to derive ML-KEM from Ed25519 seed at creation time.

	// Verify name is the new name (not preserved in entropy)
	if recovered.Name != "recovered-user" {
		t.Errorf("Expected name 'recovered-user', got %s", recovered.Name)
	}

	// Test that the identity can sign and verify
	message := []byte("test message")
	signature := recovered.Sign(message)
	if !recovered.Verify(message, signature) {
		t.Error("Recovered identity cannot verify its own signature")
	}
}

func TestIdentityFromEntropyInvalidLength(t *testing.T) {
	shortEntropy := make([]byte, 16)
	_, err := IdentityFromEntropy(shortEntropy, "test")
	if err == nil {
		t.Error("Expected error for 16-byte entropy")
	}

	longEntropy := make([]byte, 64)
	_, err = IdentityFromEntropy(longEntropy, "test")
	if err == nil {
		t.Error("Expected error for 64-byte entropy")
	}
}

func TestDeterministicKEMDerivation(t *testing.T) {
	// Create two identities from the same entropy
	entropy := make([]byte, 32)
	for i := range entropy {
		entropy[i] = byte(i)
	}

	id1, err := IdentityFromEntropy(entropy, "test1")
	if err != nil {
		t.Fatalf("First IdentityFromEntropy failed: %v", err)
	}

	id2, err := IdentityFromEntropy(entropy, "test2")
	if err != nil {
		t.Fatalf("Second IdentityFromEntropy failed: %v", err)
	}

	// Signing keys should match
	if !bytes.Equal(id1.SigningPublicKey(), id2.SigningPublicKey()) {
		t.Error("Signing keys should be identical for same entropy")
	}

	// ML-KEM keys should also match (deterministically derived)
	if !bytes.Equal(id1.MLKEMPublicKey(), id2.MLKEMPublicKey()) {
		t.Error("ML-KEM keys should be identical for same entropy")
	}

	// Names are independent
	if id1.Name == id2.Name {
		t.Error("Names should be different")
	}
}
