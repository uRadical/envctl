package crypto

import (
	"bytes"
	"crypto/rand"
	"testing"
)

func TestMnemonicRoundTrip(t *testing.T) {
	// Generate random 32-byte entropy
	entropy := make([]byte, 32)
	if _, err := rand.Read(entropy); err != nil {
		t.Fatalf("Failed to generate entropy: %v", err)
	}

	// Convert to mnemonic
	mnemonic, err := EntropyToMnemonic(entropy)
	if err != nil {
		t.Fatalf("EntropyToMnemonic failed: %v", err)
	}

	// Verify we got 24 words
	words := MnemonicToWords(mnemonic)
	if len(words) != 24 {
		t.Errorf("Expected 24 words, got %d", len(words))
	}

	// Convert back to entropy
	recovered, err := MnemonicToEntropy(mnemonic)
	if err != nil {
		t.Fatalf("MnemonicToEntropy failed: %v", err)
	}

	// Verify entropy matches
	if !bytes.Equal(entropy, recovered) {
		t.Errorf("Entropy mismatch:\n  original:  %x\n  recovered: %x", entropy, recovered)
	}
}

func TestValidateMnemonic(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{
			name:    "valid mnemonic",
			input:   "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
			wantErr: false,
		},
		{
			name:    "invalid word",
			input:   "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon invalidword",
			wantErr: true,
		},
		{
			name:    "too few words",
			input:   "abandon abandon abandon",
			wantErr: true,
		},
		{
			name:    "empty",
			input:   "",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateMnemonic(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateMnemonic() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestEntropyToMnemonicInvalidLength(t *testing.T) {
	// Test with wrong entropy length
	shortEntropy := make([]byte, 16)
	_, err := EntropyToMnemonic(shortEntropy)
	if err == nil {
		t.Error("Expected error for 16-byte entropy")
	}

	longEntropy := make([]byte, 64)
	_, err = EntropyToMnemonic(longEntropy)
	if err == nil {
		t.Error("Expected error for 64-byte entropy")
	}
}

func TestMnemonicToWordsAndBack(t *testing.T) {
	mnemonic := "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
	words := MnemonicToWords(mnemonic)

	if len(words) != 12 {
		t.Errorf("Expected 12 words, got %d", len(words))
	}

	rejoined := WordsToMnemonic(words)
	if rejoined != mnemonic {
		t.Errorf("Mismatch:\n  original: %s\n  rejoined: %s", mnemonic, rejoined)
	}
}
