package crypto

import (
	"fmt"
	"strings"

	"github.com/cosmos/go-bip39"
)

// EntropyToMnemonic converts raw entropy bytes to mnemonic words
// Requires 32 bytes (256 bits) of entropy, produces 24 words
func EntropyToMnemonic(entropy []byte) (string, error) {
	if len(entropy) != 32 {
		return "", fmt.Errorf("entropy must be 32 bytes, got %d", len(entropy))
	}

	mnemonic, err := bip39.NewMnemonic(entropy)
	if err != nil {
		return "", fmt.Errorf("generating mnemonic: %w", err)
	}

	return mnemonic, nil
}

// MnemonicToEntropy converts mnemonic words back to raw entropy
func MnemonicToEntropy(mnemonic string) ([]byte, error) {
	// Normalize whitespace
	mnemonic = strings.TrimSpace(mnemonic)
	mnemonic = strings.Join(strings.Fields(mnemonic), " ")

	// Validate mnemonic
	if !bip39.IsMnemonicValid(mnemonic) {
		return nil, fmt.Errorf("invalid mnemonic phrase")
	}

	// MnemonicToByteArray returns entropy + checksum byte
	// For 24 words: 256 bits entropy + 8 bits checksum = 33 bytes
	// We need to strip the checksum byte to get the original 32 bytes
	data, err := bip39.MnemonicToByteArray(mnemonic)
	if err != nil {
		return nil, fmt.Errorf("decoding mnemonic: %w", err)
	}

	// Strip the checksum byte (last byte for 24-word mnemonic)
	if len(data) != 33 {
		return nil, fmt.Errorf("unexpected data length: %d (expected 33)", len(data))
	}

	return data[:32], nil
}

// ValidateMnemonic checks if a mnemonic phrase is valid
func ValidateMnemonic(mnemonic string) error {
	mnemonic = strings.TrimSpace(mnemonic)
	mnemonic = strings.Join(strings.Fields(mnemonic), " ")

	if !bip39.IsMnemonicValid(mnemonic) {
		return fmt.Errorf("invalid mnemonic phrase")
	}

	return nil
}

// MnemonicToWords splits a mnemonic string into individual words
func MnemonicToWords(mnemonic string) []string {
	return strings.Fields(mnemonic)
}

// WordsToMnemonic joins words into a mnemonic string
func WordsToMnemonic(words []string) string {
	return strings.Join(words, " ")
}
