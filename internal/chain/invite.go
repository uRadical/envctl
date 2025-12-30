package chain

import (
	"crypto/rand"
	"fmt"
	"strings"
)

const (
	// inviteCodeLength is the total length of the invite code (3 groups of 3)
	inviteCodeLength = 9
	// inviteCodeCharset excludes ambiguous characters (0/O/1/I/L)
	inviteCodeCharset = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"
)

// GenerateInviteCode creates a random invite code in the format XXX-XXX-XXX
func GenerateInviteCode() (string, error) {
	code := make([]byte, inviteCodeLength)
	for i := range code {
		b := make([]byte, 1)
		if _, err := rand.Read(b); err != nil {
			return "", fmt.Errorf("generate random byte: %w", err)
		}
		code[i] = inviteCodeCharset[int(b[0])%len(inviteCodeCharset)]
	}

	// Format as XXX-XXX-XXX
	return fmt.Sprintf("%s-%s-%s",
		string(code[0:3]),
		string(code[3:6]),
		string(code[6:9])), nil
}

// NormalizeInviteCode normalizes a code for comparison.
// Converts to uppercase and removes dashes/spaces.
func NormalizeInviteCode(code string) string {
	code = strings.ToUpper(code)
	code = strings.ReplaceAll(code, "-", "")
	code = strings.ReplaceAll(code, " ", "")
	return code
}

// FormatInviteCode formats a normalized code with dashes for display
func FormatInviteCode(code string) string {
	code = NormalizeInviteCode(code)
	if len(code) != inviteCodeLength {
		return code // Return as-is if wrong length
	}
	return fmt.Sprintf("%s-%s-%s", code[0:3], code[3:6], code[6:9])
}

// ValidateInviteCodeFormat checks if a code has valid format
func ValidateInviteCodeFormat(code string) bool {
	normalized := NormalizeInviteCode(code)
	if len(normalized) != inviteCodeLength {
		return false
	}
	for _, c := range normalized {
		if !strings.ContainsRune(inviteCodeCharset, c) {
			return false
		}
	}
	return true
}
