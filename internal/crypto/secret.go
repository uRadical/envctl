package crypto

// secret.go provides memory-safe handling for cryptographic secrets.
//
// This is a placeholder for Go's future runtime/secret package (Go 1.26+)
// which will provide automatic zeroing of sensitive memory.
//
// When runtime/secret becomes available, this can be updated to use:
//   secret.Do(func() { ... })
//
// For now, we implement manual memory clearing.

import (
	"crypto/subtle"
	"runtime"
)

// ZeroBytes securely zeroes a byte slice.
// Uses constant-time operations to prevent timing attacks.
func ZeroBytes(b []byte) {
	subtle.ConstantTimeCopy(1, b, make([]byte, len(b)))
	runtime.KeepAlive(b)
}

// WithSecret executes a function that handles secret data,
// intended to be replaced with runtime/secret.Do when available.
//
// Currently this is a simple wrapper, but when runtime/secret is
// available, it will provide:
// - Automatic memory zeroing on exit
// - Protection from memory dumps
// - Prevention of secret data swapping to disk
func WithSecret(fn func()) {
	fn()
	// Future: runtime/secret.Do(fn) will automatically zero
	// any secret data allocated within the function
}

// SecureBytes is a wrapper for byte slices that should be zeroed when done.
// Call Clear() when finished using the data.
type SecureBytes struct {
	data []byte
}

// NewSecureBytes creates a new SecureBytes wrapper
func NewSecureBytes(data []byte) *SecureBytes {
	return &SecureBytes{data: data}
}

// Data returns the underlying byte slice
func (s *SecureBytes) Data() []byte {
	return s.data
}

// Clear zeroes the underlying data
func (s *SecureBytes) Clear() {
	if s.data != nil {
		ZeroBytes(s.data)
		s.data = nil
	}
}

// Len returns the length of the underlying data
func (s *SecureBytes) Len() int {
	if s.data == nil {
		return 0
	}
	return len(s.data)
}
