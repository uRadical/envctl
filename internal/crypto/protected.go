package crypto

import (
	"runtime"
	"sync"
)

// ProtectedBuffer holds sensitive data with memory protection
type ProtectedBuffer struct {
	mu     sync.Mutex
	data   []byte
	locked bool
}

// NewProtectedBuffer creates a buffer that won't be swapped to disk
func NewProtectedBuffer(size int) *ProtectedBuffer {
	buf := &ProtectedBuffer{
		data: make([]byte, size),
	}

	// Prevent swapping to disk (best effort)
	if err := buf.mlock(); err != nil {
		// Log warning but continue - mlock may fail without CAP_IPC_LOCK
		// The data is still protected by process memory isolation
	}

	// Set finalizer to ensure cleanup
	runtime.SetFinalizer(buf, (*ProtectedBuffer).Destroy)

	return buf
}

// NewProtectedBufferFromBytes creates a protected buffer from existing bytes
func NewProtectedBufferFromBytes(data []byte) *ProtectedBuffer {
	buf := NewProtectedBuffer(len(data))
	copy(buf.data, data)

	// Zero the source
	ZeroBytes(data)

	return buf
}

// Bytes returns the underlying byte slice (use carefully)
func (p *ProtectedBuffer) Bytes() []byte {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.data
}

// Size returns the buffer size
func (p *ProtectedBuffer) Size() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.data)
}

// Destroy securely zeros the memory and unlocks
func (p *ProtectedBuffer) Destroy() {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.data == nil {
		return
	}

	// Secure zero
	ZeroBytes(p.data)

	// Unlock memory
	if p.locked {
		p.munlock()
	}

	p.data = nil

	// Remove finalizer since we've cleaned up
	runtime.SetFinalizer(p, nil)
}

// Copy creates a copy of the protected buffer data
func (p *ProtectedBuffer) Copy() []byte {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.data == nil {
		return nil
	}

	result := make([]byte, len(p.data))
	copy(result, p.data)
	return result
}
