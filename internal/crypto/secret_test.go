package crypto

import (
	"bytes"
	"testing"
)

func TestZeroBytes(t *testing.T) {
	t.Run("zeroes slice", func(t *testing.T) {
		data := []byte{1, 2, 3, 4, 5, 6, 7, 8}
		ZeroBytes(data)

		for i, b := range data {
			if b != 0 {
				t.Errorf("byte %d not zero: %d", i, b)
			}
		}
	})

	t.Run("handles empty slice", func(t *testing.T) {
		data := []byte{}
		ZeroBytes(data) // Should not panic
	})

	t.Run("handles nil slice", func(t *testing.T) {
		var data []byte
		ZeroBytes(data) // Should not panic
	})

	t.Run("zeroes large slice", func(t *testing.T) {
		data := make([]byte, 1024*1024) // 1MB
		for i := range data {
			data[i] = byte(i % 256)
		}

		ZeroBytes(data)

		for i, b := range data {
			if b != 0 {
				t.Errorf("byte %d not zero: %d", i, b)
			}
		}
	})

	t.Run("zeroes sensitive pattern", func(t *testing.T) {
		// Simulate a key
		key := []byte("super-secret-key-1234567890123456")
		ZeroBytes(key)

		if !bytes.Equal(key, make([]byte, len(key))) {
			t.Error("key not fully zeroed")
		}
	})
}

func TestWithSecret(t *testing.T) {
	t.Run("executes function", func(t *testing.T) {
		executed := false
		WithSecret(func() {
			executed = true
		})

		if !executed {
			t.Error("function not executed")
		}
	})

	t.Run("allows data manipulation", func(t *testing.T) {
		var result int
		WithSecret(func() {
			result = 42
		})

		if result != 42 {
			t.Errorf("expected 42, got %d", result)
		}
	})

	t.Run("handles panic", func(t *testing.T) {
		defer func() {
			if r := recover(); r == nil {
				t.Error("expected panic to propagate")
			}
		}()

		WithSecret(func() {
			panic("test panic")
		})
	})
}

func TestSecureBytes(t *testing.T) {
	t.Run("stores data", func(t *testing.T) {
		data := []byte("secret data")
		sb := NewSecureBytes(data)

		if !bytes.Equal(sb.Data(), data) {
			t.Error("data not stored correctly")
		}
	})

	t.Run("reports correct length", func(t *testing.T) {
		data := []byte("12345")
		sb := NewSecureBytes(data)

		if sb.Len() != 5 {
			t.Errorf("Len: got %d, want 5", sb.Len())
		}
	})

	t.Run("clears data", func(t *testing.T) {
		data := []byte{1, 2, 3, 4, 5}
		original := make([]byte, len(data))
		copy(original, data)

		sb := NewSecureBytes(data)
		sb.Clear()

		// Data should be zeroed
		for i, b := range data {
			if b != 0 {
				t.Errorf("byte %d not zero after Clear: %d", i, b)
			}
		}

		// Internal reference should be nil
		if sb.Data() != nil {
			t.Error("Data() should return nil after Clear")
		}

		// Len should be 0
		if sb.Len() != 0 {
			t.Errorf("Len should be 0 after Clear, got %d", sb.Len())
		}
	})

	t.Run("double clear is safe", func(t *testing.T) {
		data := []byte("test")
		sb := NewSecureBytes(data)
		sb.Clear()
		sb.Clear() // Should not panic
	})

	t.Run("nil data", func(t *testing.T) {
		sb := NewSecureBytes(nil)

		if sb.Data() != nil {
			t.Error("Data should be nil")
		}

		if sb.Len() != 0 {
			t.Errorf("Len should be 0 for nil data, got %d", sb.Len())
		}

		sb.Clear() // Should not panic
	})

	t.Run("empty data", func(t *testing.T) {
		sb := NewSecureBytes([]byte{})

		if sb.Len() != 0 {
			t.Errorf("Len should be 0 for empty data, got %d", sb.Len())
		}

		sb.Clear()
	})
}

func TestSecureBytesUsagePattern(t *testing.T) {
	// Demonstrate the intended usage pattern
	t.Run("typical usage", func(t *testing.T) {
		// Simulate receiving a key
		key := []byte("encryption-key-32-bytes-long!!")
		secureKey := NewSecureBytes(key)
		defer secureKey.Clear()

		// Use the key for something
		data := secureKey.Data()
		if len(data) != 30 {
			t.Errorf("expected 30 bytes, got %d", len(data))
		}

		// After the deferred Clear, key will be zeroed
	})

	t.Run("early clear", func(t *testing.T) {
		key := []byte("temporary-key")
		secureKey := NewSecureBytes(key)

		// Use key
		_ = secureKey.Len()

		// Clear immediately when done
		secureKey.Clear()

		// Key should be zeroed
		for _, b := range key {
			if b != 0 {
				t.Error("key should be zeroed after Clear")
			}
		}
	})
}

// Benchmarks

func BenchmarkZeroBytes(b *testing.B) {
	sizes := []struct {
		name string
		size int
	}{
		{"32B", 32},
		{"256B", 256},
		{"1KB", 1024},
		{"64KB", 64 * 1024},
		{"1MB", 1024 * 1024},
	}

	for _, sz := range sizes {
		b.Run(sz.name, func(b *testing.B) {
			data := make([]byte, sz.size)
			for i := range data {
				data[i] = byte(i % 256)
			}

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				ZeroBytes(data)
			}
		})
	}
}

func BenchmarkSecureBytesCreateAndClear(b *testing.B) {
	data := make([]byte, 32)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		sb := NewSecureBytes(data)
		sb.Clear()
	}
}
