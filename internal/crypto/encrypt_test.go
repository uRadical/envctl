package crypto

import (
	"bytes"
	"crypto/mlkem"
	"testing"
)

func TestEncryptDecrypt(t *testing.T) {
	t.Run("round trip encryption", func(t *testing.T) {
		// Generate key pair
		privKey, err := mlkem.GenerateKey768()
		if err != nil {
			t.Fatalf("GenerateKey768: %v", err)
		}
		pubKey := privKey.EncapsulationKey()

		plaintext := []byte("hello, world!")

		// Encrypt
		ciphertext, err := Encrypt(plaintext, pubKey)
		if err != nil {
			t.Fatalf("Encrypt: %v", err)
		}

		// Ciphertext should be larger than plaintext
		// ML-KEM ciphertext (1088) + nonce (12) + AES ciphertext + tag (16)
		expectedMinLen := mlkemCiphertextSize + aesNonceSize + len(plaintext) + 16
		if len(ciphertext) < expectedMinLen {
			t.Errorf("ciphertext too short: got %d, want at least %d", len(ciphertext), expectedMinLen)
		}

		// Decrypt
		decrypted, err := Decrypt(ciphertext, privKey)
		if err != nil {
			t.Fatalf("Decrypt: %v", err)
		}

		if !bytes.Equal(decrypted, plaintext) {
			t.Errorf("decrypted text mismatch: got %q, want %q", decrypted, plaintext)
		}
	})

	t.Run("empty plaintext", func(t *testing.T) {
		privKey, err := mlkem.GenerateKey768()
		if err != nil {
			t.Fatalf("GenerateKey768: %v", err)
		}
		pubKey := privKey.EncapsulationKey()

		plaintext := []byte{}

		ciphertext, err := Encrypt(plaintext, pubKey)
		if err != nil {
			t.Fatalf("Encrypt: %v", err)
		}

		decrypted, err := Decrypt(ciphertext, privKey)
		if err != nil {
			t.Fatalf("Decrypt: %v", err)
		}

		if !bytes.Equal(decrypted, plaintext) {
			t.Errorf("decrypted text mismatch for empty plaintext")
		}
	})

	t.Run("large plaintext", func(t *testing.T) {
		privKey, err := mlkem.GenerateKey768()
		if err != nil {
			t.Fatalf("GenerateKey768: %v", err)
		}
		pubKey := privKey.EncapsulationKey()

		// 1MB of data
		plaintext := make([]byte, 1024*1024)
		for i := range plaintext {
			plaintext[i] = byte(i % 256)
		}

		ciphertext, err := Encrypt(plaintext, pubKey)
		if err != nil {
			t.Fatalf("Encrypt: %v", err)
		}

		decrypted, err := Decrypt(ciphertext, privKey)
		if err != nil {
			t.Fatalf("Decrypt: %v", err)
		}

		if !bytes.Equal(decrypted, plaintext) {
			t.Errorf("decrypted text mismatch for large plaintext")
		}
	})

	t.Run("different ciphertext each time", func(t *testing.T) {
		privKey, err := mlkem.GenerateKey768()
		if err != nil {
			t.Fatalf("GenerateKey768: %v", err)
		}
		pubKey := privKey.EncapsulationKey()

		plaintext := []byte("same message")

		ct1, _ := Encrypt(plaintext, pubKey)
		ct2, _ := Encrypt(plaintext, pubKey)

		if bytes.Equal(ct1, ct2) {
			t.Error("ciphertext should be different each time (due to random nonce and KEM)")
		}
	})
}

func TestDecryptErrors(t *testing.T) {
	privKey, err := mlkem.GenerateKey768()
	if err != nil {
		t.Fatalf("GenerateKey768: %v", err)
	}

	t.Run("ciphertext too short", func(t *testing.T) {
		shortCiphertext := make([]byte, 100)
		_, err := Decrypt(shortCiphertext, privKey)
		if err == nil {
			t.Error("expected error for short ciphertext")
		}
	})

	t.Run("corrupted ciphertext", func(t *testing.T) {
		pubKey := privKey.EncapsulationKey()
		plaintext := []byte("test message")

		ciphertext, err := Encrypt(plaintext, pubKey)
		if err != nil {
			t.Fatalf("Encrypt: %v", err)
		}

		// Corrupt the AES ciphertext portion
		corruptIdx := mlkemCiphertextSize + aesNonceSize + 5
		if corruptIdx < len(ciphertext) {
			ciphertext[corruptIdx] ^= 0xFF
		}

		_, err = Decrypt(ciphertext, privKey)
		if err == nil {
			t.Error("expected error for corrupted ciphertext")
		}
	})

	t.Run("wrong key", func(t *testing.T) {
		pubKey := privKey.EncapsulationKey()
		plaintext := []byte("test message")

		ciphertext, err := Encrypt(plaintext, pubKey)
		if err != nil {
			t.Fatalf("Encrypt: %v", err)
		}

		// Try to decrypt with different key
		wrongPrivKey, _ := mlkem.GenerateKey768()
		_, err = Decrypt(ciphertext, wrongPrivKey)
		if err == nil {
			t.Error("expected error when decrypting with wrong key")
		}
	})
}

func TestEncryptForIdentity(t *testing.T) {
	sender, err := GenerateIdentity("sender")
	if err != nil {
		t.Fatalf("GenerateIdentity sender: %v", err)
	}

	recipient, err := GenerateIdentity("recipient")
	if err != nil {
		t.Fatalf("GenerateIdentity recipient: %v", err)
	}

	plaintext := []byte("secret message for recipient")

	// Encrypt using recipient's public identity
	ciphertext, err := EncryptForIdentity(plaintext, recipient.Public())
	if err != nil {
		t.Fatalf("EncryptForIdentity: %v", err)
	}

	// Decrypt using recipient's full identity
	decrypted, err := DecryptWithIdentity(ciphertext, recipient)
	if err != nil {
		t.Fatalf("DecryptWithIdentity: %v", err)
	}

	if !bytes.Equal(decrypted, plaintext) {
		t.Errorf("decrypted text mismatch")
	}

	// Verify sender cannot decrypt
	_, err = DecryptWithIdentity(ciphertext, sender)
	if err == nil {
		t.Error("sender should not be able to decrypt message for recipient")
	}
}

func TestDeriveKey(t *testing.T) {
	t.Run("derives correct length", func(t *testing.T) {
		sharedSecret := []byte("test-shared-secret-value")

		key16, err := DeriveKey(sharedSecret, "purpose-1", 16)
		if err != nil {
			t.Fatalf("DeriveKey 16: %v", err)
		}
		if len(key16) != 16 {
			t.Errorf("key length: got %d, want 16", len(key16))
		}

		key32, err := DeriveKey(sharedSecret, "purpose-2", 32)
		if err != nil {
			t.Fatalf("DeriveKey 32: %v", err)
		}
		if len(key32) != 32 {
			t.Errorf("key length: got %d, want 32", len(key32))
		}

		key64, err := DeriveKey(sharedSecret, "purpose-3", 64)
		if err != nil {
			t.Fatalf("DeriveKey 64: %v", err)
		}
		if len(key64) != 64 {
			t.Errorf("key length: got %d, want 64", len(key64))
		}
	})

	t.Run("same input produces same output", func(t *testing.T) {
		sharedSecret := []byte("test-shared-secret")
		purpose := "my-purpose"

		key1, _ := DeriveKey(sharedSecret, purpose, 32)
		key2, _ := DeriveKey(sharedSecret, purpose, 32)

		if !bytes.Equal(key1, key2) {
			t.Error("same inputs should produce same key")
		}
	})

	t.Run("different purpose produces different key", func(t *testing.T) {
		sharedSecret := []byte("test-shared-secret")

		key1, _ := DeriveKey(sharedSecret, "purpose-a", 32)
		key2, _ := DeriveKey(sharedSecret, "purpose-b", 32)

		if bytes.Equal(key1, key2) {
			t.Error("different purposes should produce different keys")
		}
	})

	t.Run("different secret produces different key", func(t *testing.T) {
		key1, _ := DeriveKey([]byte("secret-1"), "purpose", 32)
		key2, _ := DeriveKey([]byte("secret-2"), "purpose", 32)

		if bytes.Equal(key1, key2) {
			t.Error("different secrets should produce different keys")
		}
	})
}

// Benchmarks

func BenchmarkEncrypt(b *testing.B) {
	privKey, _ := mlkem.GenerateKey768()
	pubKey := privKey.EncapsulationKey()
	plaintext := make([]byte, 1024) // 1KB

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Encrypt(plaintext, pubKey)
	}
}

func BenchmarkDecrypt(b *testing.B) {
	privKey, _ := mlkem.GenerateKey768()
	pubKey := privKey.EncapsulationKey()
	plaintext := make([]byte, 1024)

	ciphertext, _ := Encrypt(plaintext, pubKey)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Decrypt(ciphertext, privKey)
	}
}

func BenchmarkEncryptLarge(b *testing.B) {
	privKey, _ := mlkem.GenerateKey768()
	pubKey := privKey.EncapsulationKey()
	plaintext := make([]byte, 1024*1024) // 1MB

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Encrypt(plaintext, pubKey)
	}
}
