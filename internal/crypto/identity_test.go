package crypto

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestGenerateIdentity(t *testing.T) {
	t.Run("creates valid identity", func(t *testing.T) {
		identity, err := GenerateIdentity("test-user")
		if err != nil {
			t.Fatalf("GenerateIdentity failed: %v", err)
		}

		if identity.Name != "test-user" {
			t.Errorf("expected name 'test-user', got '%s'", identity.Name)
		}

		if identity.CreatedAt.IsZero() {
			t.Error("CreatedAt should not be zero")
		}

		if identity.mlkemPriv == nil {
			t.Error("ML-KEM private key should not be nil")
		}

		if identity.mlkemPub == nil {
			t.Error("ML-KEM public key should not be nil")
		}

		if identity.signingKey == nil {
			t.Error("signing key should not be nil")
		}

		if identity.verifyKey == nil {
			t.Error("verify key should not be nil")
		}
	})

	t.Run("generates unique keys", func(t *testing.T) {
		id1, err := GenerateIdentity("user1")
		if err != nil {
			t.Fatalf("GenerateIdentity failed: %v", err)
		}

		id2, err := GenerateIdentity("user2")
		if err != nil {
			t.Fatalf("GenerateIdentity failed: %v", err)
		}

		if bytes.Equal(id1.MLKEMPublicKey(), id2.MLKEMPublicKey()) {
			t.Error("two identities should have different ML-KEM keys")
		}

		if bytes.Equal(id1.SigningPublicKey(), id2.SigningPublicKey()) {
			t.Error("two identities should have different signing keys")
		}
	})
}

func TestIdentityPublicKeys(t *testing.T) {
	identity, err := GenerateIdentity("test-user")
	if err != nil {
		t.Fatalf("GenerateIdentity failed: %v", err)
	}

	t.Run("MLKEMPublicKey returns non-empty bytes", func(t *testing.T) {
		pubKey := identity.MLKEMPublicKey()
		if len(pubKey) == 0 {
			t.Error("ML-KEM public key should not be empty")
		}
		// ML-KEM-768 public key is 1184 bytes
		if len(pubKey) != 1184 {
			t.Errorf("expected ML-KEM public key length 1184, got %d", len(pubKey))
		}
	})

	t.Run("SigningPublicKey returns non-empty bytes", func(t *testing.T) {
		pubKey := identity.SigningPublicKey()
		if len(pubKey) == 0 {
			t.Error("signing public key should not be empty")
		}
		// Ed25519 public key is 32 bytes
		if len(pubKey) != 32 {
			t.Errorf("expected signing public key length 32, got %d", len(pubKey))
		}
	})
}

func TestIdentityFingerprint(t *testing.T) {
	identity, err := GenerateIdentity("test-user")
	if err != nil {
		t.Fatalf("GenerateIdentity failed: %v", err)
	}

	fingerprint := identity.Fingerprint()

	t.Run("fingerprint is not empty", func(t *testing.T) {
		if fingerprint == "" {
			t.Error("fingerprint should not be empty")
		}
	})

	t.Run("fingerprint is hex encoded", func(t *testing.T) {
		// Fingerprint is first 8 bytes of SHA-256 hash, hex encoded = 16 chars
		if len(fingerprint) != 16 {
			t.Errorf("expected fingerprint length 16, got %d", len(fingerprint))
		}

		// Check it's valid hex
		for _, c := range fingerprint {
			if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
				t.Errorf("fingerprint contains non-hex character: %c", c)
			}
		}
	})

	t.Run("fingerprint is consistent", func(t *testing.T) {
		fp1 := identity.Fingerprint()
		fp2 := identity.Fingerprint()
		if fp1 != fp2 {
			t.Error("fingerprint should be consistent")
		}
	})
}

func TestIdentitySignVerify(t *testing.T) {
	identity, err := GenerateIdentity("test-user")
	if err != nil {
		t.Fatalf("GenerateIdentity failed: %v", err)
	}

	message := []byte("Hello, World!")

	t.Run("sign produces signature", func(t *testing.T) {
		signature := identity.Sign(message)
		if len(signature) == 0 {
			t.Error("signature should not be empty")
		}
		// Ed25519 signature is 64 bytes
		if len(signature) != 64 {
			t.Errorf("expected signature length 64, got %d", len(signature))
		}
	})

	t.Run("verify accepts valid signature", func(t *testing.T) {
		signature := identity.Sign(message)
		if !identity.Verify(message, signature) {
			t.Error("Verify should accept valid signature")
		}
	})

	t.Run("verify rejects modified message", func(t *testing.T) {
		signature := identity.Sign(message)
		modifiedMessage := []byte("Hello, World!!")
		if identity.Verify(modifiedMessage, signature) {
			t.Error("Verify should reject signature for modified message")
		}
	})

	t.Run("verify rejects modified signature", func(t *testing.T) {
		signature := identity.Sign(message)
		signature[0] ^= 0xff // Flip bits in first byte
		if identity.Verify(message, signature) {
			t.Error("Verify should reject modified signature")
		}
	})
}

func TestIdentityPublic(t *testing.T) {
	identity, err := GenerateIdentity("test-user")
	if err != nil {
		t.Fatalf("GenerateIdentity failed: %v", err)
	}

	pub := identity.Public()

	t.Run("Public returns correct name", func(t *testing.T) {
		if pub.Name != identity.Name {
			t.Errorf("expected name '%s', got '%s'", identity.Name, pub.Name)
		}
	})

	t.Run("Public returns correct ML-KEM key", func(t *testing.T) {
		if !bytes.Equal(pub.MLKEMPub, identity.MLKEMPublicKey()) {
			t.Error("Public ML-KEM key mismatch")
		}
	})

	t.Run("Public returns correct signing key", func(t *testing.T) {
		if !bytes.Equal(pub.SigningPub, identity.SigningPublicKey()) {
			t.Error("Public signing key mismatch")
		}
	})

	t.Run("Public returns correct CreatedAt", func(t *testing.T) {
		if !pub.CreatedAt.Equal(identity.CreatedAt) {
			t.Error("CreatedAt mismatch")
		}
	})
}

func TestIdentitySaveLoadEncrypted(t *testing.T) {
	tempDir := t.TempDir()
	identityPath := filepath.Join(tempDir, "identity.enc")

	identity, err := GenerateIdentity("test-user")
	if err != nil {
		t.Fatalf("GenerateIdentity failed: %v", err)
	}

	passphrase := []byte("test-passphrase-12345")

	t.Run("SaveEncrypted creates file", func(t *testing.T) {
		err := identity.SaveEncrypted(identityPath, passphrase)
		if err != nil {
			t.Fatalf("SaveEncrypted failed: %v", err)
		}

		if _, err := os.Stat(identityPath); os.IsNotExist(err) {
			t.Error("identity file should exist")
		}
	})

	t.Run("LoadEncrypted restores identity", func(t *testing.T) {
		loaded, err := LoadEncrypted(identityPath, passphrase)
		if err != nil {
			t.Fatalf("LoadEncrypted failed: %v", err)
		}

		if loaded.Name != identity.Name {
			t.Errorf("expected name '%s', got '%s'", identity.Name, loaded.Name)
		}

		if !bytes.Equal(loaded.MLKEMPublicKey(), identity.MLKEMPublicKey()) {
			t.Error("ML-KEM public key mismatch after load")
		}

		if !bytes.Equal(loaded.SigningPublicKey(), identity.SigningPublicKey()) {
			t.Error("signing public key mismatch after load")
		}

		// Verify signing still works
		message := []byte("test message")
		sig := loaded.Sign(message)
		if !identity.Verify(message, sig) {
			t.Error("loaded identity signature should be verifiable by original")
		}
	})

	t.Run("LoadEncrypted fails with wrong passphrase", func(t *testing.T) {
		_, err := LoadEncrypted(identityPath, []byte("wrong-passphrase"))
		if err == nil {
			t.Error("LoadEncrypted should fail with wrong passphrase")
		}
	})

	t.Run("LoadEncrypted fails with corrupted file", func(t *testing.T) {
		corruptedPath := filepath.Join(tempDir, "corrupted.enc")
		err := os.WriteFile(corruptedPath, []byte("not valid json"), 0600)
		if err != nil {
			t.Fatalf("failed to create corrupted file: %v", err)
		}

		_, err = LoadEncrypted(corruptedPath, passphrase)
		if err == nil {
			t.Error("LoadEncrypted should fail with corrupted file")
		}
	})
}

func TestIdentitySaveLoadPublic(t *testing.T) {
	tempDir := t.TempDir()
	publicPath := filepath.Join(tempDir, "identity.pub")

	identity, err := GenerateIdentity("test-user")
	if err != nil {
		t.Fatalf("GenerateIdentity failed: %v", err)
	}

	t.Run("SavePublic creates file", func(t *testing.T) {
		err := identity.SavePublic(publicPath)
		if err != nil {
			t.Fatalf("SavePublic failed: %v", err)
		}

		if _, err := os.Stat(publicPath); os.IsNotExist(err) {
			t.Error("public key file should exist")
		}
	})

	t.Run("LoadPublic restores public identity", func(t *testing.T) {
		pub, err := LoadPublic(publicPath)
		if err != nil {
			t.Fatalf("LoadPublic failed: %v", err)
		}

		if pub.Name != identity.Name {
			t.Errorf("expected name '%s', got '%s'", identity.Name, pub.Name)
		}

		if !bytes.Equal(pub.MLKEMPub, identity.MLKEMPublicKey()) {
			t.Error("ML-KEM public key mismatch after load")
		}

		if !bytes.Equal(pub.SigningPub, identity.SigningPublicKey()) {
			t.Error("signing public key mismatch after load")
		}
	})

	t.Run("public file is readable JSON", func(t *testing.T) {
		data, err := os.ReadFile(publicPath)
		if err != nil {
			t.Fatalf("failed to read public file: %v", err)
		}

		// Should contain the name
		if !bytes.Contains(data, []byte("test-user")) {
			t.Error("public file should contain the identity name")
		}
	})
}

func TestPublicIdentityFingerprint(t *testing.T) {
	identity, err := GenerateIdentity("test-user")
	if err != nil {
		t.Fatalf("GenerateIdentity failed: %v", err)
	}

	pub := identity.Public()

	t.Run("Public fingerprint matches identity fingerprint", func(t *testing.T) {
		if pub.Fingerprint() != identity.Fingerprint() {
			t.Error("public identity fingerprint should match full identity fingerprint")
		}
	})
}

func TestPublicIdentitySerialization(t *testing.T) {
	identity, err := GenerateIdentity("test-user")
	if err != nil {
		t.Fatalf("GenerateIdentity failed: %v", err)
	}

	pub := identity.Public()

	t.Run("Serialize produces bytes", func(t *testing.T) {
		data, err := pub.Serialize()
		if err != nil {
			t.Fatalf("Serialize failed: %v", err)
		}

		if len(data) == 0 {
			t.Error("serialized data should not be empty")
		}
	})

	t.Run("Deserialize restores identity", func(t *testing.T) {
		data, err := pub.Serialize()
		if err != nil {
			t.Fatalf("Serialize failed: %v", err)
		}

		restored, err := DeserializePublicIdentity(data)
		if err != nil {
			t.Fatalf("DeserializePublicIdentity failed: %v", err)
		}

		if restored.Name != pub.Name {
			t.Errorf("expected name '%s', got '%s'", pub.Name, restored.Name)
		}

		if !bytes.Equal(restored.MLKEMPub, pub.MLKEMPub) {
			t.Error("ML-KEM public key mismatch after deserialization")
		}

		if !bytes.Equal(restored.SigningPub, pub.SigningPub) {
			t.Error("signing public key mismatch after deserialization")
		}
	})
}

func TestEncapsulationKeyFromBytes(t *testing.T) {
	identity, err := GenerateIdentity("test-user")
	if err != nil {
		t.Fatalf("GenerateIdentity failed: %v", err)
	}

	pubKeyBytes := identity.MLKEMPublicKey()

	t.Run("reconstructs valid key", func(t *testing.T) {
		key, err := EncapsulationKeyFromBytes(pubKeyBytes)
		if err != nil {
			t.Fatalf("EncapsulationKeyFromBytes failed: %v", err)
		}

		if key == nil {
			t.Error("key should not be nil")
		}
	})

	t.Run("fails with invalid bytes", func(t *testing.T) {
		_, err := EncapsulationKeyFromBytes([]byte("invalid"))
		if err == nil {
			t.Error("should fail with invalid bytes")
		}
	})
}

func TestPublicKeyFingerprint(t *testing.T) {
	pubKey := []byte("test-public-key-data")

	t.Run("produces consistent fingerprint", func(t *testing.T) {
		fp1 := PublicKeyFingerprint(pubKey)
		fp2 := PublicKeyFingerprint(pubKey)

		if fp1 != fp2 {
			t.Error("fingerprint should be consistent")
		}
	})

	t.Run("different keys produce different fingerprints", func(t *testing.T) {
		fp1 := PublicKeyFingerprint([]byte("key1"))
		fp2 := PublicKeyFingerprint([]byte("key2"))

		if fp1 == fp2 {
			t.Error("different keys should produce different fingerprints")
		}
	})
}

func TestIdentityDecapsulate(t *testing.T) {
	identity, err := GenerateIdentity("test-user")
	if err != nil {
		t.Fatalf("GenerateIdentity failed: %v", err)
	}

	// Encapsulate using the public key
	ciphertext, sharedSecret := Encapsulate(identity.mlkemPub)

	t.Run("decapsulates correctly", func(t *testing.T) {
		decapsulated, err := identity.Decapsulate(ciphertext)
		if err != nil {
			t.Fatalf("Decapsulate failed: %v", err)
		}

		if !bytes.Equal(decapsulated, sharedSecret) {
			t.Error("decapsulated secret should match encapsulated secret")
		}
	})

	t.Run("fails with wrong ciphertext", func(t *testing.T) {
		wrongCiphertext := make([]byte, len(ciphertext))
		copy(wrongCiphertext, ciphertext)
		wrongCiphertext[0] ^= 0xff

		_, err := identity.Decapsulate(wrongCiphertext)
		// Note: ML-KEM may not error but will produce wrong shared secret
		// This is by design for implicit rejection
		if err == nil {
			decapsulated, _ := identity.Decapsulate(wrongCiphertext)
			if bytes.Equal(decapsulated, sharedSecret) {
				t.Error("wrong ciphertext should produce different shared secret")
			}
		}
	})
}

func BenchmarkGenerateIdentity(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, err := GenerateIdentity("bench-user")
		if err != nil {
			b.Fatalf("GenerateIdentity failed: %v", err)
		}
	}
}

func BenchmarkSign(b *testing.B) {
	identity, _ := GenerateIdentity("bench-user")
	message := []byte("benchmark message to sign")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		identity.Sign(message)
	}
}

func BenchmarkVerify(b *testing.B) {
	identity, _ := GenerateIdentity("bench-user")
	message := []byte("benchmark message to verify")
	signature := identity.Sign(message)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		identity.Verify(message, signature)
	}
}

func BenchmarkSaveLoadEncrypted(b *testing.B) {
	tempDir := b.TempDir()
	identity, _ := GenerateIdentity("bench-user")
	passphrase := []byte("benchmark-passphrase")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		path := filepath.Join(tempDir, "identity.enc")
		identity.SaveEncrypted(path, passphrase)
		LoadEncrypted(path, passphrase)
	}
}

func TestIdentityCreatedAtIsUTC(t *testing.T) {
	identity, err := GenerateIdentity("test-user")
	if err != nil {
		t.Fatalf("GenerateIdentity failed: %v", err)
	}

	// CreatedAt should be in UTC
	if identity.CreatedAt.Location() != time.UTC {
		t.Error("CreatedAt should be in UTC timezone")
	}

	// Should be recent (within last minute)
	if time.Since(identity.CreatedAt) > time.Minute {
		t.Error("CreatedAt should be recent")
	}
}
