package crypto

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"testing"
)

func TestEd25519Signer(t *testing.T) {
	t.Run("sign and verify", func(t *testing.T) {
		_, privKey, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatalf("GenerateKey: %v", err)
		}

		signer := NewEd25519Signer(privKey)
		message := []byte("test message to sign")

		signature, err := signer.Sign(message)
		if err != nil {
			t.Fatalf("Sign: %v", err)
		}

		if len(signature) != ed25519.SignatureSize {
			t.Errorf("signature length: got %d, want %d", len(signature), ed25519.SignatureSize)
		}

		if !signer.Verify(signer.PublicKey(), message, signature) {
			t.Error("signature should be valid")
		}
	})

	t.Run("wrong message fails verification", func(t *testing.T) {
		_, privKey, _ := ed25519.GenerateKey(rand.Reader)
		signer := NewEd25519Signer(privKey)

		message := []byte("original message")
		signature, _ := signer.Sign(message)

		wrongMessage := []byte("wrong message")
		if signer.Verify(signer.PublicKey(), wrongMessage, signature) {
			t.Error("verification should fail for wrong message")
		}
	})

	t.Run("wrong key fails verification", func(t *testing.T) {
		_, privKey1, _ := ed25519.GenerateKey(rand.Reader)
		_, privKey2, _ := ed25519.GenerateKey(rand.Reader)

		signer1 := NewEd25519Signer(privKey1)
		signer2 := NewEd25519Signer(privKey2)

		message := []byte("test message")
		signature, _ := signer1.Sign(message)

		// Verify with wrong key
		if signer1.Verify(signer2.PublicKey(), message, signature) {
			t.Error("verification should fail with wrong key")
		}
	})

	t.Run("algorithm returns ed25519", func(t *testing.T) {
		_, privKey, _ := ed25519.GenerateKey(rand.Reader)
		signer := NewEd25519Signer(privKey)

		if signer.Algorithm() != AlgorithmEd25519 {
			t.Errorf("Algorithm: got %q, want %q", signer.Algorithm(), AlgorithmEd25519)
		}
	})

	t.Run("public key matches", func(t *testing.T) {
		pubKey, privKey, _ := ed25519.GenerateKey(rand.Reader)
		signer := NewEd25519Signer(privKey)

		if !bytes.Equal(signer.PublicKey(), pubKey) {
			t.Error("PublicKey should match generated public key")
		}
	})

	t.Run("invalid public key length fails", func(t *testing.T) {
		_, privKey, _ := ed25519.GenerateKey(rand.Reader)
		signer := NewEd25519Signer(privKey)

		message := []byte("test")
		signature, _ := signer.Sign(message)

		// Wrong public key length
		shortKey := make([]byte, 16)
		if signer.Verify(shortKey, message, signature) {
			t.Error("verification should fail with short public key")
		}
	})

	t.Run("invalid signature length fails", func(t *testing.T) {
		_, privKey, _ := ed25519.GenerateKey(rand.Reader)
		signer := NewEd25519Signer(privKey)

		message := []byte("test")

		// Wrong signature length
		shortSig := make([]byte, 32)
		if signer.Verify(signer.PublicKey(), message, shortSig) {
			t.Error("verification should fail with short signature")
		}
	})
}

func TestEd25519Verifier(t *testing.T) {
	t.Run("verify valid signature", func(t *testing.T) {
		pubKey, privKey, _ := ed25519.GenerateKey(rand.Reader)
		message := []byte("test message")
		signature := ed25519.Sign(privKey, message)

		verifier := NewEd25519Verifier()
		if !verifier.Verify(pubKey, message, signature) {
			t.Error("valid signature should verify")
		}
	})

	t.Run("algorithm returns ed25519", func(t *testing.T) {
		verifier := NewEd25519Verifier()
		if verifier.Algorithm() != AlgorithmEd25519 {
			t.Errorf("Algorithm: got %q, want %q", verifier.Algorithm(), AlgorithmEd25519)
		}
	})

	t.Run("wrong message fails", func(t *testing.T) {
		pubKey, privKey, _ := ed25519.GenerateKey(rand.Reader)
		message := []byte("test message")
		signature := ed25519.Sign(privKey, message)

		verifier := NewEd25519Verifier()
		if verifier.Verify(pubKey, []byte("different"), signature) {
			t.Error("should reject wrong message")
		}
	})
}

func TestVerifySignature(t *testing.T) {
	t.Run("ed25519 algorithm", func(t *testing.T) {
		pubKey, privKey, _ := ed25519.GenerateKey(rand.Reader)
		message := []byte("test message")
		signature := ed25519.Sign(privKey, message)

		valid, err := VerifySignature(AlgorithmEd25519, pubKey, message, signature)
		if err != nil {
			t.Fatalf("VerifySignature: %v", err)
		}
		if !valid {
			t.Error("valid signature should verify")
		}
	})

	t.Run("invalid signature", func(t *testing.T) {
		pubKey, _, _ := ed25519.GenerateKey(rand.Reader)
		message := []byte("test message")
		badSig := make([]byte, ed25519.SignatureSize)

		valid, err := VerifySignature(AlgorithmEd25519, pubKey, message, badSig)
		if err != nil {
			t.Fatalf("VerifySignature: %v", err)
		}
		if valid {
			t.Error("invalid signature should not verify")
		}
	})

	t.Run("mldsa algorithm", func(t *testing.T) {
		pubKey, privKey, err := GenerateMLDSA65()
		if err != nil {
			t.Fatalf("GenerateMLDSA65: %v", err)
		}
		message := []byte("test message")
		signature, err := SignMLDSA65(privKey, message)
		if err != nil {
			t.Fatalf("SignMLDSA65: %v", err)
		}

		valid, err := VerifySignature(AlgorithmMLDSA, pubKey, message, signature)
		if err != nil {
			t.Fatalf("VerifySignature: %v", err)
		}
		if !valid {
			t.Error("valid ML-DSA signature should verify")
		}
	})

	t.Run("unknown algorithm", func(t *testing.T) {
		_, err := VerifySignature("unknown", nil, nil, nil)
		if err == nil {
			t.Error("expected error for unknown algorithm")
		}
	})
}

func TestGetVerifier(t *testing.T) {
	t.Run("ed25519", func(t *testing.T) {
		verifier, err := GetVerifier(AlgorithmEd25519)
		if err != nil {
			t.Fatalf("GetVerifier: %v", err)
		}
		if verifier == nil {
			t.Error("verifier should not be nil")
		}
		if verifier.Algorithm() != AlgorithmEd25519 {
			t.Error("wrong algorithm")
		}
	})

	t.Run("mldsa", func(t *testing.T) {
		verifier, err := GetVerifier(AlgorithmMLDSA)
		if err != nil {
			t.Fatalf("GetVerifier: %v", err)
		}
		if verifier == nil {
			t.Error("verifier should not be nil")
		}
		if verifier.Algorithm() != AlgorithmMLDSA {
			t.Error("wrong algorithm")
		}
	})

	t.Run("unknown algorithm", func(t *testing.T) {
		_, err := GetVerifier("unknown")
		if err == nil {
			t.Error("expected error for unknown algorithm")
		}
	})
}

func TestSignerFromIdentity(t *testing.T) {
	identity, err := GenerateIdentity("test-user")
	if err != nil {
		t.Fatalf("GenerateIdentity: %v", err)
	}

	signer := SignerFromIdentity(identity)

	message := []byte("test message to sign")
	signature, err := signer.Sign(message)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	// Verify with identity's public key
	pubIdentity := identity.Public()
	if !signer.Verify(pubIdentity.SigningPub, message, signature) {
		t.Error("signature should verify with identity's public signing key")
	}

	// Verify signer's public key matches identity's
	if !bytes.Equal(signer.PublicKey(), pubIdentity.SigningPub) {
		t.Error("signer public key should match identity signing key")
	}
}

// Benchmarks

func BenchmarkEd25519Sign(b *testing.B) {
	_, privKey, _ := ed25519.GenerateKey(rand.Reader)
	signer := NewEd25519Signer(privKey)
	message := make([]byte, 256)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		signer.Sign(message)
	}
}

func BenchmarkEd25519Verify(b *testing.B) {
	pubKey, privKey, _ := ed25519.GenerateKey(rand.Reader)
	signer := NewEd25519Signer(privKey)
	message := make([]byte, 256)
	signature, _ := signer.Sign(message)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		signer.Verify(pubKey, message, signature)
	}
}
