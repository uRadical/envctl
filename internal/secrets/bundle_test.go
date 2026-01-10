package secrets

import (
	"testing"

	"envctl.dev/go/envctl/internal/crypto"
)

func TestGenerateCIKeyPair(t *testing.T) {
	kp1, err := GenerateCIKeyPair()
	if err != nil {
		t.Fatalf("GenerateCIKeyPair failed: %v", err)
	}

	if len(kp1.PublicKey) != mlkemPublicKeySize {
		t.Errorf("expected %d byte public key, got %d bytes", mlkemPublicKeySize, len(kp1.PublicKey))
	}

	if len(kp1.PrivateKey) != mlkemPrivateKeySize {
		t.Errorf("expected %d byte private key, got %d bytes", mlkemPrivateKeySize, len(kp1.PrivateKey))
	}

	// Generate another keypair and ensure it's different
	kp2, err := GenerateCIKeyPair()
	if err != nil {
		t.Fatalf("GenerateCIKeyPair failed: %v", err)
	}

	if string(kp1.PublicKey) == string(kp2.PublicKey) {
		t.Error("two generated keypairs should not have identical public keys")
	}

	if string(kp1.PrivateKey) == string(kp2.PrivateKey) {
		t.Error("two generated keypairs should not have identical private keys")
	}
}

func TestEncodeDecodeKeys(t *testing.T) {
	kp, err := GenerateCIKeyPair()
	if err != nil {
		t.Fatalf("GenerateCIKeyPair failed: %v", err)
	}

	// Test public key encoding/decoding
	encodedPub := kp.EncodePublicKey()
	decodedPub, err := ParseCIPublicKey(encodedPub)
	if err != nil {
		t.Fatalf("ParseCIPublicKey failed: %v", err)
	}
	if string(decodedPub) != string(kp.PublicKey) {
		t.Error("public key roundtrip failed")
	}

	// Test private key encoding/decoding
	encodedPriv := kp.EncodePrivateKey()
	decodedPriv, err := ParseCIPrivateKey(encodedPriv)
	if err != nil {
		t.Fatalf("ParseCIPrivateKey failed: %v", err)
	}
	if string(decodedPriv) != string(kp.PrivateKey) {
		t.Error("private key roundtrip failed")
	}
}

func TestEncryptDecryptBundle(t *testing.T) {
	kp, err := GenerateCIKeyPair()
	if err != nil {
		t.Fatalf("GenerateCIKeyPair failed: %v", err)
	}

	vars := map[string]string{
		"DATABASE_URL": "postgres://localhost/test",
		"API_KEY":      "secret-key-12345",
		"DEBUG":        "true",
	}

	meta := BundleMeta{
		Project:             "test-project",
		Environment:         "production",
		ExporterFingerprint: "abc123",
	}

	bundle, err := EncryptBundle(vars, kp.PublicKey, meta)
	if err != nil {
		t.Fatalf("EncryptBundle failed: %v", err)
	}

	// Verify metadata
	if bundle.Version != BundleVersion {
		t.Errorf("expected version %d, got %d", BundleVersion, bundle.Version)
	}
	if bundle.Format != "ci-bundle" {
		t.Errorf("expected format 'ci-bundle', got '%s'", bundle.Format)
	}
	if bundle.Project != "test-project" {
		t.Errorf("expected project 'test-project', got '%s'", bundle.Project)
	}
	if bundle.Environment != "production" {
		t.Errorf("expected environment 'production', got '%s'", bundle.Environment)
	}
	if bundle.Encryption.Algorithm != "ML-KEM-768+AES-256-GCM" {
		t.Errorf("expected algorithm 'ML-KEM-768+AES-256-GCM', got '%s'", bundle.Encryption.Algorithm)
	}

	// Decrypt and verify
	decrypted, err := DecryptBundle(bundle, kp.PrivateKey)
	if err != nil {
		t.Fatalf("DecryptBundle failed: %v", err)
	}

	if len(decrypted) != len(vars) {
		t.Errorf("expected %d variables, got %d", len(vars), len(decrypted))
	}

	for k, v := range vars {
		if decrypted[k] != v {
			t.Errorf("variable %s: expected '%s', got '%s'", k, v, decrypted[k])
		}
	}
}

func TestDecryptWithWrongKey(t *testing.T) {
	kp1, _ := GenerateCIKeyPair()
	kp2, _ := GenerateCIKeyPair()

	vars := map[string]string{"TEST": "value"}
	meta := BundleMeta{
		Project:     "test",
		Environment: "dev",
	}

	bundle, err := EncryptBundle(vars, kp1.PublicKey, meta)
	if err != nil {
		t.Fatalf("EncryptBundle failed: %v", err)
	}

	// Try to decrypt with wrong private key
	_, err = DecryptBundle(bundle, kp2.PrivateKey)
	if err == nil {
		t.Error("expected decryption to fail with wrong key")
	}
}

func TestAADBinding(t *testing.T) {
	kp, _ := GenerateCIKeyPair()

	vars := map[string]string{"TEST": "value"}
	meta := BundleMeta{
		Project:     "project-a",
		Environment: "prod",
	}

	bundle, err := EncryptBundle(vars, kp.PublicKey, meta)
	if err != nil {
		t.Fatalf("EncryptBundle failed: %v", err)
	}

	// Modify the project/environment to test AAD binding
	bundle.Project = "project-b"

	// Decryption should fail because AAD won't match
	_, err = DecryptBundle(bundle, kp.PrivateKey)
	if err == nil {
		t.Error("expected decryption to fail when project is modified")
	}
}

func TestInvalidKeyLength(t *testing.T) {
	shortKey := []byte("too-short")
	vars := map[string]string{"TEST": "value"}
	meta := BundleMeta{Project: "test", Environment: "dev"}

	_, err := EncryptBundle(vars, shortKey, meta)
	if err != ErrInvalidPublicKey {
		t.Errorf("expected ErrInvalidPublicKey, got %v", err)
	}
}

func TestSerializeParseBundle(t *testing.T) {
	kp, _ := GenerateCIKeyPair()
	vars := map[string]string{"KEY": "value"}
	meta := BundleMeta{
		Project:             "test",
		Environment:         "staging",
		ExporterFingerprint: "fingerprint123",
	}

	bundle, _ := EncryptBundle(vars, kp.PublicKey, meta)

	// Serialize
	data, err := SerializeBundle(bundle)
	if err != nil {
		t.Fatalf("SerializeBundle failed: %v", err)
	}

	// Parse
	parsed, err := ParseBundle(data)
	if err != nil {
		t.Fatalf("ParseBundle failed: %v", err)
	}

	// Verify roundtrip
	if parsed.Project != bundle.Project {
		t.Errorf("project mismatch: %s vs %s", parsed.Project, bundle.Project)
	}
	if parsed.Environment != bundle.Environment {
		t.Errorf("environment mismatch: %s vs %s", parsed.Environment, bundle.Environment)
	}
	if parsed.Ciphertext != bundle.Ciphertext {
		t.Error("ciphertext mismatch")
	}
	if parsed.Encryption.KEMCiphertext != bundle.Encryption.KEMCiphertext {
		t.Error("KEM ciphertext mismatch")
	}

	// Decrypt the parsed bundle
	decrypted, err := DecryptBundle(parsed, kp.PrivateKey)
	if err != nil {
		t.Fatalf("DecryptBundle failed: %v", err)
	}
	if decrypted["KEY"] != "value" {
		t.Errorf("expected 'value', got '%s'", decrypted["KEY"])
	}
}

func TestSignVerifyBundle(t *testing.T) {
	kp, _ := GenerateCIKeyPair()
	vars := map[string]string{"SECRET": "data"}
	meta := BundleMeta{
		Project:     "test",
		Environment: "prod",
	}

	bundle, _ := EncryptBundle(vars, kp.PublicKey, meta)

	// Create a test identity
	identity, err := crypto.GenerateIdentity("test-user")
	if err != nil {
		t.Fatalf("GenerateIdentity failed: %v", err)
	}

	// Update fingerprint to match identity
	bundle.ExporterFingerprint = identity.Fingerprint()

	// Sign the bundle
	err = SignBundle(bundle, identity)
	if err != nil {
		t.Fatalf("SignBundle failed: %v", err)
	}

	if bundle.Signature == "" {
		t.Error("expected signature to be set")
	}

	// Verify with correct public key
	err = VerifyBundle(bundle, identity.SigningPublicKey())
	if err != nil {
		t.Errorf("VerifyBundle failed with correct key: %v", err)
	}

	// Create another identity and try to verify
	otherIdentity, _ := crypto.GenerateIdentity("other-user")
	err = VerifyBundle(bundle, otherIdentity.SigningPublicKey())
	if err == nil {
		t.Error("expected verification to fail with wrong key")
	}
}

func TestBundleWithEmptyVars(t *testing.T) {
	kp, _ := GenerateCIKeyPair()
	vars := map[string]string{}
	meta := BundleMeta{Project: "test", Environment: "dev"}

	bundle, err := EncryptBundle(vars, kp.PublicKey, meta)
	if err != nil {
		t.Fatalf("EncryptBundle failed: %v", err)
	}

	decrypted, err := DecryptBundle(bundle, kp.PrivateKey)
	if err != nil {
		t.Fatalf("DecryptBundle failed: %v", err)
	}

	if len(decrypted) != 0 {
		t.Errorf("expected 0 variables, got %d", len(decrypted))
	}
}

func TestBundleWithSpecialCharacters(t *testing.T) {
	kp, _ := GenerateCIKeyPair()
	vars := map[string]string{
		"MULTILINE":   "line1\nline2\nline3",
		"QUOTES":      `value with "quotes" and 'apostrophes'`,
		"UNICODE":     "Hello 世界 🔐",
		"EQUALS":      "key=value=more",
		"SPACES":      "  leading and trailing  ",
		"EMPTY":       "",
		"BACKSLASHES": `path\to\file`,
	}
	meta := BundleMeta{Project: "test", Environment: "dev"}

	bundle, err := EncryptBundle(vars, kp.PublicKey, meta)
	if err != nil {
		t.Fatalf("EncryptBundle failed: %v", err)
	}

	decrypted, err := DecryptBundle(bundle, kp.PrivateKey)
	if err != nil {
		t.Fatalf("DecryptBundle failed: %v", err)
	}

	for k, expected := range vars {
		if decrypted[k] != expected {
			t.Errorf("variable %s: expected %q, got %q", k, expected, decrypted[k])
		}
	}
}

func TestParseInvalidBundle(t *testing.T) {
	tests := []struct {
		name string
		data string
	}{
		{"invalid json", "not json"},
		{"wrong format", `{"format": "wrong", "version": 1}`},
		{"missing format", `{"version": 1}`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseBundle([]byte(tt.data))
			if err == nil {
				t.Error("expected error for invalid bundle")
			}
		})
	}
}

func TestParseInvalidKeys(t *testing.T) {
	// Test invalid public key
	_, err := ParseCIPublicKey("not-valid-base64!")
	if err == nil {
		t.Error("expected error for invalid public key encoding")
	}

	// Test wrong size public key (valid base64 but wrong length)
	_, err = ParseCIPublicKey("YWJjZGVm") // "abcdef" in base64
	if err == nil {
		t.Error("expected error for wrong size public key")
	}

	// Test invalid private key
	_, err = ParseCIPrivateKey("not-valid-base64!")
	if err == nil {
		t.Error("expected error for invalid private key encoding")
	}

	// Test wrong size private key
	_, err = ParseCIPrivateKey("YWJjZGVm") // "abcdef" in base64
	if err == nil {
		t.Error("expected error for wrong size private key")
	}
}
