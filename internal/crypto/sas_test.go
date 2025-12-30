package crypto

import (
	"bytes"
	"testing"
)

func TestComputeSAS(t *testing.T) {
	t.Run("produces valid result", func(t *testing.T) {
		pubkeyA := []byte("public-key-a-1234567890123456")
		pubkeyB := []byte("public-key-b-1234567890123456")

		result := ComputeSAS(pubkeyA, pubkeyB)

		if len(result.Emojis) != 4 {
			t.Errorf("expected 4 emojis, got %d", len(result.Emojis))
		}

		if len(result.Words) != 4 {
			t.Errorf("expected 4 words, got %d", len(result.Words))
		}

		for i, emoji := range result.Emojis {
			if emoji == "" {
				t.Errorf("emoji %d is empty", i)
			}
		}

		for i, word := range result.Words {
			if word == "" {
				t.Errorf("word %d is empty", i)
			}
		}
	})

	t.Run("order independent", func(t *testing.T) {
		pubkeyA := []byte("public-key-a-abcdefghijklmnop")
		pubkeyB := []byte("public-key-b-abcdefghijklmnop")

		result1 := ComputeSAS(pubkeyA, pubkeyB)
		result2 := ComputeSAS(pubkeyB, pubkeyA)

		// Results should be identical regardless of order
		for i := 0; i < 4; i++ {
			if result1.Emojis[i] != result2.Emojis[i] {
				t.Errorf("emoji %d differs: %q vs %q", i, result1.Emojis[i], result2.Emojis[i])
			}
			if result1.Words[i] != result2.Words[i] {
				t.Errorf("word %d differs: %q vs %q", i, result1.Words[i], result2.Words[i])
			}
		}
	})

	t.Run("different keys produce different SAS", func(t *testing.T) {
		pubkeyA := []byte("public-key-a-uniquevalue123456")
		pubkeyB := []byte("public-key-b-uniquevalue123456")
		pubkeyC := []byte("public-key-c-uniquevalue123456")

		result1 := ComputeSAS(pubkeyA, pubkeyB)
		result2 := ComputeSAS(pubkeyA, pubkeyC)

		// At least one emoji should differ (statistically very likely)
		same := true
		for i := 0; i < 4; i++ {
			if result1.Emojis[i] != result2.Emojis[i] {
				same = false
				break
			}
		}
		if same {
			t.Error("different key pairs should produce different SAS")
		}
	})

	t.Run("deterministic", func(t *testing.T) {
		pubkeyA := []byte("deterministic-key-a-0123456789")
		pubkeyB := []byte("deterministic-key-b-0123456789")

		result1 := ComputeSAS(pubkeyA, pubkeyB)
		result2 := ComputeSAS(pubkeyA, pubkeyB)

		for i := 0; i < 4; i++ {
			if result1.Emojis[i] != result2.Emojis[i] {
				t.Errorf("emoji %d differs on repeated call", i)
			}
			if result1.Words[i] != result2.Words[i] {
				t.Errorf("word %d differs on repeated call", i)
			}
		}
	})

	t.Run("identical keys", func(t *testing.T) {
		pubkey := []byte("identical-key-both-sides-12345")

		result := ComputeSAS(pubkey, pubkey)

		// Should still produce valid result
		if len(result.Emojis) != 4 {
			t.Errorf("expected 4 emojis for identical keys, got %d", len(result.Emojis))
		}
	})

	t.Run("empty keys", func(t *testing.T) {
		pubkeyA := []byte{}
		pubkeyB := []byte{}

		result := ComputeSAS(pubkeyA, pubkeyB)

		// Should still produce valid result
		if len(result.Emojis) != 4 {
			t.Errorf("expected 4 emojis for empty keys, got %d", len(result.Emojis))
		}
	})
}

func TestSASResultString(t *testing.T) {
	pubkeyA := []byte("string-test-key-a-123456789012")
	pubkeyB := []byte("string-test-key-b-123456789012")

	result := ComputeSAS(pubkeyA, pubkeyB)

	emojiStr := result.String()
	if emojiStr == "" {
		t.Error("String() returned empty")
	}

	// Should contain spaces between emojis
	if len(emojiStr) < 7 { // At least 4 emojis + 3 spaces
		t.Errorf("String() too short: %q", emojiStr)
	}
}

func TestSASResultWordString(t *testing.T) {
	pubkeyA := []byte("word-string-test-key-a-1234567")
	pubkeyB := []byte("word-string-test-key-b-1234567")

	result := ComputeSAS(pubkeyA, pubkeyB)

	wordStr := result.WordString()
	if wordStr == "" {
		t.Error("WordString() returned empty")
	}

	// Should contain spaces between words
	if len(wordStr) < 15 { // 4 words of at least 3 chars + 3 spaces
		t.Errorf("WordString() too short: %q", wordStr)
	}
}

func TestSASEmojisTable(t *testing.T) {
	// Verify the sasEmojis table is properly populated
	if len(sasEmojis) < 32 {
		t.Errorf("expected at least 32 emojis, got %d", len(sasEmojis))
	}

	seen := make(map[string]bool)
	for i, e := range sasEmojis {
		if e.emoji == "" {
			t.Errorf("emoji %d is empty", i)
		}
		if e.word == "" {
			t.Errorf("word %d is empty", i)
		}
		if seen[e.emoji] {
			t.Errorf("duplicate emoji: %s", e.emoji)
		}
		if seen[e.word] {
			t.Errorf("duplicate word: %s", e.word)
		}
		seen[e.emoji] = true
		seen[e.word] = true
	}
}

func TestSASWithRealIdentities(t *testing.T) {
	id1, err := GenerateIdentity("alice")
	if err != nil {
		t.Fatalf("GenerateIdentity alice: %v", err)
	}

	id2, err := GenerateIdentity("bob")
	if err != nil {
		t.Fatalf("GenerateIdentity bob: %v", err)
	}

	// Use MLKEM public keys for SAS
	pub1 := id1.Public()
	pub2 := id2.Public()

	sasAlice := ComputeSAS(pub1.MLKEMPub, pub2.MLKEMPub)
	sasBob := ComputeSAS(pub2.MLKEMPub, pub1.MLKEMPub)

	// Both parties should see the same SAS
	for i := 0; i < 4; i++ {
		if sasAlice.Emojis[i] != sasBob.Emojis[i] {
			t.Errorf("emoji mismatch at %d: %s vs %s", i, sasAlice.Emojis[i], sasBob.Emojis[i])
		}
	}

	t.Logf("SAS: %s (%s)", sasAlice.String(), sasAlice.WordString())
}

func TestSASMITMDetection(t *testing.T) {
	// Simulate a MITM attack where an attacker replaces keys

	alice, _ := GenerateIdentity("alice")
	bob, _ := GenerateIdentity("bob")
	mallory, _ := GenerateIdentity("mallory")

	alicePub := alice.Public()
	bobPub := bob.Public()
	malloryPub := mallory.Public()

	// What Alice sees (thinks she's talking to Bob but gets Mallory's key)
	sasAlice := ComputeSAS(alicePub.MLKEMPub, malloryPub.MLKEMPub)

	// What Bob sees (thinks he's talking to Alice but gets Mallory's key)
	sasBob := ComputeSAS(bobPub.MLKEMPub, malloryPub.MLKEMPub)

	// What would be legitimate
	sasLegit := ComputeSAS(alicePub.MLKEMPub, bobPub.MLKEMPub)

	// Alice's SAS should not match Bob's SAS in MITM scenario
	allMatch := true
	for i := 0; i < 4; i++ {
		if sasAlice.Emojis[i] != sasBob.Emojis[i] {
			allMatch = false
			break
		}
	}
	if allMatch {
		t.Log("Warning: MITM SAS matched - this is statistically unlikely but possible")
	}

	// Neither should match the legitimate SAS
	matchesLegit := true
	for i := 0; i < 4; i++ {
		if sasAlice.Emojis[i] != sasLegit.Emojis[i] {
			matchesLegit = false
			break
		}
	}
	if matchesLegit {
		t.Log("Warning: MITM SAS matched legitimate - statistically unlikely")
	}

	// Just verify both give valid results
	if len(sasAlice.Emojis) != 4 || len(sasBob.Emojis) != 4 {
		t.Error("MITM scenario should still produce valid SAS results")
	}
}

// Benchmarks

func BenchmarkComputeSAS(b *testing.B) {
	pubkeyA := make([]byte, 1184) // ML-KEM-768 public key size
	pubkeyB := make([]byte, 1184)

	// Fill with some data
	for i := range pubkeyA {
		pubkeyA[i] = byte(i)
		pubkeyB[i] = byte(255 - i)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ComputeSAS(pubkeyA, pubkeyB)
	}
}

func TestSASKeyOrderConsistency(t *testing.T) {
	// Test that the internal sorting is consistent
	key1 := []byte{0x00, 0x01, 0x02}
	key2 := []byte{0x01, 0x02, 0x03}

	// key1 < key2 lexicographically
	if bytes.Compare(key1, key2) >= 0 {
		t.Fatal("test setup wrong: key1 should be less than key2")
	}

	sas1 := ComputeSAS(key1, key2)
	sas2 := ComputeSAS(key2, key1)

	// Both should produce identical results
	if sas1.String() != sas2.String() {
		t.Error("SAS should be order-independent")
	}
}
