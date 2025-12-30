package crypto

import (
	"bytes"
	"crypto/sha256"
	"io"

	"golang.org/x/crypto/hkdf"
)

// SAS (Short Authentication Strings) provides out-of-band verification
// of peer identity to detect man-in-the-middle attacks.

// Emoji list for SAS display (easy to distinguish verbally)
var sasEmojis = []struct {
	emoji string
	word  string
}{
	{"🍎", "apple"},
	{"🍌", "banana"},
	{"🍒", "cherry"},
	{"🍇", "grape"},
	{"🍋", "lemon"},
	{"🍊", "orange"},
	{"🍑", "peach"},
	{"🍓", "strawberry"},
	{"🌸", "flower"},
	{"🌻", "sunflower"},
	{"🌲", "tree"},
	{"🌵", "cactus"},
	{"🌊", "wave"},
	{"⭐", "star"},
	{"🌙", "moon"},
	{"☀️", "sun"},
	{"🔥", "fire"},
	{"❄️", "snow"},
	{"⚡", "lightning"},
	{"🌈", "rainbow"},
	{"🎸", "guitar"},
	{"🎹", "piano"},
	{"🎺", "trumpet"},
	{"🥁", "drum"},
	{"🚀", "rocket"},
	{"✈️", "plane"},
	{"🚗", "car"},
	{"🚢", "ship"},
	{"🏠", "house"},
	{"🏰", "castle"},
	{"⛰️", "mountain"},
	{"🏝️", "island"},
	{"🐶", "dog"},
	{"🐱", "cat"},
	{"🐦", "bird"},
	{"🐠", "fish"},
	{"🦁", "lion"},
	{"🐘", "elephant"},
	{"🦋", "butterfly"},
	{"🐢", "turtle"},
	{"💎", "diamond"},
	{"🔑", "key"},
	{"🎁", "gift"},
	{"🎈", "balloon"},
	{"📚", "book"},
	{"✏️", "pencil"},
	{"🔔", "bell"},
	{"⏰", "clock"},
	{"🎯", "target"},
	{"🏆", "trophy"},
	{"⚽", "soccer"},
	{"🏀", "basketball"},
	{"🎲", "dice"},
	{"🧩", "puzzle"},
	{"🎭", "mask"},
	{"👑", "crown"},
	{"💡", "lightbulb"},
	{"🔒", "lock"},
	{"⚙️", "gear"},
	{"🧲", "magnet"},
	{"🔮", "crystal"},
	{"🧪", "potion"},
	{"💊", "pill"},
	{"🩺", "stethoscope"},
}

// SASResult contains the SAS verification data
type SASResult struct {
	Emojis []string // 4 emojis
	Words  []string // 4 words
}

// ComputeSAS generates a Short Authentication String from two public keys.
// Both parties will compute the same SAS if there's no MITM.
func ComputeSAS(pubkeyA, pubkeyB []byte) *SASResult {
	// Sort keys for consistency (same result regardless of order)
	var first, second []byte
	if bytes.Compare(pubkeyA, pubkeyB) < 0 {
		first, second = pubkeyA, pubkeyB
	} else {
		first, second = pubkeyB, pubkeyA
	}

	// Derive 4 bytes using HKDF
	combined := append(first, second...)
	hkdfReader := hkdf.New(sha256.New, combined, nil, []byte("envctl-sas"))

	sasBytes := make([]byte, 4)
	io.ReadFull(hkdfReader, sasBytes)

	// Map each byte to an emoji
	result := &SASResult{
		Emojis: make([]string, 4),
		Words:  make([]string, 4),
	}

	for i, b := range sasBytes {
		idx := int(b) % len(sasEmojis)
		result.Emojis[i] = sasEmojis[idx].emoji
		result.Words[i] = sasEmojis[idx].word
	}

	return result
}

// String returns the SAS as an emoji string
func (s *SASResult) String() string {
	return s.Emojis[0] + " " + s.Emojis[1] + " " + s.Emojis[2] + " " + s.Emojis[3]
}

// WordString returns the SAS as words
func (s *SASResult) WordString() string {
	return s.Words[0] + " " + s.Words[1] + " " + s.Words[2] + " " + s.Words[3]
}
