package link

import (
	"crypto/sha256"
	"fmt"

	"salsa.debian.org/vasudev/gospake2"
)

const (
	// Identity strings for SPAKE2 asymmetric mode
	sourceIdentity = "envctl-source"
	targetIdentity = "envctl-target"
)

// SPAKE2Exchange wraps the gospake2 library for device linking
type SPAKE2Exchange struct {
	spake *gospake2.SPAKE2
	role  string
}

// NewSPAKE2Source creates a SPAKE2 exchange for the source device
func NewSPAKE2Source(code string) *SPAKE2Exchange {
	password := gospake2.NewPassword(code)
	idA := gospake2.NewIdentityA(sourceIdentity)
	idB := gospake2.NewIdentityB(targetIdentity)

	spake := gospake2.SPAKE2A(password, idA, idB)

	return &SPAKE2Exchange{
		spake: &spake,
		role:  "source",
	}
}

// NewSPAKE2Target creates a SPAKE2 exchange for the target device
func NewSPAKE2Target(code string) *SPAKE2Exchange {
	password := gospake2.NewPassword(code)
	idA := gospake2.NewIdentityA(sourceIdentity)
	idB := gospake2.NewIdentityB(targetIdentity)

	spake := gospake2.SPAKE2B(password, idA, idB)

	return &SPAKE2Exchange{
		spake: &spake,
		role:  "target",
	}
}

// Start returns the first message to send to the peer
func (e *SPAKE2Exchange) Start() []byte {
	return e.spake.Start()
}

// Finish processes the peer's message and returns the shared key
func (e *SPAKE2Exchange) Finish(peerMessage []byte) ([]byte, error) {
	sharedKey, err := e.spake.Finish(peerMessage)
	if err != nil {
		return nil, fmt.Errorf("SPAKE2 finish: %w", err)
	}

	// Derive a 32-byte encryption key using HKDF-like construction
	h := sha256.New()
	h.Write(sharedKey)
	h.Write([]byte("envctl-link-v1"))

	return h.Sum(nil), nil
}
