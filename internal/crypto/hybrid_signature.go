package crypto

import (
	"encoding/binary"
	"fmt"
)

// Hybrid signature constants
const (
	hybridSignatureVersion = 1
	signatureTypeSoftware  = 0x00 // Ed25519 or ML-DSA only
	signatureTypeHybrid    = 0x01 // P-256 ECDSA + ML-DSA-65

	AlgorithmHybrid = "hybrid" // P-256 + ML-DSA-65 hybrid
)

// Hybrid signature format:
// [version:1][type:1][hw_len:2][hw_sig:...][pqc_sig:...]

// EncodeHybridSignature encodes hardware (P-256) and PQC (ML-DSA) signatures
func EncodeHybridSignature(hwSig, pqcSig []byte) []byte {
	buf := make([]byte, 4+len(hwSig)+len(pqcSig))

	buf[0] = hybridSignatureVersion
	buf[1] = signatureTypeHybrid
	binary.BigEndian.PutUint16(buf[2:4], uint16(len(hwSig)))
	copy(buf[4:], hwSig)
	copy(buf[4+len(hwSig):], pqcSig)

	return buf
}

// DecodeHybridSignature decodes a hybrid signature into its components
func DecodeHybridSignature(sig []byte) (hwSig, pqcSig []byte, err error) {
	if len(sig) < 4 {
		return nil, nil, fmt.Errorf("signature too short")
	}

	if sig[0] != hybridSignatureVersion {
		return nil, nil, fmt.Errorf("unknown signature version: %d", sig[0])
	}

	if sig[1] != signatureTypeHybrid {
		return nil, nil, fmt.Errorf("not a hybrid signature (type=%d)", sig[1])
	}

	hwLen := binary.BigEndian.Uint16(sig[2:4])

	if len(sig) < 4+int(hwLen) {
		return nil, nil, fmt.Errorf("signature truncated: need %d bytes for hw sig, have %d", hwLen, len(sig)-4)
	}

	hwSig = sig[4 : 4+hwLen]
	pqcSig = sig[4+hwLen:]

	if len(pqcSig) == 0 {
		return nil, nil, fmt.Errorf("missing PQC signature component")
	}

	return hwSig, pqcSig, nil
}

// IsHybridSignature checks if a signature is in hybrid format
func IsHybridSignature(sig []byte) bool {
	return len(sig) >= 2 && sig[0] == hybridSignatureVersion && sig[1] == signatureTypeHybrid
}
