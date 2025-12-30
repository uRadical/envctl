package crypto

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"time"
)

// TLSConfig holds TLS configuration derived from an identity
type TLSConfig struct {
	// Certificate is the self-signed certificate for this identity
	Certificate tls.Certificate

	// CertPEM is the PEM-encoded certificate
	CertPEM []byte

	// Fingerprint is the identity fingerprint (for verification)
	Fingerprint string
}

// GenerateTLSConfig creates a TLS configuration from an identity.
// The certificate is self-signed using the identity's Ed25519 signing key.
// Peer verification is done by checking that the certificate's public key
// matches the expected peer fingerprint.
func GenerateTLSConfig(identity *Identity) (*TLSConfig, error) {
	// Create a self-signed certificate
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   identity.Name,
			Organization: []string{"envctl"},
		},
		NotBefore: identity.CreatedAt,
		NotAfter:  identity.CreatedAt.Add(100 * 365 * 24 * time.Hour), // 100 years

		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,

		// Allow any IP/DNS for P2P connections
		IPAddresses: []net.IP{net.IPv4zero, net.IPv6zero},
		DNSNames:    []string{"localhost", "*"},
	}

	// Get the Ed25519 private key
	privKey := identity.signingKey
	pubKey := identity.verifyKey

	// Create the certificate
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, pubKey, privKey)
	if err != nil {
		return nil, fmt.Errorf("create certificate: %w", err)
	}

	// Encode certificate to PEM
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})

	// Encode private key to PEM
	privKeyBytes, err := x509.MarshalPKCS8PrivateKey(privKey)
	if err != nil {
		return nil, fmt.Errorf("marshal private key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privKeyBytes,
	})

	// Create TLS certificate
	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("create TLS certificate: %w", err)
	}

	// Zero out the key PEM
	ZeroBytes(keyPEM)

	return &TLSConfig{
		Certificate: tlsCert,
		CertPEM:     certPEM,
		Fingerprint: identity.Fingerprint(),
	}, nil
}

// NewServerTLSConfig creates a TLS config for the server (listener) side.
// It requires client certificates (mutual TLS).
func (tc *TLSConfig) NewServerTLSConfig() *tls.Config {
	return &tls.Config{
		Certificates: []tls.Certificate{tc.Certificate},
		ClientAuth:   tls.RequireAnyClientCert, // Require cert, we verify manually
		MinVersion:   tls.VersionTLS13,         // TLS 1.3 only for modern security

		// We do custom verification based on fingerprint
		VerifyPeerCertificate: nil, // Set per-connection
		InsecureSkipVerify:    true, // We verify manually via fingerprint
	}
}

// NewClientTLSConfig creates a TLS config for the client (dialer) side.
// expectedFingerprint is the fingerprint of the peer we're connecting to.
func (tc *TLSConfig) NewClientTLSConfig(expectedFingerprint string) *tls.Config {
	return &tls.Config{
		Certificates:       []tls.Certificate{tc.Certificate},
		MinVersion:         tls.VersionTLS13,
		InsecureSkipVerify: true, // We verify manually via fingerprint

		VerifyPeerCertificate: func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
			return VerifyPeerCertificate(rawCerts, expectedFingerprint)
		},
	}
}

// VerifyPeerCertificate verifies that the peer's certificate matches the expected fingerprint.
// This is used for mutual TLS verification.
func VerifyPeerCertificate(rawCerts [][]byte, expectedFingerprint string) error {
	if len(rawCerts) == 0 {
		return fmt.Errorf("no peer certificate provided")
	}

	// Parse the first certificate
	cert, err := x509.ParseCertificate(rawCerts[0])
	if err != nil {
		return fmt.Errorf("parse peer certificate: %w", err)
	}

	// Extract the public key
	pubKey, ok := cert.PublicKey.(ed25519.PublicKey)
	if !ok {
		return fmt.Errorf("peer certificate does not contain Ed25519 key")
	}

	// Calculate fingerprint (cast Ed25519 public key to []byte)
	fingerprint := PublicKeyFingerprint([]byte(pubKey))

	// Compare with expected
	if fingerprint != expectedFingerprint {
		return fmt.Errorf("peer fingerprint mismatch: got %s, expected %s", fingerprint, expectedFingerprint)
	}

	return nil
}

// ExtractFingerprintFromCert extracts the identity fingerprint from a peer's certificate.
// This is used when we don't know the peer's fingerprint in advance (e.g., incoming connections).
func ExtractFingerprintFromCert(rawCerts [][]byte) (string, error) {
	if len(rawCerts) == 0 {
		return "", fmt.Errorf("no peer certificate provided")
	}

	cert, err := x509.ParseCertificate(rawCerts[0])
	if err != nil {
		return "", fmt.Errorf("parse peer certificate: %w", err)
	}

	pubKey, ok := cert.PublicKey.(ed25519.PublicKey)
	if !ok {
		return "", fmt.Errorf("peer certificate does not contain Ed25519 key")
	}

	return PublicKeyFingerprint([]byte(pubKey)), nil
}

// ExtractPublicKeyFromCert extracts the Ed25519 public key from a peer's certificate.
func ExtractPublicKeyFromCert(rawCerts [][]byte) (ed25519.PublicKey, error) {
	if len(rawCerts) == 0 {
		return nil, fmt.Errorf("no peer certificate provided")
	}

	cert, err := x509.ParseCertificate(rawCerts[0])
	if err != nil {
		return nil, fmt.Errorf("parse peer certificate: %w", err)
	}

	pubKey, ok := cert.PublicKey.(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("peer certificate does not contain Ed25519 key")
	}

	return pubKey, nil
}
