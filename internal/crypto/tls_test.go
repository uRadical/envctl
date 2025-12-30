package crypto

import (
	"crypto/tls"
	"net"
	"testing"
	"time"
)

func TestGenerateTLSConfig(t *testing.T) {
	identity, err := GenerateIdentity("test-user")
	if err != nil {
		t.Fatalf("GenerateIdentity: %v", err)
	}

	tlsConfig, err := GenerateTLSConfig(identity)
	if err != nil {
		t.Fatalf("GenerateTLSConfig: %v", err)
	}

	// Check that certificate was generated
	if len(tlsConfig.CertPEM) == 0 {
		t.Error("CertPEM should not be empty")
	}

	// Check that fingerprint matches identity
	if tlsConfig.Fingerprint != identity.Fingerprint() {
		t.Errorf("Fingerprint mismatch: got %s, want %s", tlsConfig.Fingerprint, identity.Fingerprint())
	}

	// Verify the certificate can be parsed
	if len(tlsConfig.Certificate.Certificate) == 0 {
		t.Error("Certificate.Certificate should not be empty")
	}
}

func TestTLSServerClientConfig(t *testing.T) {
	identity, err := GenerateIdentity("test-user")
	if err != nil {
		t.Fatalf("GenerateIdentity: %v", err)
	}

	tlsConfig, err := GenerateTLSConfig(identity)
	if err != nil {
		t.Fatalf("GenerateTLSConfig: %v", err)
	}

	// Create server config
	serverConfig := tlsConfig.NewServerTLSConfig()
	if serverConfig.MinVersion != tls.VersionTLS13 {
		t.Error("Server should require TLS 1.3")
	}
	if serverConfig.ClientAuth != tls.RequireAnyClientCert {
		t.Error("Server should require client certificates")
	}

	// Create client config
	clientConfig := tlsConfig.NewClientTLSConfig(identity.Fingerprint())
	if clientConfig.MinVersion != tls.VersionTLS13 {
		t.Error("Client should require TLS 1.3")
	}
	if len(clientConfig.Certificates) != 1 {
		t.Error("Client should have one certificate")
	}
}

func TestMutualTLSConnection(t *testing.T) {
	// Create two identities (simulating two peers)
	alice, err := GenerateIdentity("alice")
	if err != nil {
		t.Fatalf("GenerateIdentity alice: %v", err)
	}
	bob, err := GenerateIdentity("bob")
	if err != nil {
		t.Fatalf("GenerateIdentity bob: %v", err)
	}

	// Generate TLS configs
	aliceTLS, err := GenerateTLSConfig(alice)
	if err != nil {
		t.Fatalf("GenerateTLSConfig alice: %v", err)
	}
	bobTLS, err := GenerateTLSConfig(bob)
	if err != nil {
		t.Fatalf("GenerateTLSConfig bob: %v", err)
	}

	// Create server (alice) listener
	serverConfig := aliceTLS.NewServerTLSConfig()
	listener, err := tls.Listen("tcp", "127.0.0.1:0", serverConfig)
	if err != nil {
		t.Fatalf("tls.Listen: %v", err)
	}
	defer listener.Close()

	serverAddr := listener.Addr().String()
	serverDone := make(chan error, 1)
	clientDone := make(chan error, 1)

	// Server goroutine
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			serverDone <- err
			return
		}
		defer conn.Close()

		tlsConn := conn.(*tls.Conn)
		if err := tlsConn.Handshake(); err != nil {
			serverDone <- err
			return
		}

		// Verify client certificate fingerprint
		state := tlsConn.ConnectionState()
		if len(state.PeerCertificates) == 0 {
			serverDone <- err
			return
		}

		rawCerts := make([][]byte, len(state.PeerCertificates))
		for i, cert := range state.PeerCertificates {
			rawCerts[i] = cert.Raw
		}

		fingerprint, err := ExtractFingerprintFromCert(rawCerts)
		if err != nil {
			serverDone <- err
			return
		}

		if fingerprint != bob.Fingerprint() {
			t.Errorf("Server: expected client fingerprint %s, got %s", bob.Fingerprint(), fingerprint)
		}

		serverDone <- nil
	}()

	// Client goroutine (bob connects to alice)
	go func() {
		// Client should verify alice's fingerprint
		clientConfig := bobTLS.NewClientTLSConfig(alice.Fingerprint())

		conn, err := tls.Dial("tcp", serverAddr, clientConfig)
		if err != nil {
			clientDone <- err
			return
		}
		defer conn.Close()

		clientDone <- nil
	}()

	// Wait for both with timeout
	timeout := time.After(5 * time.Second)

	select {
	case err := <-serverDone:
		if err != nil {
			t.Fatalf("Server error: %v", err)
		}
	case <-timeout:
		t.Fatal("Server timeout")
	}

	select {
	case err := <-clientDone:
		if err != nil {
			t.Fatalf("Client error: %v", err)
		}
	case <-timeout:
		t.Fatal("Client timeout")
	}
}

func TestVerifyPeerCertificate(t *testing.T) {
	identity, err := GenerateIdentity("test-user")
	if err != nil {
		t.Fatalf("GenerateIdentity: %v", err)
	}

	tlsConfig, err := GenerateTLSConfig(identity)
	if err != nil {
		t.Fatalf("GenerateTLSConfig: %v", err)
	}

	// Get raw certificate
	rawCert := tlsConfig.Certificate.Certificate[0]

	// Verify with correct fingerprint
	err = VerifyPeerCertificate([][]byte{rawCert}, identity.Fingerprint())
	if err != nil {
		t.Errorf("VerifyPeerCertificate should succeed: %v", err)
	}

	// Verify with wrong fingerprint
	err = VerifyPeerCertificate([][]byte{rawCert}, "wrongfingerprint")
	if err == nil {
		t.Error("VerifyPeerCertificate should fail with wrong fingerprint")
	}

	// Verify with no certs
	err = VerifyPeerCertificate([][]byte{}, identity.Fingerprint())
	if err == nil {
		t.Error("VerifyPeerCertificate should fail with no certs")
	}
}

func TestExtractFingerprintFromCert(t *testing.T) {
	identity, err := GenerateIdentity("test-user")
	if err != nil {
		t.Fatalf("GenerateIdentity: %v", err)
	}

	tlsConfig, err := GenerateTLSConfig(identity)
	if err != nil {
		t.Fatalf("GenerateTLSConfig: %v", err)
	}

	rawCert := tlsConfig.Certificate.Certificate[0]
	fingerprint, err := ExtractFingerprintFromCert([][]byte{rawCert})
	if err != nil {
		t.Fatalf("ExtractFingerprintFromCert: %v", err)
	}

	if fingerprint != identity.Fingerprint() {
		t.Errorf("Fingerprint mismatch: got %s, want %s", fingerprint, identity.Fingerprint())
	}
}

func TestMutualTLSFingerprintMismatch(t *testing.T) {
	// Create two identities
	alice, err := GenerateIdentity("alice")
	if err != nil {
		t.Fatalf("GenerateIdentity alice: %v", err)
	}
	bob, err := GenerateIdentity("bob")
	if err != nil {
		t.Fatalf("GenerateIdentity bob: %v", err)
	}
	charlie, err := GenerateIdentity("charlie")
	if err != nil {
		t.Fatalf("GenerateIdentity charlie: %v", err)
	}

	// Generate TLS configs
	aliceTLS, err := GenerateTLSConfig(alice)
	if err != nil {
		t.Fatalf("GenerateTLSConfig alice: %v", err)
	}
	bobTLS, err := GenerateTLSConfig(bob)
	if err != nil {
		t.Fatalf("GenerateTLSConfig bob: %v", err)
	}

	// Create server (alice) listener
	serverConfig := aliceTLS.NewServerTLSConfig()
	listener, err := tls.Listen("tcp", "127.0.0.1:0", serverConfig)
	if err != nil {
		t.Fatalf("tls.Listen: %v", err)
	}
	defer listener.Close()

	serverAddr := listener.Addr().String()

	// Server accepts any client cert (verification done separately)
	go func() {
		conn, _ := listener.Accept()
		if conn != nil {
			conn.Close()
		}
	}()

	// Client (bob) tries to connect expecting charlie's fingerprint (should fail)
	clientConfig := bobTLS.NewClientTLSConfig(charlie.Fingerprint()) // Wrong fingerprint!

	conn, err := net.DialTimeout("tcp", serverAddr, 2*time.Second)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}

	tlsConn := tls.Client(conn, clientConfig)
	err = tlsConn.Handshake()
	tlsConn.Close()

	// Should fail because alice's cert doesn't match charlie's fingerprint
	if err == nil {
		t.Error("Expected TLS handshake to fail with fingerprint mismatch")
	}
}
