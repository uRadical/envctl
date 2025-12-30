package link

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"net"
	"strings"
	"sync"
	"time"

	"uradical.io/go/envctl/internal/crypto"
)

const (
	CodeLength  = 6
	CodeExpiry  = 5 * time.Minute
	MaxAttempts = 3
	LinkPort    = 7836
)

// Session represents an active linking session
type Session struct {
	Code      string
	CreatedAt time.Time
	ExpiresAt time.Time
	Attempts  int
	Identity  *crypto.Identity

	listener net.Listener
	mu       sync.Mutex
	done     chan struct{}
}

// GenerateCode creates a random 6-digit code
func GenerateCode() (string, error) {
	max := big.NewInt(1000000) // 0-999999
	n, err := rand.Int(rand.Reader, max)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%06d", n.Int64()), nil
}

// FormatCode formats code for display (XXX YYY)
func FormatCode(code string) string {
	if len(code) != 6 {
		return code
	}
	return code[:3] + " " + code[3:]
}

// ParseCode removes spaces and validates
func ParseCode(input string) (string, error) {
	// Remove spaces
	code := strings.ReplaceAll(input, " ", "")

	// Validate
	if len(code) != 6 {
		return "", fmt.Errorf("code must be 6 digits")
	}

	for _, c := range code {
		if c < '0' || c > '9' {
			return "", fmt.Errorf("code must contain only digits")
		}
	}

	return code, nil
}

// NewSourceSession creates a session on the source device
func NewSourceSession(identity *crypto.Identity) (*Session, error) {
	code, err := GenerateCode()
	if err != nil {
		return nil, fmt.Errorf("generating code: %w", err)
	}

	// Start listener
	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", LinkPort))
	if err != nil {
		return nil, fmt.Errorf("starting listener: %w", err)
	}

	session := &Session{
		Code:      code,
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(CodeExpiry),
		Identity:  identity,
		listener:  listener,
		done:      make(chan struct{}),
	}

	return session, nil
}

// FormattedCode returns the display-friendly code
func (s *Session) FormattedCode() string {
	return FormatCode(s.Code)
}

// TimeRemaining returns time until expiry
func (s *Session) TimeRemaining() time.Duration {
	return time.Until(s.ExpiresAt)
}

// IsExpired returns true if the session has expired
func (s *Session) IsExpired() bool {
	return time.Now().After(s.ExpiresAt)
}

// Listener returns the TCP listener
func (s *Session) Listener() net.Listener {
	return s.listener
}

// Done returns the done channel
func (s *Session) Done() <-chan struct{} {
	return s.done
}

// IncrementAttempts increments and returns the attempt count
func (s *Session) IncrementAttempts() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Attempts++
	return s.Attempts
}

// Close cancels the session
func (s *Session) Close() error {
	select {
	case <-s.done:
		// Already closed
	default:
		close(s.done)
	}

	if s.listener != nil {
		return s.listener.Close()
	}
	return nil
}
