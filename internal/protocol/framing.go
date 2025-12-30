package protocol

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

// Maximum message size (10 MB)
const MaxMessageSize = 10 * 1024 * 1024

// ErrMessageTooLarge is returned when a message exceeds MaxMessageSize
var ErrMessageTooLarge = errors.New("message too large")

// Framer handles length-prefixed message framing
type Framer struct {
	reader io.Reader
	writer io.Writer
}

// NewFramer creates a new framer
func NewFramer(r io.Reader, w io.Writer) *Framer {
	return &Framer{
		reader: r,
		writer: w,
	}
}

// ReadMessage reads a length-prefixed message
func (f *Framer) ReadMessage() (*Message, error) {
	msg, _, err := f.ReadMessageWithSize()
	return msg, err
}

// ReadMessageWithSize reads a length-prefixed message and returns its size
func (f *Framer) ReadMessageWithSize() (*Message, int, error) {
	// Read 4-byte length prefix (big-endian)
	lengthBuf := make([]byte, 4)
	if _, err := io.ReadFull(f.reader, lengthBuf); err != nil {
		return nil, 0, fmt.Errorf("read length: %w", err)
	}

	length := binary.BigEndian.Uint32(lengthBuf)
	if length > MaxMessageSize {
		return nil, int(length), ErrMessageTooLarge
	}

	// Read message body
	body := make([]byte, length)
	if _, err := io.ReadFull(f.reader, body); err != nil {
		return nil, int(length), fmt.Errorf("read body: %w", err)
	}

	// Decode JSON
	var msg Message
	if err := json.Unmarshal(body, &msg); err != nil {
		return nil, int(length), fmt.Errorf("decode message: %w", err)
	}

	return &msg, int(length), nil
}

// WriteMessage writes a length-prefixed message
func (f *Framer) WriteMessage(msg *Message) error {
	// Encode to JSON
	body, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("encode message: %w", err)
	}

	if len(body) > MaxMessageSize {
		return ErrMessageTooLarge
	}

	// Write 4-byte length prefix
	lengthBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(lengthBuf, uint32(len(body)))

	if _, err := f.writer.Write(lengthBuf); err != nil {
		return fmt.Errorf("write length: %w", err)
	}

	// Write body
	if _, err := f.writer.Write(body); err != nil {
		return fmt.Errorf("write body: %w", err)
	}

	return nil
}

// Send creates a message and writes it
func (f *Framer) Send(msgType MessageType, payload interface{}) error {
	msg, err := NewMessage(msgType, payload)
	if err != nil {
		return fmt.Errorf("create message: %w", err)
	}
	return f.WriteMessage(msg)
}

// ReadRaw reads raw bytes with length prefix
func (f *Framer) ReadRaw() ([]byte, error) {
	// Read 4-byte length prefix
	lengthBuf := make([]byte, 4)
	if _, err := io.ReadFull(f.reader, lengthBuf); err != nil {
		return nil, fmt.Errorf("read length: %w", err)
	}

	length := binary.BigEndian.Uint32(lengthBuf)
	if length > MaxMessageSize {
		return nil, ErrMessageTooLarge
	}

	// Read body
	body := make([]byte, length)
	if _, err := io.ReadFull(f.reader, body); err != nil {
		return nil, fmt.Errorf("read body: %w", err)
	}

	return body, nil
}

// WriteRaw writes raw bytes with length prefix
func (f *Framer) WriteRaw(data []byte) error {
	if len(data) > MaxMessageSize {
		return ErrMessageTooLarge
	}

	// Write 4-byte length prefix
	lengthBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(lengthBuf, uint32(len(data)))

	if _, err := f.writer.Write(lengthBuf); err != nil {
		return fmt.Errorf("write length: %w", err)
	}

	// Write body
	if _, err := f.writer.Write(data); err != nil {
		return fmt.Errorf("write body: %w", err)
	}

	return nil
}
