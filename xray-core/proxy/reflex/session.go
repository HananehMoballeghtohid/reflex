package reflex

import (
	"crypto/cipher"
	"encoding/binary"
	"io"

	"golang.org/x/crypto/chacha20poly1305"
)

const (
	FrameTypeData    = 0x01
	FrameTypePadding = 0x02
	FrameTypeTiming  = 0x03
	FrameTypeClose   = 0x04
)

type Frame struct {
	Length  uint16
	Type    uint8
	Payload []byte
}

type Session struct {
	key        []byte
	aead       cipher.AEAD
	readNonce  uint64
	writeNonce uint64
}

func NewSession(sessionKey []byte) (*Session, error) {
	aead, err := chacha20poly1305.New(sessionKey)
	if err != nil {
		return nil, err
	}
	return &Session{
		key:        sessionKey,
		aead:       aead,
		readNonce:  0,
		writeNonce: 0,
	}, nil
}

func (s *Session) ReadFrame(reader io.Reader) (*Frame, error) {
	// header: [len(2)][type(1)]
	header := make([]byte, 3)
	if _, err := io.ReadFull(reader, header); err != nil {
		return nil, err
	}
	length := binary.BigEndian.Uint16(header[0:2])
	frameType := header[2]

	encryptedPayload := make([]byte, length)
	if _, err := io.ReadFull(reader, encryptedPayload); err != nil {
		return nil, err
	}

	nonce := make([]byte, 12)
	binary.BigEndian.PutUint64(nonce[4:], s.readNonce)
	s.readNonce++

	payload, err := s.aead.Open(nil, nonce, encryptedPayload, nil)
	if err != nil {
		return nil, err
	}

	return &Frame{
		Length:  length,
		Type:    frameType,
		Payload: payload,
	}, nil
}

func (s *Session) WriteFrame(writer io.Writer, frameType uint8, data []byte) error {
	nonce := make([]byte, 12)
	binary.BigEndian.PutUint64(nonce[4:], s.writeNonce)
	s.writeNonce++

	encrypted := s.aead.Seal(nil, nonce, data, nil)

	header := make([]byte, 3)
	binary.BigEndian.PutUint16(header[0:2], uint16(len(encrypted)))
	header[2] = frameType

	if _, err := writer.Write(header); err != nil {
		return err
	}
	if _, err := writer.Write(encrypted); err != nil {
		return err
	}
	return nil
}
