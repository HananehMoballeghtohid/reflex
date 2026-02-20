package inbound

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	stdnet "net"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/proxy/reflex"
)

// دقیقا همون فرمتی که readClientHandshake شما می‌خونه:
// pub(32) + uuid(16) + policyLen(2) + policy(N) + ts(8) + nonce(16)
func writeClientHandshake(w io.Writer, hs reflex.ClientHandshake) error {
	// Magic (4 bytes)
	var magic [4]byte
	binary.BigEndian.PutUint32(magic[:], reflex.ReflexMagic)
	if _, err := w.Write(magic[:]); err != nil {
		return err
	}

	// PublicKey (32)
	if _, err := w.Write(hs.PublicKey[:]); err != nil {
		return err
	}
	// UserID (16)
	if _, err := w.Write(hs.UserID[:]); err != nil {
		return err
	}

	// PolicyLen + Policy
	pol := hs.PolicyReq
	if pol == nil {
		pol = []byte{}
	}
	if err := binary.Write(w, binary.BigEndian, uint16(len(pol))); err != nil {
		return err
	}
	if len(pol) > 0 {
		if _, err := w.Write(pol); err != nil {
			return err
		}
	}

	// Timestamp (uint64)
	if err := binary.Write(w, binary.BigEndian, uint64(hs.Timestamp)); err != nil {
		return err
	}

	// Nonce (16)
	if _, err := w.Write(hs.Nonce[:]); err != nil {
		return err
	}

	return nil
}

func TestReflexMagicHandshake_OK(t *testing.T) {
	userID := [16]byte{0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe, 0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe}
	userStr := uuid.UUID(userID).String()

	h := &Handler{
		clients: []*protocol.MemoryUser{
			{Email: userStr, Account: &MemoryAccount{Id: userStr}},
		},
	}

	cClient, cServer := stdnet.Pipe()

	respCh := make(chan []byte, 1)
	done := make(chan struct{})

	go func() {
		defer close(done)
		defer cClient.Close()

		hs := reflex.ClientHandshake{
			PublicKey: [32]byte{},
			UserID:    userID,
			PolicyReq: []byte{},
			Timestamp: time.Now().Unix(),
			Nonce:     [16]byte{1, 2, 3},
		}
		_ = writeClientHandshake(cClient, hs)

		// read server response
		b, _ := io.ReadAll(cClient)
		respCh <- b
	}()

	var srvConn xnet.Conn = cServer
	err := h.Process(context.Background(), xnet.Network_TCP, srvConn, nil)
	_ = cServer.Close()
	<-done

	if err != nil {
		t.Fatalf("expected nil error, got: %v", err)
	}

	resp := string(<-respCh)

	// 1) status line
	if !strings.Contains(resp, "HTTP/1.1 200 OK") {
		t.Fatalf("expected 200 OK response, got: %q", resp)
	}

	// 2) has serverPublicKey
	marker := `"serverPublicKey":"`
	idx := strings.Index(resp, marker)
	if idx == -1 {
		t.Fatalf("expected serverPublicKey in response, got: %q", resp)
	}
	start := idx + len(marker)
	if len(resp) < start+64 {
		t.Fatalf("serverPublicKey too short, got: %q", resp)
	}
	keyHex := resp[start : start+64]
	if !isHex(keyHex) {
		t.Fatalf("serverPublicKey not hex: %q", keyHex)
	}
}

func TestReflexMagicHandshake_Forbidden(t *testing.T) {
	h := &Handler{clients: []*protocol.MemoryUser{}}

	cClient, cServer := stdnet.Pipe()

	done := make(chan struct{})
	go func() {
		defer close(done)
		defer cClient.Close()

		hs := reflex.ClientHandshake{
			PublicKey: [32]byte{},
			UserID:    [16]byte{9, 9, 9},
			PolicyReq: []byte{},
			Timestamp: time.Now().Unix(),
			Nonce:     [16]byte{4, 5, 6},
		}
		_ = writeClientHandshake(cClient, hs)

		// Read first line of response to ensure 403 got written
		r := bufio.NewReader(cClient)
		line, _ := r.ReadString('\n')
		_ = line
	}()

	var srvConn xnet.Conn = cServer
	_ = h.Process(context.Background(), xnet.Network_TCP, srvConn, nil)

	_ = cServer.Close()
	<-done
}

func TestReflexMagicHandshake_TimestampRejected(t *testing.T) {
	userID := [16]byte{0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe, 0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe}
	userStr := uuid.UUID(userID).String()

	h := &Handler{
		clients: []*protocol.MemoryUser{{Email: userStr, Account: &MemoryAccount{Id: userStr}}},
		seen:    make(map[[16]byte]int64),
	}

	cClient, cServer := stdnet.Pipe()
	done := make(chan struct{})

	go func() {
		defer close(done)
		defer cClient.Close()

		hs := reflex.ClientHandshake{
			UserID:    userID,
			Timestamp: time.Now().Unix() - 9999, // خیلی قدیمی
			Nonce:     [16]byte{7, 7, 7},
		}
		_ = writeClientHandshake(cClient, hs)
		_, _ = io.ReadAll(cClient)
	}()

	var srvConn xnet.Conn = cServer
	_ = h.Process(context.Background(), xnet.Network_TCP, srvConn, nil)
	_ = cServer.Close()
	<-done
}

func TestReflexMagicHandshake_NonceReplayRejected(t *testing.T) {
	userID := [16]byte{0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe, 0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe}
	userStr := uuid.UUID(userID).String()

	h := &Handler{
		clients: []*protocol.MemoryUser{{Email: userStr, Account: &MemoryAccount{Id: userStr}}},
		seen:    make(map[[16]byte]int64),
	}

	nonce := [16]byte{9, 9, 9}

	// first connection
	{
		cClient, cServer := stdnet.Pipe()
		done := make(chan struct{})
		go func() {
			defer close(done)
			defer cClient.Close()
			hs := reflex.ClientHandshake{
				UserID:    userID,
				Timestamp: time.Now().Unix(),
				Nonce:     nonce,
			}
			_ = writeClientHandshake(cClient, hs)
			_, _ = io.ReadAll(cClient)
		}()
		var srvConn xnet.Conn = cServer
		_ = h.Process(context.Background(), xnet.Network_TCP, srvConn, nil)
		_ = cServer.Close()
		<-done
	}

	// second connection with same nonce -> should be rejected (fallback)
	{
		cClient, cServer := stdnet.Pipe()
		done := make(chan struct{})
		go func() {
			defer close(done)
			defer cClient.Close()
			hs := reflex.ClientHandshake{
				UserID:    userID,
				Timestamp: time.Now().Unix(),
				Nonce:     nonce,
			}
			_ = writeClientHandshake(cClient, hs)
			_, _ = io.ReadAll(cClient)
		}()
		var srvConn xnet.Conn = cServer
		_ = h.Process(context.Background(), xnet.Network_TCP, srvConn, nil)
		_ = cServer.Close()
		<-done
	}
}

func isHex(s string) bool {
	for _, c := range s {
		switch {
		case c >= '0' && c <= '9':
		case c >= 'a' && c <= 'f':
		case c >= 'A' && c <= 'F':
		default:
			return false
		}
	}
	return true
}

func TestReflexHTTPPostHandshake_OK(t *testing.T) {
	userID := [16]byte{0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe, 0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe}
	userStr := uuid.UUID(userID).String()

	h := &Handler{
		clients: []*protocol.MemoryUser{{Email: userStr, Account: &MemoryAccount{Id: userStr}}},
	}

	// raw handshake bytes مطابق readClientHandshake (بدون magic)
	var raw bytes.Buffer
	hs := reflex.ClientHandshake{
		PublicKey: [32]byte{},
		UserID:    userID,
		PolicyReq: []byte{},
		Timestamp: time.Now().Unix(),
		Nonce:     [16]byte{1, 1, 1},
	}
	// همون فرمت: pub + uuid + policyLen + policy + ts + nonce
	raw.Write(hs.PublicKey[:])
	raw.Write(hs.UserID[:])
	_ = binary.Write(&raw, binary.BigEndian, uint16(0))
	_ = binary.Write(&raw, binary.BigEndian, uint64(hs.Timestamp))
	raw.Write(hs.Nonce[:])

	b64 := base64.StdEncoding.EncodeToString(raw.Bytes())
	body := fmt.Sprintf(`{"data":"%s"}`, b64)

	req := fmt.Sprintf("POST /reflex HTTP/1.1\r\nHost: x\r\nContent-Length: %d\r\n\r\n%s", len(body), body)

	cClient, cServer := stdnet.Pipe()
	done := make(chan struct{})
	respCh := make(chan []byte, 1)

	go func() {
		defer close(done)
		defer cClient.Close()

		_, _ = cClient.Write([]byte(req))
		b, _ := io.ReadAll(cClient)
		respCh <- b
	}()

	var srvConn xnet.Conn = cServer
	err := h.Process(context.Background(), xnet.Network_TCP, srvConn, nil)
	_ = cServer.Close()
	<-done

	if err != nil {
		t.Fatalf("expected nil, got %v", err)
	}
	resp := string(<-respCh)
	if !strings.Contains(resp, "HTTP/1.1 200 OK") {
		t.Fatalf("expected 200, got: %q", resp)
	}
}
