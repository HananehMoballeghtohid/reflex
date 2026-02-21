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

func writeClientHandshake(w io.Writer, hs reflex.ClientHandshake) error {
	var magic [4]byte
	binary.BigEndian.PutUint32(magic[:], reflex.ReflexMagic)
	if _, err := w.Write(magic[:]); err != nil {
		return err
	}

	if _, err := w.Write(hs.PublicKey[:]); err != nil {
		return err
	}
	if _, err := w.Write(hs.UserID[:]); err != nil {
		return err
	}

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

	if err := binary.Write(w, binary.BigEndian, uint64(hs.Timestamp)); err != nil {
		return err
	}

	if _, err := w.Write(hs.Nonce[:]); err != nil {
		return err
	}

	return nil
}

func readHeadersAndSomeBody(c stdnet.Conn) []byte {
	r := bufio.NewReader(c)
	var out bytes.Buffer

	for i := 0; i < 20; i++ {
		line, err := r.ReadString('\n')
		if err != nil {
			break
		}
		out.WriteString(line)
		if line == "\r\n" {
			break
		}
	}

	body := make([]byte, 256)
	n, _ := r.Read(body)
	out.Write(body[:n])

	_ = c.Close()
	return out.Bytes()
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

		clientPriv, clientPub := reflex.GenerateKeyPair()
		_ = clientPriv // not used in this test

		hs := reflex.ClientHandshake{
			PublicKey: clientPub,
			UserID:    userID,
			Timestamp: time.Now().Unix(),
			Nonce:     [16]byte{1, 1, 1},
		}
		_ = writeClientHandshake(cClient, hs)

		respCh <- readHeadersAndSomeBody(cClient)
	}()

	var srvConn xnet.Conn = cServer
	err := h.Process(context.Background(), xnet.Network_TCP, srvConn, nil)
	_ = cServer.Close()
	<-done

	if err != nil && err != io.EOF {
		t.Fatalf("unexpected error: %v", err)
	}

	resp := string(<-respCh)

	if !strings.Contains(resp, "HTTP/1.1 200 OK") {
		t.Fatalf("expected 200 OK, got: %q", resp)
	}

	marker := `"serverPublicKey":"`
	idx := strings.Index(resp, marker)
	if idx == -1 {
		t.Fatalf("missing serverPublicKey: %q", resp)
	}

	start := idx + len(marker)
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

		hs := reflex.ClientHandshake{
			UserID:    [16]byte{9, 9, 9},
			Timestamp: time.Now().Unix(),
			Nonce:     [16]byte{4, 5, 6},
		}
		_ = writeClientHandshake(cClient, hs)
		readHeadersAndSomeBody(cClient)
	}()

	var srvConn xnet.Conn = cServer
	_ = h.Process(context.Background(), xnet.Network_TCP, srvConn, nil)
	_ = cServer.Close()
	<-done
}

func TestReflexHTTPPostHandshake_OK(t *testing.T) {
	userID := [16]byte{0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe, 0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe}
	userStr := uuid.UUID(userID).String()

	h := &Handler{
		clients: []*protocol.MemoryUser{
			{Email: userStr, Account: &MemoryAccount{Id: userStr}},
		},
	}

	var raw bytes.Buffer
	hs := reflex.ClientHandshake{
		UserID:    userID,
		Timestamp: time.Now().Unix(),
		Nonce:     [16]byte{1, 1, 1},
	}

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
		_, _ = cClient.Write([]byte(req))
		respCh <- readHeadersAndSomeBody(cClient)
	}()

	var srvConn xnet.Conn = cServer
	err := h.Process(context.Background(), xnet.Network_TCP, srvConn, nil)
	_ = cServer.Close()
	<-done

	if err != nil && err != io.EOF {
		t.Fatalf("unexpected error: %v", err)
	}

	resp := string(<-respCh)
	if !strings.Contains(resp, "HTTP/1.1 200 OK") {
		t.Fatalf("expected 200 OK, got: %q", resp)
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
