package tests

import (
	"bufio"
	"bytes"
	"net"
	"testing"

	"github.com/xtls/xray-core/proxy/reflex"
)

func TestSession_WriteReadFrame_RoundTrip(t *testing.T) {
	key := bytes.Repeat([]byte{0x11}, 32)
	s1, err := reflex.NewSession(key)
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}
	s2, err := reflex.NewSession(key)
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}

	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()

	want := []byte("hello reflex")

	// writer side
	go func() {
		_ = s1.WriteFrame(c1, reflex.FrameTypeData, want)
	}()

	// reader side
	r := bufio.NewReader(c2)
	fr, err := s2.ReadFrame(r)
	if err != nil {
		t.Fatalf("ReadFrame: %v", err)
	}
	if fr.Type != reflex.FrameTypeData {
		t.Fatalf("frame type mismatch: got %v", fr.Type)
	}
	if !bytes.Equal(fr.Payload, want) {
		t.Fatalf("payload mismatch: got %q want %q", fr.Payload, want)
	}
}

func TestParseConnectPayload_Basic(t *testing.T) {

}