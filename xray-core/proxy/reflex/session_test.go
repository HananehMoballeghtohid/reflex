package reflex

import (
	"bytes"
	"net"
	"testing"
)

func TestSession_FrameRoundTrip(t *testing.T) {
	key := bytes.Repeat([]byte{0x11}, 32)

	sender, err := NewSession(key)
	if err != nil {
		t.Fatalf("NewSession sender: %v", err)
	}
	receiver, err := NewSession(key)
	if err != nil {
		t.Fatalf("NewSession receiver: %v", err)
	}

	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()

	want := []byte("hello reflex frame")

	done := make(chan struct{})
	go func() {
		defer close(done)
		if err := sender.WriteFrame(c1, FrameTypeData, want); err != nil {
			t.Errorf("WriteFrame: %v", err)
			return
		}
	}()

	f, err := receiver.ReadFrame(c2)
	<-done
	if err != nil {
		t.Fatalf("ReadFrame: %v", err)
	}

	if f.Type != FrameTypeData {
		t.Fatalf("type: got %v want %v", f.Type, FrameTypeData)
	}
	if !bytes.Equal(f.Payload, want) {
		t.Fatalf("payload mismatch: got %q want %q", f.Payload, want)
	}
}
