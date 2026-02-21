package inbound

import (
	"encoding/binary"
	"testing"

	"github.com/xtls/xray-core/proxy/reflex"
)

func buildConnectPayloadDomain(host string, port uint16) []byte {
	b := make([]byte, 0, 64)
	b = append(b, reflex.CmdConnect)
	b = append(b, reflex.AtypDomain)
	b = append(b, byte(len(host)))
	b = append(b, []byte(host)...)

	p := make([]byte, 2)
	binary.BigEndian.PutUint16(p, port)
	b = append(b, p...)

	b = append(b, 0) // optlen
	return b
}

func TestSessionState_FirstDataIsConnect(t *testing.T) {
	var st sessionState
	payload := buildConnectPayloadDomain("example.com", 80)

	ack, err := st.handleDataFrame(payload)
	if err != nil {
		t.Fatal(err)
	}
	if string(ack) != "OK" {
		t.Fatalf("expected OK ack, got %q", string(ack))
	}
	if !st.destSet {
		t.Fatalf("destSet should be true")
	}
}
