package reflex

import (
	"encoding/binary"
	"testing"

	"github.com/xtls/xray-core/common/net"
)

func buildConnect(cmd, atyp byte, addr []byte, port uint16) []byte {
	b := make([]byte, 0, 64)
	b = append(b, cmd)
	b = append(b, atyp)
	if atyp == AtypDomain {
		b = append(b, byte(len(addr)))
	}
	b = append(b, addr...)
	p := make([]byte, 2)
	binary.BigEndian.PutUint16(p, port)
	b = append(b, p...)
	b = append(b, 0) // optlen
	return b
}

func TestParseConnectPayload_IPv4(t *testing.T) {
	payload := buildConnect(CmdConnect, AtypIPv4, []byte{1, 2, 3, 4}, 80)
	dest, opts, err := ParseConnectPayload(payload)
	if err != nil {
		t.Fatal(err)
	}
	if len(opts) != 0 {
		t.Fatalf("expected no opts")
	}
	if dest.Port != net.Port(80) {
		t.Fatalf("port mismatch")
	}
}

func TestParseConnectPayload_Domain(t *testing.T) {
	payload := buildConnect(CmdConnect, AtypDomain, []byte("example.com"), 443)
	dest, _, err := ParseConnectPayload(payload)
	if err != nil {
		t.Fatal(err)
	}
	if dest.Port != net.Port(443) {
		t.Fatalf("port mismatch")
	}
}

func TestParseConnectPayload_BadCmd(t *testing.T) {
	payload := buildConnect(0x99, AtypIPv4, []byte{1, 2, 3, 4}, 80)
	_, _, err := ParseConnectPayload(payload)
	if err == nil {
		t.Fatalf("expected error")
	}
}
