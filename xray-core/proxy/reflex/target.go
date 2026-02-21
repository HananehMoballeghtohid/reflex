package reflex

import (
	"encoding/binary"
	"errors"

	"github.com/xtls/xray-core/common/net"
)

const (
	CmdConnect = 0x01

	AtypIPv4   = 0x01
	AtypDomain = 0x03
	AtypIPv6   = 0x04
)

func ParseConnectPayload(b []byte) (net.Destination, []byte, error) {
	if len(b) < 5 {
		return net.Destination{}, nil, errors.New("connect payload too short")
	}
	cmd := b[0]
	if cmd != CmdConnect {
		return net.Destination{}, nil, errors.New("unsupported cmd")
	}

	atyp := b[1]
	i := 2

	var addr net.Address
	switch atyp {
	case AtypIPv4:
		if len(b) < i+4+2+1 {
			return net.Destination{}, nil, errors.New("ipv4 payload too short")
		}
		addr = net.IPAddress(b[i : i+4])
		i += 4
	case AtypIPv6:
		if len(b) < i+16+2+1 {
			return net.Destination{}, nil, errors.New("ipv6 payload too short")
		}
		addr = net.IPAddress(b[i : i+16])
		i += 16
	case AtypDomain:
		if len(b) < i+1+2+1 {
			return net.Destination{}, nil, errors.New("domain payload too short")
		}
		l := int(b[i])
		i++
		if len(b) < i+l+2+1 {
			return net.Destination{}, nil, errors.New("domain payload too short")
		}
		addr = net.DomainAddress(string(b[i : i+l]))
		i += l
	default:
		return net.Destination{}, nil, errors.New("unknown atyp")
	}

	port := binary.BigEndian.Uint16(b[i : i+2])
	i += 2

	optLen := int(b[i])
	i++

	if len(b) < i+optLen {
		return net.Destination{}, nil, errors.New("options truncated")
	}
	opts := b[i : i+optLen]

	dest := net.TCPDestination(addr, net.Port(port))
	return dest, opts, nil
}
