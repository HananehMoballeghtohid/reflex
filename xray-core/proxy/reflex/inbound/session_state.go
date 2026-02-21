package inbound

import (
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/proxy/reflex"
)

type sessionState struct {
	destSet bool
	dest    net.Destination
}

func (s *sessionState) handleDataFrame(payload []byte) (ack []byte, err error) {
	if !s.destSet {
		d, _, err := reflex.ParseConnectPayload(payload)
		if err != nil {
			return nil, err
		}
		s.dest = d
		s.destSet = true
		return []byte("OK"), nil
	}
	// after connect, no-op for now
	return nil, nil
}
