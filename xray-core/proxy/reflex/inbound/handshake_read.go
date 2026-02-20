package inbound

import (
	"bufio"
	"encoding/binary"
	"io"

	"github.com/xtls/xray-core/proxy/reflex"
)

func readClientHandshake(r *bufio.Reader) (reflex.ClientHandshake, error) {
	var hs reflex.ClientHandshake

	if _, err := io.ReadFull(r, hs.PublicKey[:]); err != nil {
		return hs, err
	}
	if _, err := io.ReadFull(r, hs.UserID[:]); err != nil {
		return hs, err
	}

	var n uint16
	if err := binary.Read(r, binary.BigEndian, &n); err != nil {
		return hs, err
	}
	if n > 0 {
		hs.PolicyReq = make([]byte, n)
		if _, err := io.ReadFull(r, hs.PolicyReq); err != nil {
			return hs, err
		}
	}

	var ts uint64
	if err := binary.Read(r, binary.BigEndian, &ts); err != nil {
		return hs, err
	}
	hs.Timestamp = int64(ts)

	if _, err := io.ReadFull(r, hs.Nonce[:]); err != nil {
		return hs, err
	}

	return hs, nil
}
