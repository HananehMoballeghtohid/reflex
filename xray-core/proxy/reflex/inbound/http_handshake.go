package inbound

import (
	"bufio"
	"encoding/binary"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"strconv"
	"strings"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/proxy/reflex"
	"github.com/xtls/xray-core/transport/internet/stat"
)

type httpBody struct {
	Data string `json:"data"`
}

func (h *Handler) handleReflexHTTP(reader *bufio.Reader, conn stat.Connection, dispatcher routing.Dispatcher, ctx context.Context) error {
	hs, err := readHTTPPostHandshake(reader)
	if err != nil {
		body := `{"error":"bad handshake"}`
		resp := "HTTP/1.1 400 Bad Request\r\nContent-Type: application/json\r\nContent-Length: " +
			strconv.Itoa(len(body)) + "\r\n\r\n" + body
		_, _ = conn.Write([]byte(resp))
		return errors.New("reflex: bad http-post handshake").Base(err).AtWarning()
	}
	return h.processHandshake(ctx, reader, conn, dispatcher, hs)
}

func readHTTPPostHandshake(r *bufio.Reader) (reflex.ClientHandshake, error) {
	var hs reflex.ClientHandshake

	// 1) request line
	line, err := r.ReadString('\n')
	if err != nil {
		return hs, err
	}
	if !strings.HasPrefix(line, "POST ") {
		return hs, errors.New("not a POST request")
	}

	// 2) headers
	contentLen := -1
	for {
		hline, err := r.ReadString('\n')
		if err != nil {
			return hs, err
		}
		hline = strings.TrimRight(hline, "\r\n")
		if hline == "" {
			break
		}
		parts := strings.SplitN(hline, ":", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.ToLower(strings.TrimSpace(parts[0]))
		val := strings.TrimSpace(parts[1])
		if key == "content-length" {
			n, err := strconv.Atoi(val)
			if err == nil {
				contentLen = n
			}
		}
	}

	if contentLen < 0 {
		return hs, errors.New("missing content-length")
	}
	if contentLen > 4096 {
		return hs, errors.New("content-length too large")
	}

	// 3) body
	body := make([]byte, contentLen)
	if _, err := io.ReadFull(r, body); err != nil {
		return hs, err
	}

	// 4) json {"data":"..."}
	var b httpBody
	if err := json.Unmarshal(body, &b); err != nil {
		return hs, err
	}
	if b.Data == "" {
		return hs, errors.New("missing data")
	}

	// 5) base64 decode
	raw, err := base64.StdEncoding.DecodeString(b.Data)
	if err != nil {
		return hs, err
	}

	// 6) parse raw handshake bytes (HTTP format: PK | UID | TS | Nonce | PolicyReq)
	if len(raw) < 32+16+8+16 {
		return hs, errors.New("handshake too short")
	}

	offset := 0

	// PublicKey (32)
	copy(hs.PublicKey[:], raw[offset:offset+32])
	offset += 32

	// UserID (16)
	copy(hs.UserID[:], raw[offset:offset+16])
	offset += 16

	// Timestamp (8)
	ts := binary.BigEndian.Uint64(raw[offset : offset+8])
	hs.Timestamp = int64(ts)
	offset += 8

	// Nonce (16)
	copy(hs.Nonce[:], raw[offset:offset+16])
	offset += 16

	// PolicyReq (rest)
	if offset < len(raw) {
		hs.PolicyReq = make([]byte, len(raw)-offset)
		copy(hs.PolicyReq, raw[offset:])
	}

	return hs, nil
}	
