package inbound

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"strconv"
	"strings"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/proxy/reflex"
)

type httpBody struct {
	Data string `json:"data"`
}

func (h *Handler) handleReflexHTTP(reader *bufio.Reader, conn net.Conn, dispatcher routing.Dispatcher, ctx context.Context) error {
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

	// 6) decode raw handshake bytes using the same reader-based decoder
	return readClientHandshake(bufio.NewReader(bytes.NewReader(raw)))
}
