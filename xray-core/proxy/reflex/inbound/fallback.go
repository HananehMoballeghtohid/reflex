package inbound

import (
	"bufio"
	"context"
	"fmt"
	"io"
	stdnet "net"
	"time"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
)

func (h *Handler) handleFallback(ctx context.Context, reader *bufio.Reader, conn net.Conn) error {
	_ = ctx

	if h.fallback == nil || h.fallback.Dest == 0 {
		_, _ = conn.Write([]byte("HTTP/1.1 403 Forbidden\r\nContent-Type: text/plain\r\nContent-Length: 9\r\n\r\nforbidden"))
		return errors.New("reflex: no fallback configured").AtWarning()
	}

	wrapped := &preloadedConn{
		Reader: reader,
		Conn:   conn,
	}

	targetAddr := fmt.Sprintf("127.0.0.1:%d", h.fallback.Dest)
	target, err := stdnet.Dial("tcp", targetAddr)
	if err != nil {
		_, _ = conn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\nContent-Type: text/plain\r\nContent-Length: 11\r\n\r\nbad gateway"))
		return errors.New("reflex: fallback dial failed").Base(err).AtWarning()
	}
	defer target.Close()
	defer wrapped.Close()

	// Basic idle deadlines to avoid stuck connections
	_ = conn.SetDeadline(time.Now().Add(2 * time.Minute))
	_ = target.SetDeadline(time.Now().Add(2 * time.Minute))

	errCh := make(chan error, 2)

	go func() {
		_, e := io.Copy(target, wrapped)
		errCh <- e
	}()
	go func() {
		_, e := io.Copy(wrapped, target)
		errCh <- e
	}()

	// Wait first to finish, then close both to stop the other direction, then wait second.
	first := <-errCh
	_ = wrapped.Close()
	_ = target.Close()
	<-errCh

	if first == nil || first == io.EOF {
		return nil
	}
	return errors.New("reflex: fallback copy error").Base(first).AtWarning()
}
