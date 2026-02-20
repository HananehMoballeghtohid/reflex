package inbound

import (
	"bufio"
	"context"
	"fmt"
	"io"
	stdnet "net"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
)

func (h *Handler) handleFallback(ctx context.Context, reader *bufio.Reader, conn net.Conn) error {
	_ = ctx

	if h.fallback == nil || h.fallback.Dest == 0 {
		return errors.New("reflex: no fallback configured").AtWarning()
	}

	wrapped := &preloadedConn{
		Reader: reader,
		Conn:   conn,
	}

	targetAddr := fmt.Sprintf("127.0.0.1:%d", h.fallback.Dest)
	target, err := stdnet.Dial("tcp", targetAddr)
	if err != nil {
		return errors.New("reflex: fallback dial failed").Base(err).AtWarning()
	}
	defer target.Close()
	defer wrapped.Close()

	errCh := make(chan error, 2)

	go func() {
		_, e := io.Copy(target, wrapped)
		errCh <- e
	}()
	go func() {
		_, e := io.Copy(wrapped, target)
		errCh <- e
	}()

	<-errCh
	return nil
}
