package inbound

import (
	"bufio"
	"context"
	"fmt"
	"io"
	stdnet "net"
	"testing"
	"time"

	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/features/routing"
)

func TestFallback_ForwardsHTTP(t *testing.T) {
	// Backend ساده
	ln, err := stdnet.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	port := ln.Addr().(*stdnet.TCPAddr).Port

	// accept backend
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()

		r := bufio.NewReader(c)
		line, err := r.ReadString('\n')
		if err != nil || line == "" {
			return
		}

		_, _ = io.WriteString(c, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK")
	}()

	h := &Handler{
		fallback: &FallbackConfig{Dest: uint32(port)},
	}

	client, server := stdnet.Pipe()
	defer client.Close()
	defer server.Close()

	// کلاینت یه HTTP request خیلی عادی می‌فرسته (نه Reflex)
	req := "GET / HTTP/1.1\r\nHost: example\r\n\r\n"

	done := make(chan string, 1)
	go func() {
		_, _ = io.WriteString(client, req)
		_ = client.SetReadDeadline(time.Now().Add(2 * time.Second))
		b, _ := io.ReadAll(client)
		done <- string(b)
	}()

	// xray net.Conn سازگار با std net.Conn هست تو تست‌های تو
	var srvConn xnet.Conn = server
	_ = h.Process(context.Background(), xnet.Network_TCP, srvConn, routing.Dispatcher(nil))

	resp := <-done
	if resp == "" || resp[:12] != "HTTP/1.1 200" {
		t.Fatalf("expected backend HTTP response, got: %q", resp)
	}
	fmt.Println(resp)
}
