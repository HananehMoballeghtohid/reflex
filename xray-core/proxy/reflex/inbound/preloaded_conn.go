package inbound

import (
	"bufio"
	"io"
)

// preloadedConn باعث می‌شه Read از روی bufio.Reader انجام بشه
// یعنی بایت‌هایی که Peek کردیم هم هنوز قابل خواندن هستن.
type preloadedConn struct {
	Reader *bufio.Reader
	Conn   io.ReadWriteCloser
}

func (pc *preloadedConn) Read(b []byte) (int, error)  { return pc.Reader.Read(b) }
func (pc *preloadedConn) Write(b []byte) (int, error) { return pc.Conn.Write(b) }
func (pc *preloadedConn) Close() error                { return pc.Conn.Close() }
