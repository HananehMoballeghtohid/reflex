package inbound

import (
	"bufio"
	"io"
)

type preloadedConn struct {
	Reader *bufio.Reader
	Conn   io.ReadWriteCloser
}

func (pc *preloadedConn) Read(b []byte) (int, error)  { return pc.Reader.Read(b) }
func (pc *preloadedConn) Write(b []byte) (int, error) { return pc.Conn.Write(b) }
func (pc *preloadedConn) Close() error                { return pc.Conn.Close() }
