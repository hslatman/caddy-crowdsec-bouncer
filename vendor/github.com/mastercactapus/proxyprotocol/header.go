package proxyprotocol

import (
	"io"
	"net"
)

// Header provides information decoded from a PROXY header.
type Header interface {
	Version() int
	SrcAddr() net.Addr
	DestAddr() net.Addr

	WriteTo(io.Writer) (int64, error)
}
