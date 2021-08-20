package proxyprotocol

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
)

// HeaderV1 contains information relayed by the PROXY protocol version 1 (human-readable) header.
type HeaderV1 struct {
	SrcPort  int
	SrcIP    net.IP
	DestPort int
	DestIP   net.IP
}

func parseV1(r *bufio.Reader) (*HeaderV1, error) {
	buf := make([]byte, 0, 108)
	last := byte(0)
	for {
		b, err := r.ReadByte()
		if err != nil {
			return nil, &InvalidHeaderErr{Read: buf, error: err}
		}
		buf = append(buf, b)
		if last == '\r' && b == '\n' {
			break
		}
		if len(buf) == 108 {
			return nil, &InvalidHeaderErr{Read: buf, error: errors.New("header too long")}
		}
		last = b
	}
	if bytes.HasPrefix(buf, []byte("PROXY UNKNOWN")) {
		// From the documentation:
		//
		// For "UNKNOWN", the rest of the line before the
		// CRLF may be omitted by the sender, and the receiver must ignore anything
		// presented before the CRLF is found.
		return &HeaderV1{}, nil
	}
	var fam string
	var srcIPStr, dstIPStr string
	var srcPort, dstPort int
	n, err := fmt.Sscanf(string(buf), string(sigV1), &fam, &srcIPStr, &dstIPStr, &srcPort, &dstPort)
	if n == 0 && err != nil {
		return nil, &InvalidHeaderErr{Read: buf, error: err}
	}
	switch fam {
	case "TCP4", "TCP6":
		if err != nil {
			// couldn't parse IP/port
			return nil, &InvalidHeaderErr{Read: buf, error: err}
		}
	default:
		return nil, &InvalidHeaderErr{Read: buf, error: errors.New("unsupported INET protocol/family value")}
	}

	if srcPort < 0 || srcPort > 65535 {
		return nil, &InvalidHeaderErr{Read: buf, error: errors.New("invalid source port")}
	}
	if dstPort < 0 || dstPort > 65535 {
		return nil, &InvalidHeaderErr{Read: buf, error: errors.New("invalid destination port")}
	}

	validAddr := func(ip net.IP) bool {
		if ip == nil {
			return false
		}
		if fam == "TCP4" {
			return ip.To4() != nil
		}
		if fam == "TCP6" {
			return ip.To16() != nil
		}

		return false
	}

	srcIP := net.ParseIP(srcIPStr)
	if !validAddr(srcIP) {
		return nil, &InvalidHeaderErr{Read: buf, error: errors.New("invalid source address")}
	}
	dstIP := net.ParseIP(dstIPStr)
	if !validAddr(dstIP) {
		return nil, &InvalidHeaderErr{Read: buf, error: errors.New("invalid destination address")}
	}

	return &HeaderV1{
		SrcIP:    srcIP,
		DestIP:   dstIP,
		SrcPort:  srcPort,
		DestPort: dstPort,
	}, nil
}

// FromConn will populate header data from the given net.Conn.
//
// The RemoteAddr of the Conn will be considered the Source address/port
// and the LocalAddr of the Conn will be considered the Destination address/port for
// the purposes of the PROXY header if outgoing is false, if outgoing is true, the
// inverse is true.
func (h *HeaderV1) FromConn(c net.Conn, outgoing bool) {
	setIPPort := func(a *net.TCPAddr, ip *net.IP, port *int) {
		if a == nil {
			*ip = nil
			*port = 0
		} else {
			*ip = a.IP
			*port = a.Port
		}
	}

	rem, _ := c.RemoteAddr().(*net.TCPAddr)
	if outgoing {
		setIPPort(rem, &h.DestIP, &h.DestPort)
	} else {
		setIPPort(rem, &h.SrcIP, &h.SrcPort)
	}

	local, _ := c.LocalAddr().(*net.TCPAddr)
	if outgoing {
		setIPPort(local, &h.SrcIP, &h.SrcPort)
	} else {
		setIPPort(local, &h.DestIP, &h.DestPort)
	}
}

// Version always returns 1.
func (HeaderV1) Version() int { return 1 }

// SrcAddr returns the TCP source address.
func (h HeaderV1) SrcAddr() net.Addr { return &net.TCPAddr{IP: h.SrcIP, Port: h.SrcPort} }

// DestAddr returns the TCP destination address.
func (h HeaderV1) DestAddr() net.Addr { return &net.TCPAddr{IP: h.DestIP, Port: h.DestPort} }

// protoFam will return the protocol & family value for the current configuration.
//
// Possible values are: TCP4, TCP6, or UNKNOWN
func (h HeaderV1) protoFam() string {
	if h.DestPort >= 0 && h.DestPort <= 65535 && h.SrcPort >= 0 && h.SrcPort <= 65535 {
		src4 := h.SrcIP.To4() != nil
		dst4 := h.DestIP.To4() != nil
		if src4 && dst4 {
			return "TCP4"
		} else if !src4 && !dst4 && h.SrcIP.To16() != nil && h.DestIP.To16() != nil {
			return "TCP6"
		}
	}
	return "UNKNOWN"
}

// WriteTo will write the V1 header to w. The proto/fam will be set to UNKNOWN
// if source and dest IPs are of mismatched types, or any port is out of bounds.
func (h HeaderV1) WriteTo(w io.Writer) (int64, error) {
	var n int
	var err error
	fam := h.protoFam()
	if fam == "UNKNOWN" {
		n, err = io.WriteString(w, "PROXY UNKNOWN\r\n")
	} else {
		n, err = fmt.Fprintf(w, "PROXY %s %s %s %d %d\r\n",
			fam,
			h.SrcIP.String(),
			h.DestIP.String(),
			h.SrcPort,
			h.DestPort,
		)
	}

	return int64(n), err
}
