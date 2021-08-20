package proxyprotocol

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strings"
)

// HeaderV2 contains information relayed by the PROXY protocol version 2 (binary) header.
type HeaderV2 struct {
	Command Cmd
	Src     net.Addr
	Dest    net.Addr
}

type rawV2 struct {
	Sig      [12]byte
	VerCmd   byte
	FamProto byte
	Len      uint16
}

func parseV2(r *bufio.Reader) (*HeaderV2, error) {
	buf := make([]byte, 232)
	n, err := io.ReadFull(r, buf[:16])
	if err != nil {
		return nil, &InvalidHeaderErr{Read: buf[:n], error: err}
	}
	var rawHdr rawV2
	err = binary.Read(bytes.NewReader(buf), binary.BigEndian, &rawHdr)
	if err != nil {
		return nil, &InvalidHeaderErr{Read: buf[:16], error: err}
	}
	if !bytes.Equal(rawHdr.Sig[:], sigV2) {
		return nil, &InvalidHeaderErr{Read: buf[:16], error: errors.New("invalid signature")}
	}
	// highest 4 indicate version
	if (rawHdr.VerCmd >> 4) != 2 {
		return nil, &InvalidHeaderErr{Read: buf[:16], error: errors.New("invalid v2 version value")}
	}
	var h HeaderV2
	// lowest 4 = command (0xf == 0b00001111)
	h.Command = Cmd(rawHdr.VerCmd & 0xf)
	if h.Command > CmdProxy {
		return nil, &InvalidHeaderErr{Read: buf[:16], error: errors.New("invalid v2 command")}
	}

	// highest 4 indicate address family
	switch rawHdr.FamProto >> 4 {
	case 0: // local
		if rawHdr.Len != 0 {
			return nil, &InvalidHeaderErr{Read: buf[:16], error: errors.New("invalid length")}
		}
	case 1: // ipv4
		if rawHdr.Len != 12 {
			return nil, &InvalidHeaderErr{Read: buf[:16], error: errors.New("invalid length")}
		}
	case 2: // ipv6
		if rawHdr.Len != 36 {
			return nil, &InvalidHeaderErr{Read: buf[:16], error: errors.New("invalid length")}
		}
	case 3: // unix
		if rawHdr.Len != 216 {
			return nil, &InvalidHeaderErr{Read: buf[:16], error: errors.New("invalid length")}
		}
	default:
		return nil, &InvalidHeaderErr{Read: buf[:16], error: errors.New("invalid v2 address family")}
	}

	// lowest 4 = transport protocol (0xf == 0b00001111)
	if (rawHdr.FamProto & 0xf) > 2 {
		return nil, &InvalidHeaderErr{Read: buf[:16], error: errors.New("invalid v2 transport protocol")}
	}

	buf = buf[:16+int(rawHdr.Len)]

	n, err = io.ReadFull(r, buf[16:])
	if err != nil {
		return nil, &InvalidHeaderErr{Read: buf[:16+n], error: err}
	}

	if h.Command == CmdLocal {
		// ignore address information for local
		return &h, nil
	}

	switch rawHdr.FamProto {
	case 0x11: // TCP over IPv4
		h.Src = &net.TCPAddr{
			IP:   net.IP(buf[16:20]),
			Port: int(binary.BigEndian.Uint16(buf[24:])),
		}
		h.Dest = &net.TCPAddr{
			IP:   net.IP(buf[20:24]),
			Port: int(binary.BigEndian.Uint16(buf[26:])),
		}
	case 0x12: // UDP over IPv4
		h.Src = &net.UDPAddr{
			IP:   net.IP(buf[16:20]),
			Port: int(binary.BigEndian.Uint16(buf[24:])),
		}
		h.Dest = &net.UDPAddr{
			IP:   net.IP(buf[20:24]),
			Port: int(binary.BigEndian.Uint16(buf[26:])),
		}
	case 0x21: // TCP over IPv6
		h.Src = &net.TCPAddr{
			IP:   net.IP(buf[16:32]),
			Port: int(binary.BigEndian.Uint16(buf[48:])),
		}
		h.Dest = &net.TCPAddr{
			IP:   net.IP(buf[32:48]),
			Port: int(binary.BigEndian.Uint16(buf[50:])),
		}
	case 0x22: // UDP over IPv6
		h.Src = &net.UDPAddr{
			IP:   net.IP(buf[16:32]),
			Port: int(binary.BigEndian.Uint16(buf[48:])),
		}
		h.Dest = &net.UDPAddr{
			IP:   net.IP(buf[32:48]),
			Port: int(binary.BigEndian.Uint16(buf[50:])),
		}
	case 0x31: // UNIX stream
		h.Src = &net.UnixAddr{
			Net:  "unix",
			Name: strings.TrimRight(string(buf[16:124]), "\x00"),
		}
		h.Dest = &net.UnixAddr{
			Net:  "unix",
			Name: strings.TrimRight(string(buf[124:232]), "\x00"),
		}
	case 0x32: // UNIX datagram
		h.Src = &net.UnixAddr{
			Net:  "unixgram",
			Name: strings.TrimRight(string(buf[16:124]), "\x00"),
		}
		h.Dest = &net.UnixAddr{
			Net:  "unixgram",
			Name: strings.TrimRight(string(buf[124:232]), "\x00"),
		}
	}

	return &h, nil
}

// FromConn will populate header data from the given net.Conn.
//
// The RemoteAddr of the Conn will be considered the Source address/port
// and the LocalAddr of the Conn will be considered the Destination address/port for
// the purposes of the PROXY header if outgoing is false, if outgoing is true, the
// inverse is true.
func (h *HeaderV2) FromConn(c net.Conn, outgoing bool) {
	h.Command = CmdProxy
	if outgoing {
		h.Src = c.LocalAddr()
		h.Dest = c.RemoteAddr()
	} else {
		h.Src = c.RemoteAddr()
		h.Dest = c.LocalAddr()
	}
}

// Version always returns 2.
func (HeaderV2) Version() int { return 2 }

// SrcAddr returns the source address as TCP, UDP, Unix, or nil depending on Protocol and Family.
func (h HeaderV2) SrcAddr() net.Addr { return h.Src }

// DestAddr returns the destination address as TCP, UDP, Unix, or nil depending on Protocol and Family.
func (h HeaderV2) DestAddr() net.Addr { return h.Dest }

// WriteTo will write the V2 header to w. Command must be CommandProxy
// to send any address data.
func (h HeaderV2) WriteTo(w io.Writer) (int64, error) {
	if h.Command > CmdProxy {
		return 0, errors.New("invalid command")
	}

	var rawHdr rawV2
	copy(rawHdr.Sig[:], sigV2)
	rawHdr.VerCmd = (2 << 4) | (0xf & byte(h.Command))
	sendEmpty := func() (int64, error) {
		err := binary.Write(w, binary.BigEndian, rawHdr)
		if err != nil {
			return 0, err
		}
		return 16, nil
	}
	if h.Command == CmdLocal {
		return sendEmpty()
	}

	buf := newBuffer(16, 232)

	setAddr := func(srcIP, dstIP net.IP, srcPort, dstPort int) (fam byte) {
		src := srcIP.To4()
		dst := dstIP.To4()
		if src != nil && dst != nil {
			fam = 0x1 // INET
		} else if src == nil && dst == nil {
			src = srcIP.To16()
			dst = dstIP.To16()
			fam = 0x2 // INET6
		}
		if src == nil || dst == nil {
			return 0 // UNSPEC
		}

		buf.Write(src)
		buf.Write(dst)
		binary.Write(buf, binary.BigEndian, uint16(srcPort))
		binary.Write(buf, binary.BigEndian, uint16(dstPort))

		return fam
	}

	switch src := h.Src.(type) {
	case *net.TCPAddr:
		dst, ok := h.Dest.(*net.TCPAddr)
		if !ok {
			return sendEmpty()
		}
		addrFam := setAddr(src.IP, dst.IP, src.Port, dst.Port)
		if addrFam == 0 {
			return sendEmpty()
		}
		rawHdr.FamProto = (addrFam << 4) | 0x1 // 0x1 == STREAM
	case *net.UDPAddr:
		dst, ok := h.Dest.(*net.UDPAddr)
		if !ok {
			return sendEmpty()
		}
		addrFam := setAddr(src.IP, dst.IP, src.Port, dst.Port)
		if addrFam == 0 {
			return sendEmpty()
		}
		rawHdr.FamProto = (addrFam << 4) | 0x2 // 0x2 == DGRAM
	case *net.UnixAddr:
		dst, ok := h.Dest.(*net.UnixAddr)
		if !ok || src.Net != dst.Net {
			return sendEmpty()
		}
		if len(src.Name) > 108 || len(dst.Name) > 108 {
			// name too long to use
			return sendEmpty()
		}
		switch src.Net {
		case "unix":
			rawHdr.FamProto = (0x3 << 4) | 0x1 // 0x3 (UNIX) | 0x1 (STREAM)
		case "unixgram":
			rawHdr.FamProto = (0x3 << 4) | 0x2 // 0x3 (UNIX) | 0x2 (DGRAM)
		default:
			return sendEmpty()
		}
		buf.Write([]byte(src.Name))
		buf.Seek(108 + 16)
		buf.Write([]byte(dst.Name))
		buf.Seek(232)
	}

	rawHdr.Len = uint16(buf.Len() - 16)

	buf.Seek(0)
	err := binary.Write(buf, binary.BigEndian, rawHdr)
	if err != nil {
		return 0, err
	}

	return buf.WriteTo(w)
}
