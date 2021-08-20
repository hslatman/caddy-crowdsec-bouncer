package proxyprotocol

import (
	"bufio"
	"errors"
)

var (
	sigV1 = []byte("PROXY %s %s %s %d %d\r\n")
	sigV2 = []byte{0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A}
)

// InvalidHeaderErr contains the parsing error as well as all data read from the reader.
type InvalidHeaderErr struct {
	error
	Read []byte
}

// Parse will parse detect and return a V1 or V2 header, otherwise InvalidHeaderErr is returned.
func Parse(r *bufio.Reader) (Header, error) {
	b, err := r.ReadByte()
	if err != nil {
		return nil, err
	}
	r.UnreadByte()

	switch b {
	case sigV1[0]:
		return parseV1(r)
	case sigV2[0]:
		return parseV2(r)
	}

	return nil, &InvalidHeaderErr{error: errors.New("invalid signature")}
}
