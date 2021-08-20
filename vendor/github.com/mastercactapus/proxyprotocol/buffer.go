package proxyprotocol

import "io"

type buffer struct {
	data []byte
	size int
}

func newBuffer(pos, cap int) *buffer {
	return &buffer{
		size: pos,
		data: make([]byte, pos, cap),
	}
}

func (b *buffer) Seek(pos int) {
	b.data = b.data[:pos]
	if pos > b.size {
		b.size = pos
	}
}
func (b *buffer) Write(p []byte) (int, error) {
	b.data = append(b.data, p...)
	l := len(b.data)
	if l > b.size {
		b.size = l
	}
	return len(p), nil
}
func (b *buffer) WriteTo(w io.Writer) (int64, error) {
	n, err := w.Write(b.data[:b.size])
	return int64(n), err
}
func (b *buffer) Len() int { return b.size }
