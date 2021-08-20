package proxyprotocol

import (
	"net"
	"sort"
	"sync"
	"time"
)

// Listener wraps a net.Listener automatically wrapping new connections with PROXY protocol support.
type Listener struct {
	net.Listener

	filter []Rule
	t      time.Duration

	mx sync.RWMutex
}

// NewListener will wrap nl, automatically handling PROXY headers for all connections.
// To expect PROXY headers only from certain addresses/subnets, use SetFilter.
//
// By default, all connections must provide a PROXY header within the specified timeout.
func NewListener(nl net.Listener, t time.Duration) *Listener {
	l := &Listener{
		Listener: nl,
		t:        t,
	}
	return l
}

// Accept waits for and returns the next connection to the listener, wrapping it with NewConn if the RemoteAddr matches
// any registered rules.
func (l *Listener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}

	l.mx.RLock()
	filter := l.filter
	t := l.t
	l.mx.RUnlock()

	if len(filter) == 0 {
		if t == 0 {
			return NewConn(c, time.Time{}), nil
		}
		return NewConn(c, time.Now().Add(t)), nil
	}

	var remoteIP net.IP
	switch r := c.RemoteAddr().(type) {
	case *net.TCPAddr:
		remoteIP = r.IP
	case *net.UDPAddr:
		remoteIP = r.IP
	default:
		return c, nil
	}

	for _, n := range filter {
		if n.Subnet.Contains(remoteIP) {
			if n.Timeout == 0 {
				return NewConn(c, time.Time{}), nil
			}
			return NewConn(c, time.Now().Add(n.Timeout)), nil
		}
	}
	return c, nil
}

// SetDefaultTimeout sets the default timeout, used when the subnet filter is nil.
//
// SetDefaultTimeout is safe to call from multiple goroutines while the listener is in use.
func (l *Listener) SetDefaultTimeout(t time.Duration) {
	l.mx.Lock()
	l.t = t
	l.mx.Unlock()
}

// Filter returns the current set of filter rules.
//
// Filter is safe to call from multiple goroutines while the listener is in use.
func (l *Listener) Filter() []Rule {
	l.mx.RLock()
	filter := l.filter
	l.mx.RUnlock()
	f := make([]Rule, len(filter))
	copy(f, filter)
	return f
}

// SetFilter allows limiting PROXY header requirements to matching Subnets with an optional timeout.
// If filter is nil, all connections will be required to provide a PROXY header (the default).
//
// Connections not matching any rule will be returned directly without reading a PROXY header.
//
// Duplicate subnet rules will automatically be removed and the lowest non-zero timeout will be used.
//
// SetFilter is safe to call from multiple goroutines while the listener is in use.
func (l *Listener) SetFilter(filter []Rule) {
	newFilter := make([]Rule, len(filter))
	copy(newFilter, filter)
	sort.Slice(newFilter, func(i, j int) bool {
		iOnes, iBits := newFilter[i].Subnet.Mask.Size()
		jOnes, jBits := newFilter[j].Subnet.Mask.Size()
		if iOnes != jOnes {
			return iOnes > jOnes
		}
		if iBits != jBits {
			return iBits > jBits
		}
		if newFilter[i].Timeout != newFilter[j].Timeout {
			if newFilter[j].Timeout == 0 {
				return true
			}
			return newFilter[i].Timeout < newFilter[j].Timeout
		}
		return newFilter[i].Timeout < newFilter[j].Timeout
	})
	if len(newFilter) > 0 {
		// dedup
		last := newFilter[0]
		nf := newFilter[1:1]
		for _, f := range newFilter[1:] {
			if last.Subnet.String() == f.Subnet.String() {
				continue
			}

			last = f
			nf = append(nf, f)
		}
	}

	l.mx.Lock()
	l.filter = newFilter
	l.mx.Unlock()
}
