package bouncer

import (
	"crypto/tls"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestNewTransportKeepsDefaultsExceptHTTP2 guards §4.4: a zero-value
// http.Transport has no proxy support, no dial or TLS handshake timeout and no
// idle connection tuning, so a stalled connection to a LAPI that is still
// starting up consumes the entire request budget instead of failing fast.
// HTTP/2 is the deliberate exception: http.DefaultTransport.Clone() carries
// ForceAttemptHTTP2: true, but this bouncer forces it back off so HTTPS LAPI
// traffic stays on HTTP/1.1 -- the large chunked startup=true dump should not
// silently switch protocols as a side effect of this timeout fix.
func TestNewTransportKeepsDefaultsExceptHTTP2(t *testing.T) {
	tlsConfig := &tls.Config{InsecureSkipVerify: true} //nolint:gosec // test only

	transport := newTransport(tlsConfig)

	require.Same(t, tlsConfig, transport.TLSClientConfig)
	require.NotNil(t, transport.Proxy, "proxy support must come from http.DefaultTransport")
	require.NotNil(t, transport.DialContext, "dial timeout must come from http.DefaultTransport")
	require.False(t, transport.ForceAttemptHTTP2, "HTTP/2 must be forced off to keep LAPI traffic on HTTP/1.1")
	require.NotZero(t, transport.TLSHandshakeTimeout)
	require.NotZero(t, transport.IdleConnTimeout)
	require.NotZero(t, transport.MaxIdleConns)
}
