//go:build e2e

package e2e

import (
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/hslatman/caddy-crowdsec-bouncer/internal/testutils"
)

// The layer4 matcher reads the client address straight off the connection, so
// these tests cannot use the X-Forwarded-For trick the HTTP tests rely on: they
// have to ban 127.0.0.1 itself. That would block every other test sharing the
// package's CrowdSec container, so layer4 gets a container of its own.

func TestLayer4AllowsCleanConnection(t *testing.T) {
	container := layer4Container(t)
	h := testutils.NewHarness(t)
	h.Load(t, config(t, h, container, withLayer4()))

	echoed, err := dialAndEcho(t, h.L4Addr, "ping")

	require.NoError(t, err)
	assert.Equal(t, "ping", echoed, "a clean connection should reach the echo handler")
}

func TestLayer4BlocksBannedConnection(t *testing.T) {
	container := layer4Container(t)
	h := testutils.NewHarness(t)
	h.Load(t, config(t, h, container, withLayer4()))

	// sanity check: the route matches before the ban exists
	echoed, err := dialAndEcho(t, h.L4Addr, "ping")
	require.NoError(t, err)
	require.Equal(t, "ping", echoed)

	testutils.Ban(t, container, "127.0.0.1", time.Hour)

	// the matcher stops matching, so no handler runs and nothing is echoed back
	testutils.WaitFor(t, decisionTimeout, func() bool {
		echoed, err := dialAndEcho(t, h.L4Addr, "ping")

		return err != nil || echoed == ""
	}, "connection from a banned address should not have been handled")
}

// layer4Container starts a CrowdSec container scoped to this test. It is not the
// package-wide shared one, because these tests ban the loopback address.
func layer4Container(t *testing.T) *testutils.Container {
	t.Helper()
	skipIfShort(t)

	return testutils.NewCrowdSecContainer(t)
}

// dialAndEcho opens a TCP connection, writes msg and reads whatever comes back.
// An empty result means the connection was accepted but never handled, which is
// how a non-matching layer4 route presents itself.
func dialAndEcho(t *testing.T, addr, msg string) (string, error) {
	t.Helper()

	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		return "", err
	}
	defer func() { _ = conn.Close() }()

	if err := conn.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		return "", err
	}

	if _, err := conn.Write([]byte(msg)); err != nil {
		return "", err
	}

	buf := make([]byte, len(msg))
	n, err := conn.Read(buf)
	if err != nil {
		// a closed or timed-out connection is the expected outcome for a
		// blocked address, so report what was read rather than failing here
		return string(buf[:n]), err
	}

	return string(buf[:n]), nil
}
