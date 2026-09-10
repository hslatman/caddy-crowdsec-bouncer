package core

import (
	"context"
	"net/http"
	"regexp"
	"testing"
	"time"

	"github.com/jarcoal/httpmock"
	"github.com/stretchr/testify/require"
)

// decisionsRe matches the live lookup the health path performs. The streaming
// endpoint is deliberately not registered: none of these tests run the stream,
// they drive the freeze signal directly.
var decisionsRe = regexp.MustCompile(`/v1/decisions\?ip=.*`)

// staleCore returns a Core whose stream is considered frozen: nothing has ever
// pulled successfully, and instantiation is far enough back that the startup
// window has passed.
func staleCore(t *testing.T) *Core {
	t.Helper()

	c, err := newCore(t)
	require.NoError(t, err)

	c.streamStaleThreshold = 10 * time.Millisecond
	c.instantiatedAt = time.Now().Add(-time.Minute)

	return c
}

// A fresh stream must not touch the LAPI at all. This is the decoupling: a
// brief LAPI outage self-heals on the next tick, so asking it here would turn a
// blip into a restart of a bouncer that is working perfectly well.
func TestHealthyDoesNotCallTheLapiWhileTheStreamIsFresh(t *testing.T) {
	httpmock.Activate()
	defer httpmock.DeactivateAndReset()

	calls := 0
	httpmock.RegisterRegexpResponder(http.MethodGet, decisionsRe,
		func(*http.Request) (*http.Response, error) {
			calls++
			return httpmock.NewStringResponse(http.StatusOK, "[]"), nil
		})

	c, err := newCore(t)
	require.NoError(t, err)

	// Inside the startup window, so not stale.
	c.streamStaleThreshold = time.Hour
	c.instantiatedAt = time.Now()

	healthy, err := c.Healthy(context.Background())

	require.NoError(t, err)
	require.True(t, healthy)
	require.Zero(t, calls, "a fresh stream must not produce a LAPI call")
}

// The freeze itself. A rejected key answers 403 forever: the stream never
// pulls again, while the LAPI is plainly up. Before this change the health
// check asked whether the LAPI was reachable, said yes, and the bouncer served
// unfiltered traffic for as long as nobody noticed.
func TestStaleStreamIsUnhealthyWhenTheLapiAnswers(t *testing.T) {
	httpmock.Activate()
	defer httpmock.DeactivateAndReset()

	httpmock.RegisterRegexpResponder(http.MethodGet, decisionsRe,
		httpmock.NewStringResponder(http.StatusForbidden, `{"message":"access forbidden"}`))

	c := staleCore(t)

	healthy, err := c.Healthy(context.Background())

	require.False(t, healthy)
	require.ErrorContains(t, err, "stale")
}

// The counterpart, and the reason the stale stream is classified rather than
// simply reported. Every instance streams from the same LAPI, so if a failing
// LAPI read unhealthy everywhere at once, a liveness probe would restart every
// edge proxy into a LAPI that is still broken -- and again a few minutes later.
func TestStaleStreamStaysHealthyWhenTheLapiIsFailing(t *testing.T) {
	httpmock.Activate()
	defer httpmock.DeactivateAndReset()

	httpmock.RegisterRegexpResponder(http.MethodGet, decisionsRe,
		httpmock.NewStringResponder(http.StatusInternalServerError, `{"message":"boom"}`))

	c := staleCore(t)

	healthy, err := c.Healthy(context.Background())

	require.NoError(t, err)
	require.True(t, healthy, "a failing LAPI is not this bouncer's to fix")
}

// Same reasoning for a LAPI that does not answer at all: the probe reports no
// status, which is not evidence that this bouncer is the broken part.
func TestStaleStreamStaysHealthyWhenTheLapiIsUnreachable(t *testing.T) {
	httpmock.Activate()
	defer httpmock.DeactivateAndReset()

	httpmock.RegisterRegexpResponder(http.MethodGet, decisionsRe,
		httpmock.NewErrorResponder(http.ErrServerClosed))

	c := staleCore(t)

	healthy, err := c.Healthy(context.Background())

	require.NoError(t, err)
	require.True(t, healthy, "an unreachable LAPI is not this bouncer's to fix")
}

// Without streaming there is no stream to judge, so the live Ping remains the
// signal and must keep working unchanged.
func TestWithoutStreamingHealthFallsBackToThePing(t *testing.T) {
	httpmock.Activate()
	defer httpmock.DeactivateAndReset()

	httpmock.RegisterRegexpResponder(http.MethodGet, decisionsRe,
		httpmock.NewStringResponder(http.StatusOK, "[]"))

	c, err := newCore(t)
	require.NoError(t, err)
	c.useStreamingBouncer = false

	healthy, err := c.Healthy(context.Background())

	require.NoError(t, err)
	require.True(t, healthy)
}
