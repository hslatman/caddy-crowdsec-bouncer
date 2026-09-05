//go:build e2e

package e2e

import (
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/hslatman/caddy-crowdsec-bouncer/internal/testutils"
)

// decisionTimeout bounds how long a test waits for a decision to reach the
// bouncer. The streaming ticker is configured at 1s, so this leaves ample room
// without making a genuine failure take long to surface.
const decisionTimeout = 15 * time.Second

func TestHTTPAllowsCleanIP(t *testing.T) {
	container := sharedCrowdSec(t)
	h := testutils.NewHarness(t)
	h.Load(t, config(t, h, container))

	resp, body := h.Get(t, "/", testutils.NextTestIP(t))

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, allowedBody, body)
}

func TestHTTPBlocksBannedIP(t *testing.T) {
	container := sharedCrowdSec(t)
	h := testutils.NewHarness(t)
	h.Load(t, config(t, h, container))

	ip := testutils.NextTestIP(t)

	// allowed before the ban exists
	resp, _ := h.Get(t, "/", ip)
	require.Equal(t, http.StatusOK, resp.StatusCode)

	testutils.Ban(t, container, ip, time.Minute)
	h.WaitForStatus(t, "/", ip, http.StatusForbidden, decisionTimeout)

	// a different address is unaffected
	resp, body := h.Get(t, "/", testutils.NextTestIP(t))
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, allowedBody, body)
}

func TestHTTPThrottleServesRetryAfter(t *testing.T) {
	container := sharedCrowdSec(t)
	h := testutils.NewHarness(t)
	h.Load(t, config(t, h, container))

	ip := testutils.NextTestIP(t)
	testutils.BanTyped(t, container, ip, "throttle", 90*time.Second)

	h.WaitForStatus(t, "/", ip, http.StatusTooManyRequests, decisionTimeout)

	resp, _ := h.Get(t, "/", ip)
	require.Equal(t, http.StatusTooManyRequests, resp.StatusCode)

	retryAfter := resp.Header.Get("Retry-After")
	require.NotEmpty(t, retryAfter, "throttle response must carry a Retry-After header")

	seconds, err := strconv.Atoi(retryAfter)
	require.NoError(t, err, "Retry-After must be a whole number of seconds")
	assert.Positive(t, seconds)
	assert.LessOrEqual(t, seconds, 90)
}

func TestHTTPCaddyErrorServesCustomPage(t *testing.T) {
	container := sharedCrowdSec(t)
	h := testutils.NewHarness(t)

	const errorPage = "blocked by the custom error page"
	h.Load(t, config(t, h, container, withCaddyError(), withErrorPage(errorPage)))

	ip := testutils.NextTestIP(t)
	testutils.Ban(t, container, ip, time.Minute)

	h.WaitForStatus(t, "/", ip, http.StatusForbidden, decisionTimeout)

	resp, body := h.Get(t, "/", ip)
	assert.Equal(t, http.StatusForbidden, resp.StatusCode)
	assert.Equal(t, errorPage, body, "handle_errors route should have produced the body")
}

func TestHTTPCaddyErrorExposesBlockVariables(t *testing.T) {
	container := sharedCrowdSec(t)
	h := testutils.NewHarness(t)

	const errorPage = "{http.vars.crowdsec.module}|{http.vars.crowdsec.remediation}|{http.vars.crowdsec.origin}|{http.vars.crowdsec.duration}"
	h.Load(t, config(t, h, container,
		withStreaming(false), withCaddyError(), withErrorPage(errorPage)))

	ip := testutils.NextTestIP(t)
	testutils.Ban(t, container, ip, time.Minute)

	resp, body := h.Get(t, "/", ip)
	require.Equal(t, http.StatusForbidden, resp.StatusCode)

	parts := strings.Split(body, "|")
	require.Len(t, parts, 4)
	assert.Equal(t, "http", parts[0])
	assert.Equal(t, "ban", parts[1])
	assert.Equal(t, "cscli", parts[2])
	assert.NotEmpty(t, parts[3], "the block duration variable should be populated")
}

func TestHTTPAllowsAgainAfterDecisionDeleted(t *testing.T) {
	container := sharedCrowdSec(t)
	h := testutils.NewHarness(t)
	h.Load(t, config(t, h, container))

	ip := testutils.NextTestIP(t)

	testutils.Ban(t, container, ip, time.Hour)
	h.WaitForStatus(t, "/", ip, http.StatusForbidden, decisionTimeout)

	// exercises the deletion half of the decision stream
	testutils.UnBan(t, container, ip)
	h.WaitForStatus(t, "/", ip, http.StatusOK, decisionTimeout)
}

func TestHTTPLiveModeBlocksWithoutTicker(t *testing.T) {
	container := sharedCrowdSec(t)
	h := testutils.NewHarness(t)

	// in live mode every request queries the LAPI, so a decision applies
	// immediately rather than after the next poll
	h.Load(t, config(t, h, container, withStreaming(false)))

	ip := testutils.NextTestIP(t)

	resp, _ := h.Get(t, "/", ip)
	require.Equal(t, http.StatusOK, resp.StatusCode)

	testutils.Ban(t, container, ip, time.Minute)

	resp, _ = h.Get(t, "/", ip)
	assert.Equal(t, http.StatusForbidden, resp.StatusCode,
		"live mode should see the decision on the very next request")
}

func TestHTTPStreamingModePicksUpDecision(t *testing.T) {
	container := sharedCrowdSec(t)
	h := testutils.NewHarness(t)
	h.Load(t, config(t, h, container, withStreaming(true), withTicker("1s")))

	ip := testutils.NextTestIP(t)
	testutils.Ban(t, container, ip, time.Minute)

	h.WaitForStatus(t, "/", ip, http.StatusForbidden, decisionTimeout)
}

// TestHTTPIgnoresForwardedForWithoutTrustedProxies guards the trap documented in
// the README: X-Forwarded-For is only honoured when trusted_proxies is set.
// Without it the client is 127.0.0.1, so a ban on the forwarded address must
// have no effect.
func TestHTTPIgnoresForwardedForWithoutTrustedProxies(t *testing.T) {
	container := sharedCrowdSec(t)
	h := testutils.NewHarness(t)
	h.Load(t, config(t, h, container, withoutTrustedProxies()))

	ip := testutils.NextTestIP(t)
	testutils.Ban(t, container, ip, time.Minute)
	t.Cleanup(func() { testutils.UnBan(t, container, ip) })

	// give the streaming bouncer time to ingest the decision, so that a failure
	// here means "the header was trusted", not "the decision had not arrived"
	testutils.WaitFor(t, decisionTimeout, func() bool {
		return testutils.HasDecisionFor(t, container, ip)
	}, "decision for %s never reached the LAPI", ip)

	resp, body := h.Get(t, "/", ip)
	assert.Equal(t, http.StatusOK, resp.StatusCode,
		"X-Forwarded-For must be ignored when trusted_proxies is not configured")
	assert.Equal(t, allowedBody, body)
}
