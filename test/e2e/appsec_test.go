//go:build e2e

package e2e

import (
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/hslatman/caddy-crowdsec-bouncer/internal/testutils"
)

const (
	// appSecAttackPath trips the installed virtual-patching collection: it
	// simulates the JetBrains TeamCity auth bypass, CVE-2023-42793. Same payload
	// the existing integration test uses, so it is known to be caught by the
	// rules installed into the container.
	appSecAttackPath = "/rpc2"

	// appSecSQLiPath and appSecSQLiBody simulate Ivanti EPM SQLi, CVE-2024-29824,
	// which is matched on the request body rather than the path.
	appSecSQLiPath = "/wsstatusevents/eventhandler.asmx"
	appSecSQLiBody = "blabla 'xp_cmdshell' blabla"
)

func TestAppSecAllowsBenignRequest(t *testing.T) {
	container := sharedAppSec(t)
	h := testutils.NewHarness(t)
	h.Load(t, config(t, h, container, withAppSec(container.AppSecUrl())))

	resp, body := h.Get(t, "/", testutils.NextTestIP(t))

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, allowedBody, body)
}

func TestAppSecBlocksAttackPath(t *testing.T) {
	container := sharedAppSec(t)
	h := testutils.NewHarness(t)
	h.Load(t, config(t, h, container, withAppSec(container.AppSecUrl())))

	resp, _ := h.Get(t, appSecAttackPath, testutils.NextTestIP(t))

	assert.Equal(t, http.StatusForbidden, resp.StatusCode)
}

func TestAppSecBlocksMaliciousBody(t *testing.T) {
	container := sharedAppSec(t)
	h := testutils.NewHarness(t)
	h.Load(t, config(t, h, container, withAppSec(container.AppSecUrl())))

	resp, _ := h.Post(t, appSecSQLiPath, "text/plain",
		strings.NewReader(appSecSQLiBody), testutils.NextTestIP(t))

	assert.Equal(t, http.StatusForbidden, resp.StatusCode)
}

// TestAppSecPreservesRequestBody guards the body reassembly in
// internal/core/appsec.go: the body is read in order to forward it to AppSec,
// then r.Body is rebuilt from the buffered prefix and the unread remainder.
// A handler further down the chain must still see the whole thing.
func TestAppSecPreservesRequestBody(t *testing.T) {
	container := sharedAppSec(t)
	h := testutils.NewHarness(t)
	h.Load(t, config(t, h, container, withAppSec(container.AppSecUrl()), withEcho()))

	// large enough that a truncated or partially consumed body is obvious
	payload := strings.Repeat("caddy-crowdsec-bouncer.", 500)

	resp, body := h.Post(t, "/", "text/plain", strings.NewReader(payload), testutils.NextTestIP(t))

	require.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, payload, body, "the handler after appsec must receive the complete request body")
}

// TestAppSecAllowsWebSocketHandshake guards the hop-by-hop header stripping from
// 9e35b21. Forwarding "Connection: Upgrade" to an HTTP/2 AppSec endpoint gets the
// check rejected outright, which with the default fail-closed posture turns every
// WebSocket handshake into a blocked request.
func TestAppSecAllowsWebSocketHandshake(t *testing.T) {
	container := sharedAppSec(t)
	h := testutils.NewHarness(t)
	h.Load(t, config(t, h, container, withAppSec(container.AppSecUrl())))

	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "http://"+h.HTTPAddr+"/", http.NoBody)
	require.NoError(t, err)
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "websocket")
	req.Header.Set("Sec-WebSocket-Version", "13")
	req.Header.Set("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")

	resp, _ := h.Do(t, req, testutils.NextTestIP(t))

	assert.Equal(t, http.StatusOK, resp.StatusCode,
		"a WebSocket handshake must survive the AppSec check")
}

func TestAppSecMaxBodyBytesTruncatesForwardedBody(t *testing.T) {
	container := sharedAppSec(t)
	h := testutils.NewHarness(t)

	ip := testutils.NextTestIP(t)

	// hide the payload behind enough padding that a truncated body cannot
	// contain it
	padding := strings.Repeat("a", 128)
	body := padding + appSecSQLiBody

	t.Run("full body is inspected", func(t *testing.T) {
		h.Load(t, config(t, h, container, withAppSec(container.AppSecUrl())))

		resp, _ := h.Post(t, appSecSQLiPath, "text/plain", strings.NewReader(body), ip)
		require.Equal(t, http.StatusForbidden, resp.StatusCode,
			"without a limit the payload should reach AppSec and be blocked")
	})

	t.Run("truncated body hides the payload", func(t *testing.T) {
		h.Load(t, config(t, h, container,
			withAppSec(container.AppSecUrl()), withAppSecMaxBodyBytes(len(padding)/2)))

		resp, _ := h.Post(t, appSecSQLiPath, "text/plain", strings.NewReader(body), ip)
		assert.Equal(t, http.StatusOK, resp.StatusCode,
			"with the body truncated below the payload, AppSec cannot match it")
	})
}

// TestAppSecFailOpen covers what happens when the AppSec component cannot be
// reached at all.
//
// Note the failure mode when fail-open is off: checkRequest returns a plain
// error rather than an AppSecError, so the handler hands it to Caddy and the
// client sees 500 rather than a 403 block. See docs/REFACTOR_BACKLOG.md T8.
func TestAppSecFailOpen(t *testing.T) {
	container := sharedCrowdSec(t)
	unreachable := "http://" + testutils.FreeAddr(t)

	t.Run("fail open allows the request", func(t *testing.T) {
		h := testutils.NewHarness(t)
		h.Load(t, config(t, h, container,
			withAppSec(unreachable), withAppSecFailOpen(true), withAppSecTimeout("1s")))

		resp, body := h.Get(t, "/", testutils.NextTestIP(t))
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		assert.Equal(t, allowedBody, body)
	})

	t.Run("fail closed rejects the request", func(t *testing.T) {
		h := testutils.NewHarness(t)
		h.Load(t, config(t, h, container,
			withAppSec(unreachable), withAppSecFailOpen(false), withAppSecTimeout("1s")))

		resp, _ := h.Get(t, "/", testutils.NextTestIP(t))
		assert.Equal(t, http.StatusInternalServerError, resp.StatusCode,
			"an unreachable AppSec component surfaces as a Caddy error, not a block")
	})
}
