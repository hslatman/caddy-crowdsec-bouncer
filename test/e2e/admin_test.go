//go:build e2e

package e2e

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/hslatman/caddy-crowdsec-bouncer/internal/adminapi"
	"github.com/hslatman/caddy-crowdsec-bouncer/internal/testutils"
)

func TestAdminInfoReportsConfiguration(t *testing.T) {
	container := sharedCrowdSec(t)
	h := testutils.NewHarness(t)
	h.Load(t, config(t, h, container, withStreaming(true), withTicker("5s")))

	var info adminapi.InfoResponse
	adminJSON(t, h, "/crowdsec/info", nil, &info)

	assert.True(t, info.Streaming.Enabled)
	assert.Equal(t, "5s", info.Streaming.Interval)
	assert.True(t, info.Live.Enabled, "the live bouncer is always available for ad hoc lookups")
	assert.Equal(t, "adhoc", info.Live.Mode)
	assert.False(t, info.AppSec.Enabled)
	assert.False(t, info.ShouldFailHard)
	assert.Equal(t, "apikey", info.AuthType)
	assert.Contains(t, info.UserAgent, "caddy-cs-bouncer/")
	assert.NotEmpty(t, info.InstanceID)
	assert.Positive(t, info.Uptime)
}

func TestAdminInfoReflectsLiveMode(t *testing.T) {
	container := sharedCrowdSec(t)
	h := testutils.NewHarness(t)
	h.Load(t, config(t, h, container, withStreaming(false)))

	var info adminapi.InfoResponse
	adminJSON(t, h, "/crowdsec/info", nil, &info)

	assert.False(t, info.Streaming.Enabled)
	assert.Equal(t, "-", info.Streaming.Interval, "the interval is meaningless without streaming")
	assert.Equal(t, "live", info.Live.Mode)
}

func TestAdminPingAndHealth(t *testing.T) {
	container := sharedCrowdSec(t)
	h := testutils.NewHarness(t)
	h.Load(t, config(t, h, container))

	var ping adminapi.PingResponse
	adminJSON(t, h, "/crowdsec/ping", nil, &ping)
	assert.True(t, ping.Ok, "ping should reach the LAPI")

	var health adminapi.HealthResponse
	adminJSON(t, h, "/crowdsec/health", nil, &health)
	assert.True(t, health.Ok)
}

func TestAdminCheckReportsDecisions(t *testing.T) {
	container := sharedCrowdSec(t)
	h := testutils.NewHarness(t)
	h.Load(t, config(t, h, container))

	banned := testutils.NextTestIP(t)
	clean := testutils.NextTestIP(t)

	testutils.Ban(t, container, banned, time.Hour)
	h.WaitForStatus(t, "/", banned, http.StatusForbidden, decisionTimeout)

	var checked adminapi.CheckResponse
	adminJSON(t, h, "/crowdsec/check", checkRequest(t, banned, false), &checked)
	assert.True(t, checked.Blocked)

	adminJSON(t, h, "/crowdsec/check", checkRequest(t, clean, false), &checked)
	assert.False(t, checked.Blocked)

	// ForceLive bypasses the in-memory store and queries the LAPI directly
	adminJSON(t, h, "/crowdsec/check", checkRequest(t, banned, true), &checked)
	assert.True(t, checked.Blocked, "a forced live lookup should see the decision too")
}

func TestAdminRejectsNonPost(t *testing.T) {
	container := sharedCrowdSec(t)
	h := testutils.NewHarness(t)
	h.Load(t, config(t, h, container))

	for _, path := range []string{"/crowdsec/info", "/crowdsec/ping", "/crowdsec/health", "/crowdsec/check"} {
		t.Run(path, func(t *testing.T) {
			code, _ := h.AdminGet(t, path)
			assert.Equal(t, http.StatusMethodNotAllowed, code, "admin endpoints are POST only")
		})
	}
}

func checkRequest(t *testing.T, ip string, forceLive bool) string {
	t.Helper()

	b, err := json.Marshal(adminapi.CheckRequest{IP: ip, ForceLive: forceLive})
	require.NoError(t, err)

	return string(b)
}

// adminJSON POSTs to the admin API and decodes the response into out.
func adminJSON(t *testing.T, h *testutils.Harness, path string, body any, out any) {
	t.Helper()

	var reader *strings.Reader
	switch v := body.(type) {
	case nil:
		reader = strings.NewReader("")
	case string:
		reader = strings.NewReader(v)
	default:
		require.FailNow(t, fmt.Sprintf("unsupported body type %T", body))
	}

	code, response := h.AdminPost(t, path, reader)
	require.Equalf(t, http.StatusOK, code, "%s returned %d: %s", path, code, response)
	require.NoErrorf(t, json.Unmarshal([]byte(response), out), "could not decode %s response: %s", path, response)
}
