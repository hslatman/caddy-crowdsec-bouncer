//go:build e2e

package e2e

import (
	"encoding/json"
	"net/http"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/hslatman/caddy-crowdsec-bouncer/internal/adminapi"
	"github.com/hslatman/caddy-crowdsec-bouncer/internal/testutils"
)

func TestHTTPBlocksMappedIPv4(t *testing.T) {
	container := sharedCrowdSec(t)
	for _, mode := range []struct {
		name      string
		streaming bool
	}{{"stream", true}, {"live", false}} {
		t.Run(mode.name, func(t *testing.T) {
			h := testutils.NewHarness(t)
			h.Load(t, config(t, h, container, withStreaming(mode.streaming)))
			ip := testutils.NextTestIP(t)
			t.Cleanup(func() { testutils.UnBan(t, container, ip) })
			testutils.Ban(t, container, ip, time.Minute)
			h.WaitForStatus(t, "/", ip, http.StatusForbidden, decisionTimeout)

			resp, _ := h.Get(t, "/", "::ffff:"+ip)
			require.Equal(t, http.StatusForbidden, resp.StatusCode,
				"an IPv4 ban must also block its mapped representation")

			testutils.UnBan(t, container, ip)
			h.WaitForStatus(t, "/", "::ffff:"+ip, http.StatusOK, decisionTimeout)
		})
	}
}

func TestHTTPKeepsSameTargetRemediationsIndependent(t *testing.T) {
	skipIfShort(t)

	for _, mode := range []struct {
		name      string
		streaming bool
	}{{"stream", true}, {"live", false}} {
		t.Run(mode.name, func(t *testing.T) {
			// Isolate the decision count so readiness proves both remediations
			// reached the store, rather than observing a partially applied batch.
			container := testutils.NewCrowdSecContainer(t)
			for _, order := range []struct {
				name  string
				types []string
			}{
				{"ban then throttle", []string{"ban", "throttle"}},
				{"throttle then ban", []string{"throttle", "ban"}},
			} {
				t.Run(order.name, func(t *testing.T) {
					ip := testutils.NextTestIP(t)
					t.Cleanup(func() { testutils.UnBan(t, container, ip) })
					for _, typ := range order.types {
						testutils.BanTyped(t, container, ip, typ, time.Hour)
					}

					h := testutils.NewHarness(t)
					h.Load(t, config(t, h, container, withStreaming(mode.streaming)))
					if mode.streaming {
						waitForActiveDecisions(t, h, 2)
					}
					resp, _ := h.Get(t, "/", ip)
					require.Equal(t, http.StatusForbidden, resp.StatusCode)
					require.Empty(t, resp.Header.Get("Retry-After"))

					testutils.UnBanTyped(t, container, ip, "ban")
					h.WaitForStatus(t, "/", ip, http.StatusTooManyRequests, decisionTimeout)
					resp, _ = h.Get(t, "/", ip)
					require.Equal(t, http.StatusTooManyRequests, resp.StatusCode)
					seconds, err := strconv.Atoi(resp.Header.Get("Retry-After"))
					require.NoError(t, err)
					require.Positive(t, seconds)
					if mode.streaming {
						waitForActiveDecisions(t, h, 1)
					}

					testutils.UnBanTyped(t, container, ip, "throttle")
					h.WaitForStatus(t, "/", ip, http.StatusOK, decisionTimeout)
					if mode.streaming {
						waitForActiveDecisions(t, h, 0)
					}
				})
			}
		})
	}
}

func waitForActiveDecisions(t *testing.T, h *testutils.Harness, expected int) {
	t.Helper()

	testutils.WaitFor(t, decisionTimeout, func() bool {
		code, body := h.AdminPost(t, "/crowdsec/info", http.NoBody)
		require.Equal(t, http.StatusOK, code)
		var info adminapi.InfoResponse
		require.NoError(t, json.Unmarshal([]byte(body), &info))
		return info.NumberOfActiveDecisions == expected
	}, "expected %d active decisions", expected)
}
