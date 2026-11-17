//go:build e2e

package e2e

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strconv"
	"testing"
	"time"

	"github.com/crowdsecurity/crowdsec/pkg/models"
	"github.com/stretchr/testify/require"

	"github.com/hslatman/caddy-crowdsec-bouncer/internal/adminapi"
	"github.com/hslatman/caddy-crowdsec-bouncer/internal/testutils"
)

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

func TestHTTPKeepsSameGroupBanUntilLastMemberDeleted(t *testing.T) {
	skipIfShort(t)

	for _, mode := range []struct {
		name      string
		streaming bool
	}{{"stream", true}, {"live", false}} {
		t.Run(mode.name, func(t *testing.T) {
			container := testutils.NewCrowdSecContainer(t)
			for _, firstRemoved := range []string{"longer", "shorter"} {
				t.Run(firstRemoved, func(t *testing.T) {
					ip := testutils.NextTestIP(t)
					t.Cleanup(func() { testutils.UnBan(t, container, ip) })
					testutils.Ban(t, container, ip, time.Hour)
					decisions := lapiDecisionsForIP(t, container, ip)
					require.Len(t, decisions, 1)
					shorterID := decisions[0].ID

					testutils.Ban(t, container, ip, 2*time.Hour)
					decisions = lapiDecisionsForIP(t, container, ip)
					require.Len(t, decisions, 2, "LAPI must hold two members of the same group")
					var longerID int64
					for _, decision := range decisions {
						require.NotNil(t, decision)
						require.Equal(t, "Ip", *decision.Scope)
						require.Equal(t, "ban", *decision.Type)
						require.Equal(t, ip, *decision.Value)
						if decision.ID != shorterID {
							longerID = decision.ID
						}
					}
					require.Positive(t, longerID)

					h := testutils.NewHarness(t)
					h.Load(t, config(t, h, container, withStreaming(mode.streaming)))
					if mode.streaming {
						// The default stream exposes the longest-lived member of
						// each exact scope/type/value group, not both decision IDs.
						waitForActiveDecisions(t, h, 1)
					}
					h.WaitForStatus(t, "/", ip, http.StatusForbidden, decisionTimeout)

					removedID, remainingID := longerID, shorterID
					if firstRemoved == "shorter" {
						removedID, remainingID = shorterID, longerID
					}
					testutils.UnBanID(t, container, removedID)
					decisions = lapiDecisionsForIP(t, container, ip)
					require.Len(t, decisions, 1)
					require.Equal(t, remainingID, decisions[0].ID)

					if mode.streaming {
						// A fresh target proves a post-deletion stream batch was
						// processed before checking that the original ban remains.
						sentinelIP := testutils.NextTestIP(t)
						t.Cleanup(func() { testutils.UnBan(t, container, sentinelIP) })
						testutils.Ban(t, container, sentinelIP, time.Hour)
						waitForActiveDecisions(t, h, 2)
						testutils.UnBan(t, container, sentinelIP)
						waitForActiveDecisions(t, h, 1)
					}
					resp, _ := h.Get(t, "/", ip)
					require.Equal(t, http.StatusForbidden, resp.StatusCode,
						"deleting one member must not remove the remaining ban")

					testutils.UnBanID(t, container, remainingID)
					require.Empty(t, lapiDecisionsForIP(t, container, ip))
					h.WaitForStatus(t, "/", ip, http.StatusOK, decisionTimeout)
					if mode.streaming {
						waitForActiveDecisions(t, h, 0)
					}
				})
			}
		})
	}
}

func lapiDecisionsForIP(t *testing.T, container *testutils.Container, ip string) []*models.Decision {
	t.Helper()

	// cscli decisions list deduplicates its JSON output, so use the live LAPI
	// endpoint to verify both underlying IDs before deleting either one.
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet,
		container.APIUrl()+"/v1/decisions?ip="+url.QueryEscape(ip), nil)
	require.NoError(t, err)
	req.Header.Set("X-Api-Key", container.APIKey())
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	var decisions []*models.Decision
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&decisions))
	return decisions
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
