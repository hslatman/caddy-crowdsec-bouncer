//go:build e2e

package e2e

import (
	"net/http"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/hslatman/caddy-crowdsec-bouncer/internal/testutils"
)

// reloadTimeout bounds a single config reload. Provisioning a new app and
// shutting the old one down is fast; anything approaching this means something
// is blocking rather than merely slow.
const reloadTimeout = 30 * time.Second

func TestReloadWithUnchangedConfigKeepsEnforcing(t *testing.T) {
	container := sharedCrowdSec(t)
	h := testutils.NewHarness(t)

	// forceReload is always set by the harness, so loading the identical
	// configuration still tears the app down and provisions it again rather
	// than being skipped as a no-op
	cfg := config(t, h, container)
	h.Load(t, cfg)

	ip := testutils.NextTestIP(t)
	testutils.Ban(t, container, ip, time.Hour)
	h.WaitForStatus(t, "/", ip, http.StatusForbidden, decisionTimeout)

	h.ReloadWithin(t, cfg, reloadTimeout)

	h.WaitForStatus(t, "/", ip, http.StatusForbidden, decisionTimeout)

	resp, body := h.Get(t, "/", testutils.NextTestIP(t))
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, allowedBody, body)
}

func TestReloadSwitchesBetweenStreamingAndLive(t *testing.T) {
	container := sharedCrowdSec(t)
	h := testutils.NewHarness(t)

	streaming := config(t, h, container, withStreaming(true), withTicker("1s"))
	live := config(t, h, container, withStreaming(false))

	h.Load(t, streaming)

	ip := testutils.NextTestIP(t)
	testutils.Ban(t, container, ip, time.Hour)
	h.WaitForStatus(t, "/", ip, http.StatusForbidden, decisionTimeout)

	// streaming -> live: the decision is now looked up per request
	h.ReloadWithin(t, live, reloadTimeout)
	resp, _ := h.Get(t, "/", ip)
	assert.Equal(t, http.StatusForbidden, resp.StatusCode, "live mode should block the banned address")

	// a freshly banned address is visible immediately in live mode
	second := testutils.NextTestIP(t)
	testutils.Ban(t, container, second, time.Hour)
	resp, _ = h.Get(t, "/", second)
	assert.Equal(t, http.StatusForbidden, resp.StatusCode, "live mode should not need a poll")

	// live -> streaming: the store is rebuilt from the startup stream
	h.ReloadWithin(t, streaming, reloadTimeout)
	h.WaitForStatus(t, "/", ip, http.StatusForbidden, decisionTimeout)
	h.WaitForStatus(t, "/", second, http.StatusForbidden, decisionTimeout)
}

func TestReloadChangesTickerInterval(t *testing.T) {
	container := sharedCrowdSec(t)
	h := testutils.NewHarness(t)

	h.Load(t, config(t, h, container, withTicker("1s")))

	// with a 1s ticker a new decision is picked up promptly
	fast := testutils.NextTestIP(t)
	testutils.Ban(t, container, fast, time.Hour)
	h.WaitForStatus(t, "/", fast, http.StatusForbidden, decisionTimeout)

	h.ReloadWithin(t, config(t, h, container, withTicker("60s")), reloadTimeout)

	// the running configuration reflects the new interval
	code, body := h.AdminGet(t, "/config/")
	require.Equal(t, http.StatusOK, code)
	assert.Contains(t, body, `"ticker_interval":"60s"`)

	// decisions already known at reload time survive, because the new app
	// fetches the full stream on startup
	h.WaitForStatus(t, "/", fast, http.StatusForbidden, decisionTimeout)

	// a decision created after that startup fetch must NOT show up quickly:
	// the next poll is a minute away. This is what proves the interval is
	// honoured rather than merely stored.
	slow := testutils.NextTestIP(t)
	testutils.Ban(t, container, slow, time.Hour)
	t.Cleanup(func() { testutils.UnBan(t, container, slow) })

	testutils.WaitFor(t, decisionTimeout, func() bool {
		return testutils.HasDecisionFor(t, container, slow)
	}, "decision for %s never reached the LAPI", slow)

	time.Sleep(5 * time.Second)

	resp, _ := h.Get(t, "/", slow)
	assert.Equal(t, http.StatusOK, resp.StatusCode,
		"a 60s ticker should not have polled yet, so the new decision should not be enforced")
}

func TestReloadPreservesEnforcementOfExistingDecisions(t *testing.T) {
	container := sharedCrowdSec(t)
	h := testutils.NewHarness(t)
	cfg := config(t, h, container)

	h.Load(t, cfg)

	// several decisions, so a partial rebuild of the store would be visible
	ips := []string{
		testutils.NextTestIP(t),
		testutils.NextTestIP(t),
		testutils.NextTestIP(t),
	}
	for _, ip := range ips {
		testutils.Ban(t, container, ip, time.Hour)
	}
	for _, ip := range ips {
		h.WaitForStatus(t, "/", ip, http.StatusForbidden, decisionTimeout)
	}

	h.ReloadWithin(t, cfg, reloadTimeout)

	// the in-memory store does not survive a reload; it is rebuilt from the
	// startup stream, which must yield the same decisions
	for _, ip := range ips {
		h.WaitForStatus(t, "/", ip, http.StatusForbidden, decisionTimeout)
	}
}

func TestReloadPicksUpDecisionAddedDuringReload(t *testing.T) {
	container := sharedCrowdSec(t)
	h := testutils.NewHarness(t)
	cfg := config(t, h, container)

	h.Load(t, cfg)

	ip := testutils.NextTestIP(t)

	// ban concurrently with the reload, so the decision may land either side of
	// the new app's startup fetch; either way it must end up enforced
	done := make(chan struct{})
	go func() {
		defer close(done)
		testutils.Ban(t, container, ip, time.Hour)
	}()

	h.ReloadWithin(t, cfg, reloadTimeout)
	<-done

	h.WaitForStatus(t, "/", ip, http.StatusForbidden, decisionTimeout)
}

func TestReloadTogglesAppSec(t *testing.T) {
	container := sharedAppSec(t)
	h := testutils.NewHarness(t)

	enabled := config(t, h, container, withAppSec(container.AppSecUrl()))
	disabled := config(t, h, container)

	h.Load(t, enabled)
	ip := testutils.NextTestIP(t)

	resp, _ := h.Get(t, appSecAttackPath, ip)
	require.Equal(t, http.StatusForbidden, resp.StatusCode, "AppSec should block the attack path when enabled")

	// disabling AppSec removes the handler from the chain entirely
	h.ReloadWithin(t, disabled, reloadTimeout)
	resp, body := h.Get(t, appSecAttackPath, ip)
	assert.Equal(t, http.StatusOK, resp.StatusCode, "AppSec should not run once disabled")
	assert.Equal(t, allowedBody, body)

	// and re-enabling it restores blocking
	h.ReloadWithin(t, enabled, reloadTimeout)
	resp, _ = h.Get(t, appSecAttackPath, ip)
	assert.Equal(t, http.StatusForbidden, resp.StatusCode, "AppSec should block again once re-enabled")
}

// TestReloadDoesNotLeakGoroutines checks that repeated reloads tear down each
// generation of the app: goroutines must not accumulate, and no reload may hang.
//
// It is deliberately NOT the guard for the shutdown deadlock fixed in d395a27.
// That deadlock needs the stream producer to be parked in a channel send at the
// instant the context is cancelled, and with a realistic ticker that window is
// far too small to hit reliably: reverting the fix leaves this test passing.
// TestStreamBouncerRunReturnsWhenNobodyConsumesTheStream in internal/bouncer
// reproduces it deterministically instead.
//
// What this test does catch is the broader class: a generation that fails to
// shut down at all, and goroutine growth proportional to the reload count.
func TestReloadDoesNotLeakGoroutines(t *testing.T) {
	container := sharedCrowdSec(t)
	h := testutils.NewHarness(t)
	cfg := config(t, h, container)

	h.Load(t, cfg)

	ip := testutils.NextTestIP(t)
	testutils.Ban(t, container, ip, time.Hour)
	h.WaitForStatus(t, "/", ip, http.StatusForbidden, decisionTimeout)

	baseline := settledGoroutines()

	const reloads = 10
	for i := range reloads {
		h.ReloadWithin(t, cfg, reloadTimeout)

		// keep traffic flowing so each generation actually serves requests
		resp, _ := h.Get(t, "/", testutils.NextTestIP(t))
		require.Equalf(t, http.StatusOK, resp.StatusCode, "request failed after reload %d", i+1)
	}

	after := settledGoroutines()

	// Each generation runs a handful of goroutines (stream, decision processing,
	// metrics). Leaking even one per reload would show up as growth roughly
	// proportional to the reload count; a fixed allowance absorbs the churn of
	// whichever generation happens to be running at each measurement.
	const allowance = 15
	assert.LessOrEqualf(t, after, baseline+allowance,
		"goroutine count grew from %d to %d across %d reloads, which suggests each reload leaks",
		baseline, after, reloads)

	// the final generation is still enforcing
	h.WaitForStatus(t, "/", ip, http.StatusForbidden, decisionTimeout)
}

func TestReloadWithInvalidConfigKeepsPreviousConfigServing(t *testing.T) {
	container := sharedCrowdSec(t)
	h := testutils.NewHarness(t)

	h.Load(t, config(t, h, container))

	ip := testutils.NextTestIP(t)
	testutils.Ban(t, container, ip, time.Hour)
	h.WaitForStatus(t, "/", ip, http.StatusForbidden, decisionTimeout)

	// Validate rejects a ticker interval that does not parse
	err := h.LoadExpectingError(t, config(t, h, container, withTicker("not-a-duration")))
	assert.True(t,
		strings.Contains(err.Error(), "ticker interval") || strings.Contains(err.Error(), "invalid duration"),
		"expected the error to name the offending field, got: %s", err)

	// Caddy rolls back, so the previous configuration is still in force
	resp, _ := h.Get(t, "/", ip)
	assert.Equal(t, http.StatusForbidden, resp.StatusCode, "the banned address should still be blocked")

	resp, body := h.Get(t, "/", testutils.NextTestIP(t))
	assert.Equal(t, http.StatusOK, resp.StatusCode, "clean addresses should still be served")
	assert.Equal(t, allowedBody, body)
}

// settledGoroutines returns the goroutine count once it has stopped changing,
// so that teardown of the previous generation is not counted as a leak.
func settledGoroutines() int {
	previous := -1
	for range 20 {
		runtime.GC()
		time.Sleep(250 * time.Millisecond)

		current := runtime.NumGoroutine()
		if current == previous {
			return current
		}
		previous = current
	}

	return runtime.NumGoroutine()
}
