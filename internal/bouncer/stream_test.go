package bouncer

import (
	"context"
	"errors"
	"io"
	"math/rand"
	"net/http"
	"net/url"
	"regexp"
	"testing"
	"time"

	"github.com/crowdsecurity/crowdsec/pkg/apiclient"
	"github.com/crowdsecurity/crowdsec/pkg/models"
	"github.com/jarcoal/httpmock"
	"github.com/prometheus/client_golang/prometheus"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
	"go.uber.org/goleak"
	"go.uber.org/zap/zaptest"

	"github.com/hslatman/caddy-crowdsec-bouncer/internal/metrics"
)

const testAPIURL = "http://127.0.0.1:8080/"

func newTestStreamBouncer(t *testing.T, tickerInterval time.Duration) *StreamBouncer {
	t.Helper()

	transport := &apiclient.APIKeyTransport{
		APIKey: "apiKey",
		// crucial for httpmock to work: NewDefaultClient type-asserts on
		// *http.Transport and panics on httpmock's, so it has to be wrapped here
		Transport: httpmock.DefaultTransport,
	}

	apiURL, err := apiclient.NewDefaultClient(mustParseURL(t, testAPIURL), "v1", "testing", transport.Client())
	require.NoError(t, err)

	provider, err := metrics.NewProvider(metrics.Config{
		APIClient:        apiURL,
		MetricsRegistry:  prometheus.NewRegistry(),
		Interval:         0,
		Logger:           zaptest.NewLogger(t),
		UserAgentName:    "testing",
		UserAgentVersion: "v0.0.0",
		InstanceID:       "instance",
	})
	require.NoError(t, err)

	b, err := NewStreamBouncer(apiURL, provider, tickerInterval, false, 10*time.Second)
	require.NoError(t, err)

	return b
}

// TestStreamBouncerRunReturnsWhenNobodyConsumesTheStream is the regression guard
// for the shutdown deadlock fixed in d395a27.
//
// StreamBouncer.Run sends fetched decisions on an unbuffered channel. Its only
// consumer, Core.startProcessingDecisions, returns as soon as the context is
// cancelled. If the send is not itself cancellable, a producer that is blocked
// in that send when shutdown begins stays blocked forever, and Core.Shutdown
// hangs in wg.Wait().
//
// Nobody reads b.Stream here, so the producer is guaranteed to be parked in the
// send when the context is cancelled. That makes the race deterministic, which
// it is not at the end-to-end level: with a realistic ticker the window between
// "fetched" and "sent" is far too small to hit reliably.
func TestStreamBouncerRunReturnsWhenNobodyConsumesTheStream(t *testing.T) {
	httpmock.Activate()
	defer httpmock.DeactivateAndReset()

	urlRegexp := regexp.MustCompile(`http://127\.0\.0\.1:8080/v1/decisions/stream\?.*startup=.*`)
	httpmock.RegisterRegexpResponder("GET", urlRegexp,
		httpmock.NewJsonResponderOrPanic(200, &models.DecisionsStreamResponse{
			New:     []*models.Decision{},
			Deleted: []*models.Decision{},
		}))

	// a long ticker keeps this to the initial fetch, so the bouncer parks in the
	// send rather than looping
	b := newTestStreamBouncer(t, time.Hour)

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	returned := make(chan struct{})
	go func() {
		defer close(returned)
		b.Run(ctx)
	}()

	// let the initial fetch complete so Run is parked in the channel send
	select {
	case <-returned:
		t.Fatal("Run returned before the context was cancelled")
	case <-time.After(500 * time.Millisecond):
	}

	cancel()

	select {
	case <-returned:
		// Run observed the cancellation and gave up on the send, as required
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return within 5s of context cancellation: the decision " +
			"stream send is not cancellable, so Core.Shutdown would hang in wg.Wait()")
	}
}

// TestStreamBouncerRunReturnsOnCancelWhileIdle covers the ordinary path, where
// the bouncer is waiting on its ticker rather than on a send.
func TestStreamBouncerRunReturnsOnCancelWhileIdle(t *testing.T) {
	httpmock.Activate()
	defer httpmock.DeactivateAndReset()

	urlRegexp := regexp.MustCompile(`http://127\.0\.0\.1:8080/v1/decisions/stream\?.*startup=.*`)
	httpmock.RegisterRegexpResponder("GET", urlRegexp,
		httpmock.NewJsonResponderOrPanic(200, &models.DecisionsStreamResponse{
			New:     []*models.Decision{},
			Deleted: []*models.Decision{},
		}))

	b := newTestStreamBouncer(t, time.Hour)

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	returned := make(chan struct{})
	go func() {
		defer close(returned)
		b.Run(ctx)
	}()

	// drain the initial send so Run proceeds to its ticker loop
	select {
	case <-b.Stream:
	case <-time.After(5 * time.Second):
		t.Fatal("did not receive the initial decision stream")
	}

	cancel()

	select {
	case <-returned:
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return within 5s of context cancellation while idle")
	}
}

func TestNewStreamBouncerRejectsNonPositiveInterval(t *testing.T) {
	provider := newTestStreamBouncer(t, time.Hour).metricsProvider

	for _, interval := range []time.Duration{0, -time.Second} {
		_, err := NewStreamBouncer(nil, provider, interval, false, 10*time.Second)
		require.Error(t, err, "interval %s should be rejected", interval)
	}

	for _, timeout := range []time.Duration{0, -time.Second} {
		_, err := NewStreamBouncer(nil, provider, time.Hour, false, timeout)
		require.Error(t, err, "timeout %s should be rejected", timeout)
	}
}

// TestStreamBouncerRequestsCommunityAndAdditionalPull guards §4.3: the two
// options have no `omitempty` and are only stripped from the query when true,
// so a zero-valued opts struct actively asks the LAPI to withhold community and
// third-party blocklist decisions.
func TestStreamBouncerRequestsCommunityAndAdditionalPull(t *testing.T) {
	httpmock.Activate()
	defer httpmock.DeactivateAndReset()

	var called string
	urlRegexp := regexp.MustCompile(`http://127\.0\.0\.1:8080/v1/decisions/stream\?`)
	httpmock.RegisterRegexpResponder("GET", urlRegexp,
		func(req *http.Request) (*http.Response, error) {
			called = req.URL.RawQuery
			return httpmock.NewJsonResponse(200, &models.DecisionsStreamResponse{
				New:     []*models.Decision{},
				Deleted: []*models.Decision{},
			})
		})

	b := newTestStreamBouncer(t, time.Hour)

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	go b.Run(ctx)

	select {
	case <-b.Stream:
	case <-time.After(5 * time.Second):
		t.Fatal("did not receive the initial decision stream")
	}

	require.Contains(t, called, "startup=true")
	require.NotContains(t, called, "community_pull=false")
	require.NotContains(t, called, "additional_pull=false")
}

func TestStartupTimeout(t *testing.T) {
	tests := []struct {
		name string
		in   time.Duration
		want time.Duration
	}{
		{"default", 10 * time.Second, 60 * time.Second},
		{"floor-applies", 2 * time.Second, 60 * time.Second},
		{"exactly-at-floor", 10 * time.Second, 60 * time.Second},
		{"factor-applies", 30 * time.Second, 180 * time.Second},
		{"large", 5 * time.Minute, 30 * time.Minute},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, startupTimeout(tt.in))
		})
	}
}

// TestStreamBouncerBudgetsDifferBetweenStartupAndDelta is the regression test
// for #138: the startup pull is a full-table dump whose JSON decode is billed
// to the same context, so it must not run on the delta pull's latency budget.
//
// The responder is slower than lapi_timeout but far faster than the 60s startup
// floor, so the startup call succeeds where the delta call times out.
func TestStreamBouncerBudgetsDifferBetweenStartupAndDelta(t *testing.T) {
	// The delta pull below is deliberately timed out to prove the budgets
	// differ, and CrowdSec's apiclient logs that as an error-level line via
	// the global logrus logger. Silence it for the duration of this test only
	// so the timeout isn't mistaken for a real test failure in CI logs; other
	// tests in this package see the standard logger's default output again.
	prevOut := log.StandardLogger().Out
	log.SetOutput(io.Discard)
	t.Cleanup(func() { log.SetOutput(prevOut) })

	httpmock.Activate()
	defer httpmock.DeactivateAndReset()

	urlRegexp := regexp.MustCompile(`http://127\.0\.0\.1:8080/v1/decisions/stream\?`)
	httpmock.RegisterRegexpResponder("GET", urlRegexp,
		func(req *http.Request) (*http.Response, error) {
			select {
			case <-req.Context().Done():
				return nil, req.Context().Err()
			case <-time.After(300 * time.Millisecond):
			}
			return httpmock.NewJsonResponse(200, &models.DecisionsStreamResponse{
				New:     []*models.Decision{},
				Deleted: []*models.Decision{},
			})
		})

	b := newTestStreamBouncer(t, time.Hour)
	b.timeout = 50 * time.Millisecond

	require.Equal(t, 50*time.Millisecond, b.timeoutFor(apiclient.DecisionsStreamOpts{}))
	require.Equal(t, 60*time.Second, b.timeoutFor(apiclient.DecisionsStreamOpts{Startup: true}))

	// the startup pull gets the 60s floor and completes
	data, resp, err := b.getDecisionStream(t.Context(), apiclient.DecisionsStreamOpts{Startup: true})
	if resp != nil && resp.Response != nil {
		_ = resp.Response.Body.Close()
	}
	require.NoError(t, err)
	require.NotNil(t, data)

	// the same response on a delta pull blows the latency budget
	_, resp, err = b.getDecisionStream(t.Context(), apiclient.DecisionsStreamOpts{})
	if resp != nil && resp.Response != nil {
		_ = resp.Response.Body.Close()
	}
	require.Error(t, err)
	require.ErrorIs(t, err, context.DeadlineExceeded)
}

func TestRetryDelayBound(t *testing.T) {
	require.Equal(t, 10*time.Second, retryDelayBound(0))
	require.Equal(t, 20*time.Second, retryDelayBound(1))
	require.Equal(t, 40*time.Second, retryDelayBound(2))
	require.Equal(t, 80*time.Second, retryDelayBound(3))
	require.Equal(t, 2*time.Minute, retryDelayBound(4), "must clamp at retryCap")

	// monotonic non-decreasing, never past the cap, never below the base
	prev := time.Duration(0)
	for attempt := range 100 {
		got := retryDelayBound(attempt)
		require.GreaterOrEqual(t, got, prev, "attempt %d went backwards", attempt)
		require.LessOrEqual(t, got, 2*time.Minute, "attempt %d exceeded the cap", attempt)
		require.GreaterOrEqual(t, got, 10*time.Second, "attempt %d below the base", attempt)
		prev = got
	}

	require.Equal(t, 10*time.Second, retryDelayBound(-1), "negative attempts clamp to the base")
}

func TestNextRetryDelayStaysWithinItsBound(t *testing.T) {
	rnd := rand.New(rand.NewSource(1)) //nolint:gosec // jitter, not crypto

	for attempt := range 20 {
		bound := retryDelayBound(attempt)
		for range 100 {
			got := nextRetryDelay(attempt, rnd)
			require.GreaterOrEqual(t, got, time.Duration(0))
			require.Less(t, got, bound, "attempt %d produced %s, bound %s", attempt, got, bound)
		}
	}
}

// TestStreamBouncerRunReturnsDuringRetryBackoff guards the shutdown path that
// the backoff makes riskier: with a cap of two minutes, a Run that does not
// select on ctx.Done() while sleeping would hang Core.Shutdown in wg.Wait().
func TestStreamBouncerRunReturnsDuringRetryBackoff(t *testing.T) {
	defer goleak.VerifyNone(t, goleak.IgnoreCurrent())

	// The connection is deliberately made to fail so Run parks in the backoff
	// sleep, and each failed attempt logs an error-level line via the global
	// logrus logger. Silence it for the duration of this test only, following
	// the same pattern as TestStreamBouncerBudgetsDifferBetweenStartupAndDelta.
	prevOut := log.StandardLogger().Out
	log.SetOutput(io.Discard)
	t.Cleanup(func() { log.SetOutput(prevOut) })

	httpmock.Activate()
	defer httpmock.DeactivateAndReset()

	urlRegexp := regexp.MustCompile(`http://127\.0\.0\.1:8080/v1/decisions/stream\?`)
	httpmock.RegisterRegexpResponder("GET", urlRegexp,
		httpmock.NewErrorResponder(errors.New("lapi is down")))

	b := newTestStreamBouncer(t, time.Hour)
	b.RetryInitialConnect = true

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	returned := make(chan struct{})
	go func() {
		defer close(returned)
		b.Run(ctx)
	}()

	// let the first attempt fail so Run is parked in the backoff sleep
	select {
	case <-returned:
		t.Fatal("Run returned instead of retrying the initial connection")
	case <-time.After(200 * time.Millisecond):
	}

	cancel()

	select {
	case <-returned:
		// Run observed the cancellation mid-backoff, as required
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return within 5s of context cancellation while backing off")
	}
}

func mustParseURL(t *testing.T, raw string) *url.URL {
	t.Helper()

	u, err := url.Parse(raw)
	require.NoError(t, err)

	return u
}
