package bouncer

import (
	"context"
	"net/url"
	"regexp"
	"testing"
	"time"

	"github.com/crowdsecurity/crowdsec/pkg/apiclient"
	"github.com/crowdsecurity/crowdsec/pkg/models"
	"github.com/jarcoal/httpmock"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/require"
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

	provider, err := metrics.NewProvider(apiURL, prometheus.NewRegistry(), nil, 0, zaptest.NewLogger(t), "testing", "v0.0.0", "instance")
	require.NoError(t, err)

	b, err := NewStreamBouncer(apiURL, provider, tickerInterval, false)
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

	urlRegexp := regexp.MustCompile(`http://127\.0\.0\.1:8080/v1/decisions/stream\?startup=.*`)
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

	urlRegexp := regexp.MustCompile(`http://127\.0\.0\.1:8080/v1/decisions/stream\?startup=.*`)
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
		_, err := NewStreamBouncer(nil, provider, interval, false)
		require.Error(t, err, "interval %s should be rejected", interval)
	}
}

func mustParseURL(t *testing.T, raw string) *url.URL {
	t.Helper()

	u, err := url.Parse(raw)
	require.NoError(t, err)

	return u
}
