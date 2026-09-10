package bouncer

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"time"

	"github.com/crowdsecurity/crowdsec/pkg/apiclient"
	"github.com/crowdsecurity/crowdsec/pkg/models"
	log "github.com/sirupsen/logrus"

	"github.com/hslatman/caddy-crowdsec-bouncer/internal/metrics"
)

type StreamBouncer struct {
	apiClient           *apiclient.ApiClient
	metricsProvider     *metrics.Provider
	tickerInterval      time.Duration
	timeout             time.Duration
	RetryInitialConnect bool
	opts                apiclient.DecisionsStreamOpts
	Stream              chan *models.DecisionsStreamResponse
}

// timeout deliberately goes after retryInitialConnect so it is not adjacent
// to tickerInterval, which is also a time.Duration.
func NewStreamBouncer(a *apiclient.ApiClient, m *metrics.Provider, tickerInterval time.Duration, retryInitialConnect bool, timeout time.Duration) (*StreamBouncer, error) {
	if tickerInterval <= 0 {
		return nil, fmt.Errorf("lapi update interval must be positive")
	}
	if timeout <= 0 {
		return nil, fmt.Errorf("lapi timeout must be positive")
	}

	return &StreamBouncer{
		apiClient:           a,
		metricsProvider:     m,
		tickerInterval:      tickerInterval,
		timeout:             timeout,
		RetryInitialConnect: retryInitialConnect,
		// CommunityPull and AdditionalPull have no `omitempty` and are only
		// stripped from the query string when true, so leaving them zero
		// sends community_pull=false&additional_pull=false on every request.
		// This bouncer wants both.
		opts: apiclient.DecisionsStreamOpts{
			CommunityPull:  true,
			AdditionalPull: true,
		},
		Stream: make(chan *models.DecisionsStreamResponse),
	}, nil
}

const (
	modeStream = "stream"
	modeLive   = "live"
	modePing   = "ping"
	modeCheck  = "check"
)

const (
	startupTimeoutFloor  = 60 * time.Second
	startupTimeoutFactor = 6
)

// startupTimeout is the budget for the startup=true pull. That call is a
// full-table dump on the LAPI side and its JSON decode is billed to the same
// context, so it gets a throughput budget rather than the latency budget the
// delta pulls run on. The floor keeps it usable for operators who lower
// lapi_timeout to tighten the live path.
func startupTimeout(d time.Duration) time.Duration {
	return max(startupTimeoutFloor, startupTimeoutFactor*d)
}

const (
	retryBase = 10 * time.Second
	// retryCap bounds staleness on recovery to roughly two ticker_interval
	// periods (default 60s each) while cutting retry load on the LAPI by an
	// order of magnitude during a sustained failure.
	retryCap = 2 * time.Minute
	// retryMaxShift caps the exponent so the shift cannot overflow, which
	// matters because the loop runs until it succeeds or is cancelled.
	retryMaxShift = 8
)

// retryDelayBound returns the upper bound of the retry window for the given
// zero-based attempt: an exponential ramp from retryBase, clamped at retryCap.
func retryDelayBound(attempt int) time.Duration {
	if attempt < 0 {
		attempt = 0
	}

	return min(retryCap, retryBase<<min(attempt, retryMaxShift))
}

// nextRetryDelay returns a fully jittered delay in [0, retryDelayBound(attempt)).
// Jitter is not cosmetic here: a compose restart brings several Caddy instances
// up at once, and an unjittered schedule has all of them re-running the LAPI's
// full-dump query in lockstep, which is the load pattern that keeps it slow.
func nextRetryDelay(attempt int, rnd *rand.Rand) time.Duration {
	return time.Duration(rnd.Int63n(int64(retryDelayBound(attempt))))
}

func (b *StreamBouncer) Run(ctx context.Context) {
	defer close(b.Stream)

	ticker := time.NewTicker(b.tickerInterval)

	b.opts.Startup = true

	// jitter source for the initial-connection backoff; only ever used from
	// this goroutine, so an unsynchronised *rand.Rand is fine
	rnd := rand.New(rand.NewSource(time.Now().UnixNano())) //nolint:gosec // jitter, not crypto
	attempt := 0

	// Initial connection
	for {
		data, resp, err := b.getDecisionStream(ctx, b.opts)

		if resp != nil && resp.Response != nil {
			_ = resp.Response.Body.Close()
		}

		if err != nil {
			if b.RetryInitialConnect {
				delay := nextRetryDelay(attempt, rnd)
				attempt++
				// TODO: emit this through Caddy's zap logger directly. The
				// logrus hook in internal/core/logging.go drops entry.Data, so
				// structured fields would be lost today.
				log.Errorf("failed to connect to LAPI (attempt %d), retrying in %s: %s", attempt, delay.Round(time.Millisecond), err)
				select {
				case <-ctx.Done():
					if err := ctx.Err(); err != nil && !errors.Is(err, context.Canceled) {
						log.Error(err)
					}
					return
				case <-time.After(delay):
					continue
				}
			}

			log.Error(err)
			return
		}

		// Guard the send: on shutdown the consumer (Core.startProcessingDecisions)
		// returns on ctx.Done(), so an unguarded send here would block forever and
		// deadlock Core.Shutdown's wg.Wait().
		select {
		case b.Stream <- data:
		case <-ctx.Done():
			return
		}
		break
	}

	b.opts.Startup = false
	for {
		select {
		case <-ctx.Done():
			if err := ctx.Err(); err != nil && !errors.Is(err, context.Canceled) {
				log.Error(err)
			}
			return
		case <-ticker.C:
			data, resp, err := b.getDecisionStream(ctx, b.opts)
			if resp != nil && resp.Response != nil {
				_ = resp.Response.Body.Close()
			}
			if err != nil {
				log.Error(err)
				continue
			}
			// Guard the send so a shutdown mid-loop can't block on a consumer
			// that has already returned on ctx.Done().
			select {
			case b.Stream <- data:
			case <-ctx.Done():
				return
			}
		}
	}
}

// timeoutFor returns the context budget for a stream pull. The startup pull is
// a full dump rather than a request-path call, so it gets its own budget.
func (b *StreamBouncer) timeoutFor(opts apiclient.DecisionsStreamOpts) time.Duration {
	if opts.Startup {
		return startupTimeout(b.timeout)
	}

	return b.timeout
}

func (b *StreamBouncer) getDecisionStream(ctx context.Context, opts apiclient.DecisionsStreamOpts) (*models.DecisionsStreamResponse, *apiclient.Response, error) {
	ctx, cancel := context.WithTimeout(ctx, b.timeoutFor(opts))
	defer cancel()

	b.metricsProvider.IncrementTotalBouncerCalls(modeStream)
	data, resp, err := b.apiClient.Decisions.GetStream(ctx, opts)
	if err != nil {
		b.metricsProvider.IncrementTotalBouncerErrors(modeStream)
	}

	return data, resp, err
}

func (b *StreamBouncer) SetAPIClientForTesting(a *apiclient.ApiClient) {
	b.apiClient = a
}
