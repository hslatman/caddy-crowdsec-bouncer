package bouncer

import (
	"context"
	"errors"
	"fmt"
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
	RetryInitialConnect bool
	opts                apiclient.DecisionsStreamOpts
	Stream              chan *models.DecisionsStreamResponse
}

func NewStreamBouncer(a *apiclient.ApiClient, m *metrics.Provider, tickerInterval time.Duration, retryInitialConnect bool) (*StreamBouncer, error) {
	if tickerInterval <= 0 {
		return nil, fmt.Errorf("lapi update interval must be positive")
	}

	return &StreamBouncer{
		apiClient:           a,
		metricsProvider:     m,
		tickerInterval:      tickerInterval,
		RetryInitialConnect: retryInitialConnect,
		Stream:              make(chan *models.DecisionsStreamResponse),
	}, nil
}

const (
	modeStream = "stream"
	modeLive   = "live"
	modePing   = "ping"
	modeCheck  = "check"
)

func (b *StreamBouncer) Run(ctx context.Context) {
	defer close(b.Stream)

	ticker := time.NewTicker(b.tickerInterval)

	b.opts.Startup = true

	// Initial connection
	for {
		data, resp, err := b.getDecisionStream(ctx, b.opts)

		if resp != nil && resp.Response != nil {
			_ = resp.Response.Body.Close()
		}

		if err != nil {
			if b.RetryInitialConnect {
				log.Errorf("failed to connect to LAPI, retrying in 10s: %s", err)
				select {
				case <-ctx.Done():
					if err := ctx.Err(); err != nil && !errors.Is(err, context.Canceled) {
						log.Error(err)
					}
					return
				case <-time.After(10 * time.Second):
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

func (b *StreamBouncer) getDecisionStream(ctx context.Context, opts apiclient.DecisionsStreamOpts) (*models.DecisionsStreamResponse, *apiclient.Response, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
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
