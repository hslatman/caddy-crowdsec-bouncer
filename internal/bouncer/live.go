package bouncer

import (
	"context"
	"time"

	"github.com/hslatman/caddy-crowdsec-bouncer/internal/metrics"

	"github.com/crowdsecurity/crowdsec/pkg/apiclient"
	"github.com/crowdsecurity/crowdsec/pkg/models"
)

type LiveBouncer struct {
	apiClient       *apiclient.ApiClient
	metricsProvider *metrics.Provider
}

func NewLiveBouncer(a *apiclient.ApiClient, m *metrics.Provider) *LiveBouncer {
	return &LiveBouncer{
		apiClient:       a,
		metricsProvider: m,
	}
}

func (b *LiveBouncer) Get(ctx context.Context, value, method string) (*models.GetDecisionsResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	filter := apiclient.DecisionsListOpts{
		IPEquals: value,
	}

	var mode string
	switch method {
	case "ping":
		mode = modePing
	case "check":
		mode = modeCheck
	default:
		mode = modeLive
	}

	b.metricsProvider.IncrementTotalBouncerCalls(mode)
	decision, resp, err := b.apiClient.Decisions.List(ctx, filter)
	if err != nil {
		b.metricsProvider.IncrementTotalBouncerErrors(mode)
		if resp != nil && resp.Response != nil {
			_ = resp.Response.Body.Close()
		}
		return &models.GetDecisionsResponse{}, err
	}

	if resp != nil && resp.Response != nil {
		_ = resp.Response.Body.Close()
	}

	return decision, nil
}
