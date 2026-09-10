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

// list performs the decision lookup and also reports the HTTP status the LAPI
// answered with -- 0 when it did not answer at all (transport failure). Get and
// Probe both route through here so the lookup is built in exactly one place.
func (b *LiveBouncer) list(ctx context.Context, value, mode string) (*models.GetDecisionsResponse, int, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	filter := apiclient.DecisionsListOpts{
		IPEquals: value,
	}

	b.metricsProvider.IncrementTotalBouncerCalls(mode)
	decision, resp, err := b.apiClient.Decisions.List(ctx, filter)

	status := 0
	if resp != nil && resp.Response != nil {
		status = resp.Response.StatusCode
		_ = resp.Response.Body.Close()
	}
	if err != nil {
		b.metricsProvider.IncrementTotalBouncerErrors(mode)
		return &models.GetDecisionsResponse{}, status, err
	}

	return decision, status, nil
}

func (b *LiveBouncer) Get(ctx context.Context, value, method string) (*models.GetDecisionsResponse, error) {
	var mode string
	switch method {
	case "ping":
		mode = modePing
	case "check":
		mode = modeCheck
	default:
		mode = modeLive
	}

	decision, _, err := b.list(ctx, value, mode)

	return decision, err
}

// Probe performs the ping lookup and reports the HTTP status the LAPI answered
// with, or 0 when it did not answer at all. It lets a caller tell a rejected
// request (4xx: the LAPI is up, the bouncer's own key or request is the
// problem) from a failing LAPI (5xx) or an unreachable one (0). Capped well
// below a typical 10s liveness-probe timeout so the probe itself never times
// out while waiting on a slow LAPI.
func (b *LiveBouncer) Probe(ctx context.Context) (int, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	_, status, err := b.list(ctx, "127.0.0.255", modePing)

	return status, err
}
