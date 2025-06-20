package bouncer

import (
	"context"
	"fmt"
	"time"

	"github.com/crowdsecurity/crowdsec/pkg/apiclient"
	"github.com/crowdsecurity/crowdsec/pkg/models"
	csbouncer "github.com/crowdsecurity/go-cs-bouncer"
	"github.com/crowdsecurity/go-cs-lib/ptr"
	"github.com/prometheus/client_golang/prometheus"
	"go.uber.org/zap"
)

var (
	// metrics provided by the go-cs-bouncer package
	totalLAPICalls  = csbouncer.TotalLAPICalls
	totalLAPIErrors = csbouncer.TotalLAPIError

	// appsec metrics
	totalAppSecCalls = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "lapi_appsec_requests_total",
		Help: "The total number of calls to CrowdSec LAPI AppSec component",
	})
	totalAppSecErrors = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "lapi_appsec_requests_failures_total",
		Help: "The total number of failed calls to CrowdSec LAPI AppSec component",
	})

	// TODO: additional metrics for number of blocked IPs / requests?
	// TODO: referencing the global metrics from csbouncer may not be the right
	// thing to do with how the CrowdSec module operates as part of Caddy. On
	// configuration reloads it would be pointing to the same counters. Thay may,
	// or may not be what we want.
)

func newMetricsProvider(client *apiclient.ApiClient, updater csbouncer.MetricsUpdater, interval time.Duration) (*csbouncer.MetricsProvider, error) {
	m, err := csbouncer.NewMetricsProvider(
		client,
		userAgentName,
		updater,
		newMetricsLogger(),
	)
	if err != nil {
		return nil, fmt.Errorf("failed creating metrics provider: %w", err)
	}

	m.Interval = interval

	return m, nil
}

func (b *Bouncer) startMetricsProvider(ctx context.Context) {
	b.wg.Add(1)
	go func() {
		defer b.wg.Done()

		b.logger.Debug("starting metrics provider", b.zapField())
		if err := b.metricsProvider.Run(ctx); err != nil {
			if err.Error() == "metric provider halted" {
				b.logger.Info("metrics provider stopped", b.zapField())
			} else {
				b.logger.Error("failed running metrics provider", b.zapField(), zap.Error(err))
			}
		}
	}()
}

func (b *Bouncer) updateMetrics(m *models.RemediationComponentsMetrics, interval time.Duration) {
	m.Name = userAgentName // instance ID? Is name provided when creating bouncer in CrowdSec, it seems
	m.Version = ptr.Of(userAgentVersion)
	m.Type = userAgentName
	m.UtcStartupTimestamp = ptr.Of(b.startedAt.UTC().Unix())

	// TODO: add metrics
}
