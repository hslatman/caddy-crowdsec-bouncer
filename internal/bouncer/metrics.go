package bouncer

import (
	"context"
	"errors"

	"go.uber.org/zap"

	"github.com/hslatman/caddy-crowdsec-bouncer/internal/metrics"
)

func (b *Bouncer) startMetricsProvider(ctx context.Context) {
	b.wg.Go(func() {
		b.logger.Debug("starting metrics provider", b.zapField())
		if err := b.metricsProvider.Run(ctx, b.startedAt); err != nil {
			if errors.Is(err, metrics.ErrProviderHalted) {
				b.logger.Info("metrics provider stopped", b.zapField())
			} else {
				b.logger.Error("failed running metrics provider", b.zapField(), zap.Error(err))
			}
		}
	})
}

func (b *Bouncer) IncrementProcessedRequests(ctx context.Context, server, module string, isIPv6 bool) context.Context {
	return b.metricsProvider.IncrementProcessedRequests(ctx, server, module, isIPv6)
}

func (b *Bouncer) IncrementBlockedRequests(server, origin, remediation string, isIPv6 bool) {
	b.metricsProvider.IncrementBlockedRequests(server, origin, remediation, isIPv6)
}
