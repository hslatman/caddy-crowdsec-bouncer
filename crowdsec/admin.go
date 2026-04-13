package crowdsec

import (
	"context"
	"net/netip"
	"time"

	"github.com/crowdsecurity/crowdsec/pkg/models"

	"github.com/hslatman/caddy-crowdsec-bouncer/internal/adminapi"
)

func (c *CrowdSec) Info(_ context.Context) adminapi.Info {
	return adminapi.Info{
		StreamingEnabled:        c.isStreamingEnabled(),
		TickerInterval:          c.TickerInterval,
		AppSecURL:               c.AppSecUrl,
		ShouldFailHard:          c.shouldFailHard(),
		UserAgent:               c.core.UserAgent(),
		InstanceID:              c.core.InstanceID(),
		Uptime:                  time.Since(c.core.StartedAt()),
		NumberOfActiveDecisions: c.core.NumberOfActiveDecisions(),
	}
}

func (c *CrowdSec) Healthy(ctx context.Context) bool {
	b, _ := c.core.Healthy(ctx)
	return b
}

func (c *CrowdSec) Ping(ctx context.Context) bool {
	b, _ := c.core.Ping(ctx)
	return b
}

func (c *CrowdSec) Check(_ context.Context, ip netip.Addr, forceLive bool) (bool, *models.Decision, error) {
	return c.core.IsAllowed(ip, forceLive, "check")
}
