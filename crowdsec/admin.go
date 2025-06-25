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
		UserAgent:               c.bouncer.UserAgent(),
		InstanceID:              c.bouncer.InstanceID(),
		Uptime:                  time.Since(c.bouncer.StartedAt()),
		NumberOfActiveDecisions: c.bouncer.NumberOfActiveDecisions(),
	}
}

func (c *CrowdSec) Healthy(ctx context.Context) bool {
	b, _ := c.bouncer.Healthy(ctx)
	return b
}

func (c *CrowdSec) Ping(ctx context.Context) bool {
	b, _ := c.bouncer.Ping(ctx)
	return b
}

func (c *CrowdSec) Check(_ context.Context, ip netip.Addr, forceLive bool) (bool, *models.Decision, error) {
	return c.bouncer.IsAllowed(ip, forceLive)
}
