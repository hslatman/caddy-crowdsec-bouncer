package crowdsec

import (
	"context"
	"net/netip"
	"time"

	"github.com/crowdsecurity/crowdsec/pkg/models"

	"github.com/hslatman/caddy-crowdsec-bouncer/internal/adminapi"
)

func (c *CrowdSec) Info(_ context.Context) adminapi.Info {
	info := adminapi.Info{
		StreamingEnabled: c.IsCrowdSecEnabled() && c.isStreamingEnabled(),
		TickerInterval:   c.TickerInterval,
		ShouldFailHard:   c.shouldFailHard(),
	}
	if c.IsAppSecEnabled() {
		info.AppSecURL = c.AppSecUrl
	}
	if c.core == nil {
		return info
	}
	info.UserAgent = c.core.UserAgent()
	info.InstanceID = c.core.InstanceID()
	info.Uptime = time.Since(c.core.StartedAt())
	info.NumberOfActiveDecisions = c.core.NumberOfActiveDecisions()
	return info
}

func (c *CrowdSec) Healthy(ctx context.Context) bool {
	if c.core == nil {
		return false
	}
	b, _ := c.core.Healthy(ctx)
	return b
}

func (c *CrowdSec) Ping(ctx context.Context) bool {
	if c.core == nil {
		return false
	}
	b, _ := c.core.Ping(ctx)
	return b
}

func (c *CrowdSec) Check(ctx context.Context, ip netip.Addr, forceLive bool) (bool, *models.Decision, error) {
	if c.core == nil || !c.IsCrowdSecEnabled() {
		return true, nil, nil
	}
	return c.core.IsAllowed(ctx, ip, forceLive, "check")
}
