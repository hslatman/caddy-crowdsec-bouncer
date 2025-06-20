package crowdsec

import (
	"context"
	"net/netip"
	"time"

	"github.com/crowdsecurity/crowdsec/pkg/models"
)

type info struct {
	streamingEnabled        bool
	tickerInterval          string
	appSecURL               string
	shouldFailHard          bool
	userAgent               string
	instanceID              string
	uptime                  time.Duration
	numberOfActiveDecisions int
}

type admin interface {
	info(ctx context.Context) info
	ping(ctx context.Context) bool
	healthy(ctx context.Context) bool
	check(ctx context.Context, ip netip.Addr, forceLive bool) (bool, *models.Decision, error)
}

func (c *CrowdSec) info(_ context.Context) info {
	return info{
		streamingEnabled:        c.isStreamingEnabled(),
		tickerInterval:          c.TickerInterval,
		appSecURL:               c.AppSecUrl,
		shouldFailHard:          c.shouldFailHard(),
		userAgent:               c.bouncer.UserAgent(),
		instanceID:              c.bouncer.InstanceID(),
		uptime:                  time.Since(c.bouncer.StartedAt()),
		numberOfActiveDecisions: c.bouncer.NumberOfActiveDecisions(),
	}
}

func (c *CrowdSec) healthy(ctx context.Context) bool {
	b, _ := c.bouncer.Healthy(ctx)
	return b
}

func (c *CrowdSec) ping(ctx context.Context) bool {
	b, _ := c.bouncer.Ping(ctx)
	return b
}

func (c *CrowdSec) check(_ context.Context, ip netip.Addr, forceLive bool) (bool, *models.Decision, error) {
	return c.bouncer.IsAllowed(ip, forceLive)
}
