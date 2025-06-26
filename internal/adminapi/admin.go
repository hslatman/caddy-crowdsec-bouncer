package adminapi

import (
	"context"
	"net/netip"
	"time"

	"github.com/crowdsecurity/crowdsec/pkg/models"
)

type Info struct {
	StreamingEnabled        bool
	TickerInterval          string
	AppSecURL               string
	ShouldFailHard          bool
	UserAgent               string
	InstanceID              string
	Uptime                  time.Duration
	NumberOfActiveDecisions int
}

type Admin interface {
	Info(ctx context.Context) Info
	Ping(ctx context.Context) bool
	Healthy(ctx context.Context) bool
	Check(ctx context.Context, ip netip.Addr, forceLive bool) (bool, *models.Decision, error)
}
