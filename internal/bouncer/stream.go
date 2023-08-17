package bouncer

import (
	"context"
	"fmt"
	"net/url"
	"time"

	"github.com/crowdsecurity/crowdsec/pkg/apiclient"
	"github.com/crowdsecurity/crowdsec/pkg/models"
)

// StreamBouncer is a bouncer that polls the CrowdSec Local API
// periodically to get (new) decisions. It's largely a copy of the
// implementation in github.com/crowdsec/go-cs-bouncer, but without
// the fatal calls to log.Fatalf when an API call fails. This allows
// for more control over what happens when a connection error
// occurs.
type StreamBouncer struct {
	APIKey                 string
	APIUrl                 string
	TickerInterval         string
	TickerIntervalDuration time.Duration
	Stream                 chan *models.DecisionsStreamResponse
	APIClient              *apiclient.ApiClient
	UserAgent              string
	Errors                 chan error
}

// Init initializes the StreamBouncer for usage
func (b *StreamBouncer) Init() error {
	var err error
	var apiURL *url.URL

	b.Stream = make(chan *models.DecisionsStreamResponse)

	apiURL, err = url.Parse(b.APIUrl)
	if err != nil {
		return fmt.Errorf("local API Url %q: %w", b.APIUrl, err)
	}
	t := &apiclient.APIKeyTransport{
		APIKey: b.APIKey,
	}

	b.APIClient, err = apiclient.NewDefaultClient(apiURL, "v1", b.UserAgent, t.Client())
	if err != nil {
		return fmt.Errorf("api client init: %w", err)
	}

	b.TickerIntervalDuration, err = time.ParseDuration(b.TickerInterval)
	if err != nil {
		return fmt.Errorf("unable to parse duration %q: %w", b.TickerInterval, err)
	}

	b.Errors = make(chan error)

	return nil
}

// Run runs the StreamBouncer
func (b *StreamBouncer) Run() {
	ticker := time.NewTicker(b.TickerIntervalDuration)

	opts := apiclient.DecisionsStreamOpts{
		Startup: true,
	}
	data, _, err := b.APIClient.Decisions.GetStream(context.Background(), opts) // true means we just started the bouncer
	if err != nil {
		b.Errors <- err
	}

	if data != nil {
		b.Stream <- data
	}

	opts = apiclient.DecisionsStreamOpts{
		Startup: false,
	}
	for range ticker.C {
		data, _, err := b.APIClient.Decisions.GetStream(context.Background(), opts)
		if err != nil {
			b.Errors <- err
		}
		if data != nil {
			b.Stream <- data
		}
	}
}
