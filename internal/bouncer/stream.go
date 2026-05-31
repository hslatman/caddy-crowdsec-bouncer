package bouncer

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/crowdsecurity/crowdsec/pkg/apiclient"
	"github.com/crowdsecurity/crowdsec/pkg/models"
	log "github.com/sirupsen/logrus"

	"github.com/hslatman/caddy-crowdsec-bouncer/internal/metrics"
)

type StreamBouncer struct {
	APIKey              string `yaml:"api_key"`
	APIUrl              string `yaml:"api_url"`
	InsecureSkipVerify  *bool  `yaml:"insecure_skip_verify"`
	CertPath            string `yaml:"cert_path"`
	KeyPath             string `yaml:"key_path"`
	CAPath              string `yaml:"ca_cert_path"`
	RetryInitialConnect bool   `yaml:"retry_initial_connect"`

	TickerInterval         string   `yaml:"update_frequency"`
	Scopes                 []string `yaml:"scopes"`
	ScenariosContaining    []string `yaml:"scenarios_containing"`
	ScenariosNotContaining []string `yaml:"scenarios_not_containing"`
	Origins                []string `yaml:"origins"`

	TickerIntervalDuration time.Duration
	Stream                 chan *models.DecisionsStreamResponse
	APIClient              *apiclient.ApiClient
	UserAgent              string
	Opts                   apiclient.DecisionsStreamOpts

	MetricsProvider *metrics.Provider
}

func (b *StreamBouncer) Init() error {
	var err error

	// validate the configuration

	if b.APIUrl == "" {
		return fmt.Errorf("config does not contain LAPI url")
	}

	if !strings.HasSuffix(b.APIUrl, "/") {
		b.APIUrl += "/"
	}

	if b.APIKey == "" && b.CertPath == "" && b.KeyPath == "" {
		return fmt.Errorf("config does not contain LAPI key or certificate")
	}

	//  scopes, origins, etc.

	if b.Scopes != nil {
		b.Opts.Scopes = strings.Join(b.Scopes, ",")
	}

	if b.ScenariosContaining != nil {
		b.Opts.ScenariosContaining = strings.Join(b.ScenariosContaining, ",")
	}

	if b.ScenariosNotContaining != nil {
		b.Opts.ScenariosNotContaining = strings.Join(b.ScenariosNotContaining, ",")
	}

	if b.Origins != nil {
		b.Opts.Origins = strings.Join(b.Origins, ",")
	}

	// update_frequency or however it's called in the .yaml of the specific bouncer

	if b.TickerInterval == "" {
		log.Warningf("lapi update interval is not defined, using default value of 10s")
		b.TickerInterval = "10s"
	}

	b.TickerIntervalDuration, err = time.ParseDuration(b.TickerInterval)
	if err != nil {
		return fmt.Errorf("unable to parse lapi update interval '%s': %w", b.TickerInterval, err)
	}

	if b.TickerIntervalDuration <= 0 {
		return fmt.Errorf("lapi update interval must be positive")
	}

	// prepare the client object for the lapi

	b.Stream = make(chan *models.DecisionsStreamResponse)

	b.APIClient, err = getAPIClient(b.APIUrl, b.UserAgent, b.APIKey, b.CAPath, b.CertPath, b.KeyPath, b.InsecureSkipVerify, log.StandardLogger())
	if err != nil {
		return fmt.Errorf("api client init: %w", err)
	}

	return nil
}

const (
	modeStream = "stream"
	modeLive   = "live"
	modePing   = "ping"
	modeCheck  = "check"
)

func (b *StreamBouncer) Run(ctx context.Context) {
	defer func() {
		log.Warn("running defer; closing stream?")
	}()
	defer close(b.Stream)

	ticker := time.NewTicker(b.TickerIntervalDuration)

	b.Opts.Startup = true

	// Initial connection
	for {
		data, resp, err := b.getDecisionStream(ctx, b.Opts)

		if resp != nil && resp.Response != nil {
			_ = resp.Response.Body.Close()
		}

		if err != nil {
			if b.RetryInitialConnect {
				log.Errorf("failed to connect to LAPI, retrying in 10s: %s", err)
				select {
				case <-ctx.Done():
					if err := ctx.Err(); err != nil && !errors.Is(err, context.Canceled) {
						log.Error(err)
					}
					return
				case <-time.After(10 * time.Second):
					continue
				}
			}

			log.Error(err)
			return
		}

		b.Stream <- data
		break
	}

	b.Opts.Startup = false
	for {
		select {
		case <-ctx.Done():
			if err := ctx.Err(); err != nil && !errors.Is(err, context.Canceled) {
				log.Error(err)
			}
			return
		case <-ticker.C:
			data, resp, err := b.getDecisionStream(ctx, b.Opts)
			if resp != nil && resp.Response != nil {
				_ = resp.Response.Body.Close()
			}
			if err != nil {
				log.Error(err)
				continue
			}
			b.Stream <- data
		}
	}
}

func (b *StreamBouncer) getDecisionStream(ctx context.Context, opts apiclient.DecisionsStreamOpts) (*models.DecisionsStreamResponse, *apiclient.Response, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	b.MetricsProvider.IncrementTotalBouncerCalls(modeStream)
	data, resp, err := b.APIClient.Decisions.GetStream(ctx, opts)
	if err != nil {
		b.MetricsProvider.IncrementTotalBouncerErrors(modeStream)
	}

	return data, resp, err
}
