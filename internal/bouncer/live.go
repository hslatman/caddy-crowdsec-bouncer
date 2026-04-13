package bouncer

import (
	"context"
	"fmt"
	"strings"

	"github.com/hslatman/caddy-crowdsec-bouncer/internal/metrics"
	log "github.com/sirupsen/logrus"

	"github.com/crowdsecurity/crowdsec/pkg/apiclient"
	"github.com/crowdsecurity/crowdsec/pkg/models"
)

type LiveBouncer struct {
	APIKey             string `yaml:"api_key"`
	APIUrl             string `yaml:"api_url"`
	InsecureSkipVerify *bool  `yaml:"insecure_skip_verify"`
	CertPath           string `yaml:"cert_path"`
	KeyPath            string `yaml:"key_path"`
	CAPath             string `yaml:"ca_cert_path"`

	APIClient       *apiclient.ApiClient
	UserAgent       string
	MetricsProvider *metrics.Provider
}

func (b *LiveBouncer) Init() error {
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

	b.APIClient, err = getAPIClient(b.APIUrl, b.UserAgent, b.APIKey, b.CAPath, b.CertPath, b.KeyPath, b.InsecureSkipVerify, log.StandardLogger())
	if err != nil {
		return fmt.Errorf("api client init: %w", err)
	}
	return nil
}

// TODO: plumb context.Context
func (b *LiveBouncer) Get(value, method string) (*models.GetDecisionsResponse, error) {
	filter := apiclient.DecisionsListOpts{
		IPEquals: &value,
	}

	var mode string
	switch method {
	case "ping":
		mode = modePing
	case "check":
		mode = modeCheck
	default:
		mode = modeLive
	}

	b.MetricsProvider.IncrementTotalBouncerCalls(mode)
	decision, resp, err := b.APIClient.Decisions.List(context.Background(), filter)
	if err != nil {
		b.MetricsProvider.IncrementTotalBouncerErrors(mode)
		if resp != nil && resp.Response != nil {
			_ = resp.Response.Body.Close()
		}
		return &models.GetDecisionsResponse{}, err
	}

	if resp != nil && resp.Response != nil {
		_ = resp.Response.Body.Close()
	}

	return decision, nil
}
