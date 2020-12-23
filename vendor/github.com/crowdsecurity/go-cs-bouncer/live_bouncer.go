package csbouncer

import (
	"context"
	"net/url"

	"github.com/crowdsecurity/crowdsec/pkg/apiclient"
	"github.com/crowdsecurity/crowdsec/pkg/models"

	"github.com/pkg/errors"
)

type LiveBouncer struct {
	APIKey    string
	APIUrl    string
	APIClient *apiclient.ApiClient
	UserAgent string
}

func (b *LiveBouncer) Init() error {
	var err error
	var apiURL *url.URL
	apiURL, err = url.Parse(b.APIUrl)
	if err != nil {
		return errors.Wrapf(err, "local API Url '%s'", b.APIUrl)
	}
	t := &apiclient.APIKeyTransport{
		APIKey: b.APIKey,
	}

	b.APIClient, err = apiclient.NewDefaultClient(apiURL, "v1", b.UserAgent, t.Client())
	if err != nil {
		return errors.Wrapf(err, "api client init")
	}
	return nil
}

func (b *LiveBouncer) Get(value string) (*models.GetDecisionsResponse, error) {
	filter := apiclient.DecisionsListOpts{
		IPEquals: &value,
	}

	decision, _, err := b.APIClient.Decisions.List(context.Background(), filter)
	if err != nil {
		return &models.GetDecisionsResponse{}, err
	}

	return decision, nil
}
