package bouncer

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/hslatman/caddy-crowdsec-bouncer/internal/utils"
)

type appsec struct {
	apiURL string
	apiKey string
	client *http.Client
}

func newAppSec(apiURL, apiKey string) *appsec {
	return &appsec{
		apiURL: apiURL,
		apiKey: apiKey,
		client: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

func (a *appsec) checkRequest(ctx context.Context, r *http.Request) error {
	if a.apiURL == "" {
		return nil // AppSec component not enabled
	}

	// TODO: add (debug) logging
	// TODO: return a decision, and act on it in the handler (named/typed error)

	originalIP, err := utils.DetermineIPFromRequest(r)
	if err != nil {
		return err // TODO: return error here? Or just log it and continue serving
	}

	originalBody, err := io.ReadAll(r.Body)
	if err != nil {
		return err
	}

	method := http.MethodGet
	var body io.ReadCloser = http.NoBody
	if len(originalBody) > 0 {
		method = http.MethodPost
		body = io.NopCloser(bytes.NewBuffer(originalBody))
	}
	r.Body = io.NopCloser(bytes.NewBuffer(originalBody))

	req, err := http.NewRequestWithContext(ctx, method, a.apiURL, body)
	if err != nil {
		return err
	}

	req.Header.Set("X-Crowdsec-Appsec-Ip", originalIP.String())
	req.Header.Set("X-Crowdsec-Appsec-Uri", r.URL.String())
	req.Header.Set("X-Crowdsec-Appsec-Host", r.Host)
	req.Header.Set("X-Crowdsec-Appsec-Verb", r.Method)
	req.Header.Set("X-Crowdsec-Appsec-Api-Key", a.apiKey)

	resp, err := a.client.Do(req)
	if err != nil {
		return err
	}

	switch resp.StatusCode {
	case 200:
		return nil // TODO: read decision from body?
	case 401:
		return errors.New("not authenticated")
	case 403:
		return errors.New("not allowed") // TODO: read decision
	case 500:
		return errors.New("internal error")
	default:
		return fmt.Errorf("unsupported status code %d", resp.StatusCode)
	}
}
