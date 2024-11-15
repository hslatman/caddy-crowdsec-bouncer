package bouncer

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"time"

	"github.com/hslatman/caddy-crowdsec-bouncer/internal/utils"
	"go.uber.org/zap"
)

type appsec struct {
	apiURL string
	apiKey string
	logger *zap.Logger
	client *http.Client
}

func newAppSec(apiURL, apiKey string, logger *zap.Logger) *appsec {
	return &appsec{
		apiURL: apiURL,
		apiKey: apiKey,
		logger: logger,
		client: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

type appsecResponse struct {
	Action     string `json:"action"`
	StatusCode int    `json:"http_status"`
}

func (a *appsec) checkRequest(ctx context.Context, r *http.Request) error {
	if a.apiURL == "" {
		return nil // AppSec component not enabled; skip check
	}

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
		body = io.NopCloser(bytes.NewBuffer(originalBody)) // TODO: reuse buffers?
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

	totalAppSecCalls.Inc()
	resp, err := a.client.Do(req)
	if err != nil {
		totalAppSecErrors.Inc()
		return err
	}
	defer resp.Body.Close()

	responseBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	switch resp.StatusCode {
	case 200:
		return nil
	case 401:
		a.logger.Error("appsec component not authenticated", zap.String("appsec_url", a.apiURL))
		return nil // this fails open, currently; make it fail hard if configured to do so?
	case 403:
		var r appsecResponse
		if err := json.Unmarshal(responseBody, &r); err != nil {
			return err
		}

		return &AppSecError{Err: errors.New("appsec rule triggered"), Action: r.Action, Duration: "", StatusCode: r.StatusCode}
	case 500:
		a.logger.Error("appsec component internal error", zap.String("appsec_url", a.apiURL))
		return nil // this fails open, currently; make it fail hard if configured to do so?
	default:
		a.logger.Warn("appsec component returned unsupported status", zap.String("code", resp.Status))
		return nil
	}
}

func (b *Bouncer) logAppSecStatus() {
	if b.appsec.apiURL == "" {
		b.logger.Info("appsec disabled")
		return
	}

	b.logger.Info("appsec enabled")
}
