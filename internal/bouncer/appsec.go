package bouncer

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/oxtoacart/bpool"
	"go.uber.org/zap"

	"github.com/hslatman/caddy-crowdsec-bouncer/internal/httputils"
)

type appsec struct {
	apiURL string
	apiKey string
	logger *zap.Logger
	client *http.Client
	pool   *bpool.BufferPool
}

func newAppSec(apiURL, apiKey string, logger *zap.Logger) *appsec {
	return &appsec{
		apiURL: apiURL,
		apiKey: apiKey,
		logger: logger,
		client: &http.Client{
			Timeout: 10 * time.Second,
			Transport: &http.Transport{
				Proxy: http.ProxyFromEnvironment,
				DialContext: (&net.Dialer{
					Timeout:   30 * time.Second,
					KeepAlive: 30 * time.Second,
				}).DialContext,
				ForceAttemptHTTP2:     true,
				MaxIdleConns:          100,
				IdleConnTimeout:       60 * time.Second,
				TLSHandshakeTimeout:   10 * time.Second,
				ExpectContinueTimeout: 1 * time.Second,
			},
		},
		pool: bpool.NewBufferPool(64),
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

	originalIP, ok := httputils.FromContext(ctx)
	if !ok {
		return errors.New("could not retrieve netip.Addr from context")
	}

	method := http.MethodGet
	var body io.ReadCloser = http.NoBody
	if r.Body != nil && r.ContentLength > 0 {
		originalBody, err := io.ReadAll(r.Body)
		if err != nil {
			return err
		}

		method = http.MethodPost
		buffer := a.pool.Get()
		defer a.pool.Put(buffer)

		_, _ = buffer.Write(originalBody)
		body = io.NopCloser(buffer)

		r.Body = io.NopCloser(bytes.NewBuffer(originalBody))
	}

	req, err := http.NewRequestWithContext(ctx, method, a.apiURL, body)
	if err != nil {
		return err
	}

	for key, headers := range r.Header {
		for _, value := range headers {
			req.Header.Add(key, value)
		}
	}
	req.Header.Set("X-Crowdsec-Appsec-Ip", originalIP.String())
	req.Header.Set("X-Crowdsec-Appsec-Uri", r.URL.String())
	req.Header.Set("X-Crowdsec-Appsec-Host", r.Host)
	req.Header.Set("X-Crowdsec-Appsec-Verb", r.Method)
	req.Header.Set("X-Crowdsec-Appsec-Api-Key", a.apiKey)
	req.Header.Set("X-Crowdsec-Appsec-User-Agent", r.Header.Get("User-Agent"))
	req.Header.Set("User-Agent", userAgent)

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
		a.logger.Error("appsec component not authenticated", zap.String("code", resp.Status), zap.String("appsec_url", a.apiURL))
		return nil // this fails open, currently; make it fail hard if configured to do so?
	case 403:
		var r appsecResponse
		if err := json.Unmarshal(responseBody, &r); err != nil {
			return err
		}

		return &AppSecError{Err: errors.New("appsec rule triggered"), Action: r.Action, Duration: "", StatusCode: r.StatusCode}
	case 404:
		a.logger.Error("appsec component endpoint not found", zap.String("code", resp.Status), zap.String("appsec_url", a.apiURL))
		return nil
	case 500:
		a.logger.Error("appsec component internal error", zap.String("code", resp.Status), zap.String("appsec_url", a.apiURL))
		return nil // this fails open, currently; make it fail hard if configured to do so?
	default:
		a.logger.Error("appsec component returned unsupported status", zap.String("code", resp.Status), zap.String("appsec_url", a.apiURL))
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
