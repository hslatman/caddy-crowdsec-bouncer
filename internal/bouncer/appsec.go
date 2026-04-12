package bouncer

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/oxtoacart/bpool"
	"go.uber.org/zap"

	"github.com/hslatman/caddy-crowdsec-bouncer/internal/httputils"
	"github.com/hslatman/caddy-crowdsec-bouncer/internal/metrics"
)

type appsec struct {
	apiURL          string
	apiKey          string
	maxBodySize     int
	failOpen        bool
	logger          *zap.Logger
	client          *http.Client
	metricsProvider *metrics.Provider
	pool            *bpool.BufferPool
}

func newAppSec(apiURL, apiKey string, maxBodySize int, timeout time.Duration, failOpen bool, logger *zap.Logger, metricsProvider *metrics.Provider) *appsec {
	return &appsec{
		apiURL:      apiURL,
		apiKey:      apiKey,
		maxBodySize: maxBodySize,
		failOpen:    failOpen,
		logger:      logger,
		client: &http.Client{
			Timeout: timeout,
			Transport: &http.Transport{
				Proxy: http.ProxyFromEnvironment,
				DialContext: (&net.Dialer{
					Timeout:   timeout,
					KeepAlive: 30 * time.Second,
				}).DialContext,
				ForceAttemptHTTP2:     true,
				MaxIdleConns:          100,
				IdleConnTimeout:       60 * time.Second,
				TLSHandshakeTimeout:   timeout,
				ExpectContinueTimeout: 1 * time.Second,
			},
		},
		metricsProvider: metricsProvider,
		pool:            bpool.NewBufferPool(64),
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

	var contentLength int
	method := http.MethodGet
	var body io.ReadCloser = http.NoBody
	if r.Body != nil && r.ContentLength > 0 {
		originalBody, err := io.ReadAll(r.Body)
		if err != nil {
			return err
		}

		buffer := a.pool.Get()
		defer a.pool.Put(buffer)

		if a.maxBodySize > 0 {
			len := min(len(originalBody), a.maxBodySize)
			_, _ = buffer.Write(originalBody[:len])

		} else {
			_, _ = buffer.Write(originalBody)
		}

		method = http.MethodPost
		body = io.NopCloser(buffer)
		contentLength = buffer.Len()

		// "reset" the original request body
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
	req.Header.Set("User-Agent", userAgentName)

	// explicitly setting the content length results in CrowdSec (1.6.4) properly
	// accepting the request body. Without this the Content-Length header won't be
	// set to the correct value, resulting in CrowdSec skipping its evaluation. The
	// PR at https://github.com/crowdsecurity/crowdsec/pull/3342 makes it work, but
	// that's not merged yet, and will thus require the release of CrowdSec that
	// includes the patch.
	req.ContentLength = int64(contentLength)

	a.metricsProvider.IncrementTotalAppSecCalls()
	resp, err := a.client.Do(req)
	if err != nil {
		a.metricsProvider.IncrementTotalAppSecErrors()
		a.logger.Error("appsec component unavailable", zap.Error(err), zap.String("appsec_url", a.apiURL))
		return a.failOpenOrErr(err)
	}
	defer func() { _ = resp.Body.Close() }()

	responseBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	switch resp.StatusCode {
	case 200:
		return nil
	case 401:
		a.logger.Error("appsec component not authenticated", zap.String("code", resp.Status), zap.String("appsec_url", a.apiURL))
		return a.failOpenOrErr(fmt.Errorf("appsec component not authenticated: %s", resp.Status))
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
		return a.failOpenOrErr(fmt.Errorf("appsec component internal error: %s", resp.Status))
	default:
		a.logger.Error("appsec component returned unsupported status", zap.String("code", resp.Status), zap.String("appsec_url", a.apiURL))
		return nil
	}
}

func (a *appsec) failOpenOrErr(err error) error {
	if a.failOpen {
		return nil
	}
	return err
}

func (b *Bouncer) logAppSecStatus() {
	if b.appsec.apiURL == "" {
		b.logger.Info("appsec disabled")
		return
	}

	b.logger.Info("appsec enabled")
}
