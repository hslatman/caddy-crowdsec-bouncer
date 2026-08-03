package core

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

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
	}
}

type appsecResponse struct {
	Action     string `json:"action"`
	StatusCode int    `json:"http_status"`
}

// hopByHopHeaders are connection-specific headers that must not be forwarded to
// the AppSec component. Forwarding these (e.g. "Connection: Upgrade" from a
// WebSocket handshake) is meaningless to the check and is rejected outright by
// an HTTP/2 AppSec endpoint. Keys are in canonical (textproto) form. See
// RFC 7230, section 6.1.
var hopByHopHeaders = map[string]struct{}{
	"Connection":          {},
	"Keep-Alive":          {},
	"Proxy-Authenticate":  {},
	"Proxy-Authorization": {},
	"Proxy-Connection":    {},
	"Te":                  {},
	"Trailer":             {},
	"Transfer-Encoding":   {},
	"Upgrade":             {},
}

func (a *appsec) checkRequest(ctx context.Context, r *http.Request) error {
	if a.apiURL == "" {
		return nil // AppSec component not enabled; skip check
	}

	originalIP, ok := httputils.FromContext(ctx)
	if !ok {
		return errors.New("could not retrieve netip.Addr from context")
	}

	var method = http.MethodGet
	var body io.ReadCloser = http.NoBody
	var contentLength = 0
	switch {
	case isBodyUnreadable(r):
		a.logger.Warn("dropping request body from AppSec check as it can't be buffered")
	case r.Body != nil && r.Body != http.NoBody && r.ContentLength != 0:
		// a non-positive maxBodySize means no limit; only cap the read when set
		bodyReader := io.Reader(r.Body)
		if a.maxBodySize > 0 {
			bodyReader = io.LimitReader(r.Body, int64(a.maxBodySize))
		}

		data, err := io.ReadAll(bodyReader)
		if err != nil {
			return err
		}

		method = http.MethodPost
		body = io.NopCloser(bytes.NewReader(data))
		contentLength = len(data)

		// reset the original request body: buffered prefix + unread remainder
		r.Body = io.NopCloser(io.MultiReader(bytes.NewReader(data), r.Body))
	}

	req, err := http.NewRequestWithContext(ctx, method, a.apiURL, body)
	if err != nil {
		return err
	}

	// tokens named in the Connection header are themselves hop-by-hop and must
	// be dropped as well (e.g. "Connection: Upgrade" also removes Upgrade).
	connectionHeaders := map[string]struct{}{}
	for _, value := range r.Header["Connection"] {
		for token := range strings.SplitSeq(value, ",") {
			if token = strings.TrimSpace(token); token != "" {
				connectionHeaders[http.CanonicalHeaderKey(token)] = struct{}{}
			}
		}
	}

	for key, headers := range r.Header {
		if _, ok := hopByHopHeaders[key]; ok {
			continue
		}
		if _, ok := connectionHeaders[key]; ok {
			continue
		}
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
		// A canceled request context means the downstream client went away
		// before the AppSec check completed. This is not considered an error.
		if errors.Is(err, context.Canceled) {
			return nil
		}

		a.metricsProvider.IncrementTotalAppSecErrors()
		a.logger.Error("appsec component unavailable", zap.Error(err), zap.String("appsec_url", a.apiURL))
		return a.failOpenOrErr(err)
	}
	defer func() { _, _ = io.Copy(io.Discard, resp.Body); _ = resp.Body.Close() }()

	switch resp.StatusCode {
	case 200:
		return nil
	case 401:
		a.logger.Error("appsec component not authenticated", zap.String("code", resp.Status), zap.String("appsec_url", a.apiURL))
		return a.failOpenOrErr(fmt.Errorf("appsec component not authenticated: %s", resp.Status))
	case 403:
		responseBody, err := io.ReadAll(resp.Body)
		if err != nil {
			return err
		}

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

// isBodyUnreadable reports whether the request body cannot be buffered before
// forwarding it to the Appsec component. An HTTP/2 or HTTP/3 request without a
// Content-Length (typically a bidirectional gRPC stream) keeps its body open
// for the whole life of the stream and never reaches EOF, so reading it with
// io.ReadAll would block until the request times out and is wrongly turned into
// a 403. This mirrors the reference lua-cs-bouncer behavior, which refuses to
// read the body of an HTTP/2+ request that has no Content-Length.
//
// This function was taken from https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/blob/main/bouncer.go#L735
func isBodyUnreadable(httpReq *http.Request) bool {
	return httpReq.Body != nil && httpReq.Body != http.NoBody && httpReq.ProtoMajor >= 2 && httpReq.ContentLength < 0
}

func (a *appsec) failOpenOrErr(err error) error {
	if a.failOpen {
		return nil
	}

	return err
}

func (b *Core) logAppSecStatus() {
	if b.appsec.apiURL == "" {
		b.logger.Info("appsec disabled")
		return
	}

	b.logger.Info("appsec enabled")
}
