//go:build e2e

package e2e

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/hslatman/caddy-crowdsec-bouncer/internal/testutils"
)

const allowedBody = "allowed"

// builder assembles a Caddy JSON configuration for the tests. Everything that
// varies between tests is an option; the defaults give a single HTTP server
// with the crowdsec handler in front of a static response, trusting 127.0.0.1
// as a proxy so tests can present their own client IP.
type builder struct {
	app          map[string]any
	handlers     []any
	errorRoutes  []any
	trustProxies bool
	layer4       bool
}

type option func(*builder)

// withStreaming toggles the streaming bouncer. It is enabled by default.
func withStreaming(enabled bool) option {
	return func(b *builder) { b.app["enable_streaming"] = enabled }
}

// withTicker sets the interval at which the streaming bouncer polls the LAPI.
func withTicker(interval string) option {
	return func(b *builder) { b.app["ticker_interval"] = interval }
}

// withMetricsInterval sets the usage metrics push interval.
func withMetricsInterval(interval string) option {
	return func(b *builder) { b.app["metrics_interval"] = interval }
}

// withCaddyError propagates decisions as Caddy errors instead of writing the
// response directly, so handle_errors routes can serve a custom page.
func withCaddyError() option {
	return func(b *builder) { b.app["enable_caddy_error"] = true }
}

// withAppSec points the module at an AppSec component and adds the appsec
// handler to the route, after the crowdsec handler.
func withAppSec(url string) option {
	return func(b *builder) {
		b.app["appsec_url"] = url
		b.handlers = append([]any{
			map[string]any{"handler": "crowdsec"},
			map[string]any{"handler": "appsec"},
		}, b.handlers[1:]...)
	}
}

func withAppSecFailOpen(failOpen bool) option {
	return func(b *builder) { b.app["appsec_fail_open"] = failOpen }
}

func withAppSecMaxBodyBytes(n int) option {
	return func(b *builder) { b.app["appsec_max_body_bytes"] = n }
}

func withAppSecTimeout(timeout string) option {
	return func(b *builder) { b.app["appsec_timeout"] = timeout }
}

// withoutTrustedProxies drops the trusted_proxies configuration, so Caddy
// ignores X-Forwarded-For and treats 127.0.0.1 as the client.
func withoutTrustedProxies() option {
	return func(b *builder) { b.trustProxies = false }
}

// withEcho replaces the static response with a handler that echoes the request
// body, so tests can assert the body survived being buffered for AppSec.
func withEcho() option {
	return func(b *builder) {
		b.handlers[len(b.handlers)-1] = map[string]any{"handler": echoHandlerName}
	}
}

// withErrorPage serves body for any error produced by the handler chain. Only
// meaningful together with withCaddyError.
func withErrorPage(body string) option {
	return func(b *builder) {
		b.errorRoutes = []any{
			map[string]any{
				"handle": []any{
					map[string]any{
						"handler":     "static_response",
						"status_code": "{http.error.status_code}",
						"body":        body,
					},
				},
			},
		}
	}
}

// withLayer4 adds a layer4 server whose only route matches on crowdsec and
// echoes back whatever it receives. A connection from a banned address does not
// match the route, so nothing is echoed.
func withLayer4() option {
	return func(b *builder) { b.layer4 = true }
}

// config renders a Caddy JSON configuration for the given container.
func config(t *testing.T, h *testutils.Harness, c *testutils.Container, opts ...option) string {
	t.Helper()

	b := &builder{
		app: map[string]any{
			"api_url":         c.APIUrl(),
			"api_key":         c.APIKey(),
			"ticker_interval": "1s",
		},
		handlers: []any{
			map[string]any{"handler": "crowdsec"},
			map[string]any{
				"handler":     "static_response",
				"status_code": "200",
				"body":        allowedBody,
			},
		},
		trustProxies: true,
	}

	for _, opt := range opts {
		opt(b)
	}

	server := map[string]any{
		"listen":          []any{h.HTTPAddr},
		"automatic_https": map[string]any{"disable": true},
		"routes": []any{
			map[string]any{"handle": b.handlers},
		},
	}

	if b.trustProxies {
		// without this Caddy ignores X-Forwarded-For and every test would share
		// 127.0.0.1 as its client address
		server["trusted_proxies"] = map[string]any{
			"source": "static",
			"ranges": []any{"127.0.0.1/32"},
		}
		server["client_ip_headers"] = []any{"X-Forwarded-For"}
	}

	if len(b.errorRoutes) > 0 {
		server["errors"] = map[string]any{"routes": b.errorRoutes}
	}

	apps := map[string]any{
		"crowdsec": b.app,
		"http": map[string]any{
			"servers": map[string]any{"e2e": server},
		},
	}

	if b.layer4 {
		apps["layer4"] = map[string]any{
			"servers": map[string]any{
				"l4": map[string]any{
					"listen": []any{h.L4Addr},
					"routes": []any{
						map[string]any{
							"match": []any{
								map[string]any{"crowdsec": map[string]any{}},
							},
							"handle": []any{
								map[string]any{"handler": "echo"},
							},
						},
					},
				},
			},
		}
	}

	cfg := map[string]any{
		"admin": map[string]any{"listen": h.AdminAddr},
		"logging": map[string]any{
			"logs": map[string]any{
				"default": map[string]any{"level": "ERROR"},
			},
		},
		"apps": apps,
	}

	out, err := json.Marshal(cfg)
	require.NoError(t, err)

	return string(out)
}
