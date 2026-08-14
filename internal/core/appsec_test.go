package core

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zaptest"

	"github.com/hslatman/caddy-crowdsec-bouncer/internal/httputils"
	"github.com/hslatman/caddy-crowdsec-bouncer/internal/metrics"
)

func newCaddyVarsContext(ctx context.Context) context.Context {
	return context.WithValue(ctx, caddyhttp.VarsCtxKey, map[string]any{})
}

func Test_appsec_checkRequest(t *testing.T) {
	logger := zaptest.NewLogger(t)
	ctx := newCaddyVarsContext(t.Context())
	caddyhttp.SetVar(ctx, caddyhttp.ClientIPVarKey, "10.0.0.10")
	ctx, _ = httputils.EnsureIP(ctx)
	noIPCtx := newCaddyVarsContext(t.Context())

	noIPRequest := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/path", http.NoBody)
	noIPRequest.Header.Set("User-Agent", "test-appsec")

	okGetRequest := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/path", http.NoBody)
	okGetRequest.Header.Set("User-Agent", "test-appsec")

	okPostRequest := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/path", bytes.NewBufferString("body"))
	okPostRequest.Header.Set("User-Agent", "test-appsec")

	okPostLimitRequest := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/path", bytes.NewBufferString("body"))
	okPostLimitRequest.Header.Set("User-Agent", "test-appsec")

	appSecTimeout := 2 * time.Second

	// TODO: add assertions for responses and how they're handled
	type fields struct {
		maxBodySize int
		failOpen    bool
	}
	type args struct {
		ctx context.Context
		r   *http.Request
	}
	tests := []struct {
		name                 string
		fields               fields
		args                 args
		expectedMethod       string
		expectedAppSecBody   []byte
		expectedUpstreamBody []byte
		wantErr              bool
		serverDown           bool
	}{
		{
			name: "ok get",
			args: args{
				ctx: ctx,
				r:   okGetRequest,
			},
			expectedMethod:       "GET",
			expectedUpstreamBody: []byte{},
		},
		{
			name: "ok post",
			fields: fields{
				maxBodySize: 10485760, // default max body size of 1MB
			},
			args: args{
				ctx: ctx,
				r:   okPostRequest,
			},
			expectedMethod:       "POST",
			expectedAppSecBody:   []byte("body"),
			expectedUpstreamBody: []byte("body"),
		},
		{
			name: "ok post limit",
			fields: fields{
				maxBodySize: 1,
			},
			args: args{
				ctx: ctx,
				r:   okPostLimitRequest,
			},
			expectedMethod:       "POST",
			expectedAppSecBody:   []byte("b"),
			expectedUpstreamBody: []byte("body"),
		},
		{
			name: "fail ip",
			args: args{
				ctx: noIPCtx,
				r:   noIPRequest,
			},
			wantErr: true,
		},
		{
			name: "fail open on connection error",
			fields: fields{
				failOpen: true,
			},
			args: args{
				ctx: ctx,
				r:   okGetRequest,
			},
			serverDown:           true,
			expectedUpstreamBody: []byte{},
		},
		{
			name: "fail hard on connection error",
			args: args{
				ctx: ctx,
				r:   okGetRequest,
			},
			serverDown: true,
			wantErr:    true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := http.NewServeMux()
			h.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
				assert.Equal(t, "caddy-cs-bouncer", r.Header.Get("User-Agent"))
				assert.Equal(t, "test-appsec", r.Header.Get("X-Crowdsec-Appsec-User-Agent"))
				assert.Equal(t, "10.0.0.10", r.Header.Get("X-Crowdsec-Appsec-Ip"))
				assert.Equal(t, "/path", r.Header.Get("X-Crowdsec-Appsec-Uri"))
				assert.Equal(t, "example.com", r.Header.Get("X-Crowdsec-Appsec-Host"))
				assert.Equal(t, tt.expectedMethod, r.Header.Get("X-Crowdsec-Appsec-Verb"))
				assert.Equal(t, "test-apikey", r.Header.Get("X-Crowdsec-Appsec-Api-Key"))

				if r.Method == http.MethodPost {
					b, err := io.ReadAll(r.Body)
					require.NoError(t, err)
					assert.Equal(t, tt.expectedAppSecBody, b)
					assert.Equal(t, len(tt.expectedAppSecBody), int(r.ContentLength))
				}
			})

			s := httptest.NewServer(h)
			if tt.serverDown {
				s.Close()
			} else {
				t.Cleanup(s.Close)
			}

			m := &metrics.Provider{}
			a := newAppSec(s.URL, "test-apikey", tt.fields.maxBodySize, appSecTimeout, tt.fields.failOpen, logger, m)
			err := a.checkRequest(tt.args.ctx, tt.args.r)
			if tt.wantErr {
				assert.Error(t, err)
				return
			}

			assert.NoError(t, err)

			body, readErr := io.ReadAll(tt.args.r.Body)
			require.NoError(t, readErr)
			assert.Equal(t, tt.expectedUpstreamBody, body)
		})
	}
}

// Test_appsec_checkRequest_stripsHopByHopHeaders is the regression guard for
// 9e35b21: connection-specific headers must not be forwarded to the AppSec
// component.
//
// This is asserted here rather than end to end because the symptom only appears
// when the AppSec endpoint speaks HTTP/2, which rejects such headers outright.
// A test container is reached over plain HTTP/1.1, where forwarding them is
// harmless, so an end-to-end test passes with or without the fix. Inspecting the
// forwarded headers directly makes the check independent of the transport.
func Test_appsec_checkRequest_stripsHopByHopHeaders(t *testing.T) {
	logger := zaptest.NewLogger(t)

	ctx := newCaddyVarsContext(t.Context())
	caddyhttp.SetVar(ctx, caddyhttp.ClientIPVarKey, "10.0.0.10")
	ctx, _ = httputils.EnsureIP(ctx)

	r := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/path", http.NoBody)
	r.Header.Set("User-Agent", "test-appsec")

	// a WebSocket handshake, plus a token named by Connection that is itself
	// hop-by-hop by virtue of being listed there
	r.Header.Set("Connection", "Upgrade, X-Custom-Hop")
	r.Header.Set("Upgrade", "websocket")
	r.Header.Set("Keep-Alive", "timeout=5")
	r.Header.Set("Proxy-Connection", "keep-alive")
	r.Header.Set("X-Custom-Hop", "should-be-dropped")

	// an ordinary header, which must still be forwarded
	r.Header.Set("X-Keep-Me", "kept")

	var received http.Header
	h := http.NewServeMux()
	h.HandleFunc("/", func(_ http.ResponseWriter, req *http.Request) {
		received = req.Header.Clone()
	})

	s := httptest.NewServer(h)
	t.Cleanup(s.Close)

	a := newAppSec(s.URL, "test-apikey", 0, 2*time.Second, false, logger, &metrics.Provider{})
	require.NoError(t, a.checkRequest(ctx, r))
	require.NotNil(t, received, "the appsec component was never called")

	for _, header := range []string{"Upgrade", "Keep-Alive", "Proxy-Connection", "X-Custom-Hop"} {
		assert.Emptyf(t, received.Get(header), "%s must not be forwarded to the appsec component", header)
	}

	assert.Equal(t, "kept", received.Get("X-Keep-Me"), "ordinary headers must still be forwarded")
	assert.Equal(t, "test-appsec", received.Get("X-Crowdsec-Appsec-User-Agent"))
}
