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
