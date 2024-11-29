package bouncer

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zaptest"

	"github.com/hslatman/caddy-crowdsec-bouncer/internal/httputils"
)

func newCaddyVarsContext() (ctx context.Context) {
	ctx = context.WithValue(context.Background(), caddyhttp.VarsCtxKey, map[string]any{})
	return
}

func Test_appsec_checkRequest(t *testing.T) {
	logger := zaptest.NewLogger(t)
	ctx := newCaddyVarsContext()
	caddyhttp.SetVar(ctx, caddyhttp.ClientIPVarKey, "10.0.0.10")
	ctx, _ = httputils.EnsureIP(ctx)
	noIPCtx := newCaddyVarsContext()

	noIPRequest := httptest.NewRequest(http.MethodGet, "/path", http.NoBody)
	noIPRequest.Header.Set("User-Agent", "test-appsec")

	okGetRequest := httptest.NewRequest(http.MethodGet, "/path", http.NoBody)
	okGetRequest.Header.Set("User-Agent", "test-appsec")

	okPostRequest := httptest.NewRequest(http.MethodPost, "/path", bytes.NewBufferString("body"))
	okPostRequest.Header.Set("User-Agent", "test-appsec")

	// TODO: add test for no connection; reading error?
	// TODO: add assertions for responses and how they're handled
	type fields struct {
		maxBodySize int
	}
	type args struct {
		ctx context.Context
		r   *http.Request
	}
	tests := []struct {
		name           string
		fields         fields
		args           args
		expectedMethod string
		expectedBody   []byte
		wantErr        bool
	}{
		{
			name: "ok get",
			args: args{
				ctx: ctx,
				r:   okGetRequest,
			},
			expectedMethod: "GET",
		},
		{
			name: "ok post",
			args: args{
				ctx: ctx,
				r:   okPostRequest,
			},
			expectedMethod: "POST",
			expectedBody:   []byte("body"),
		},
		{
			name: "ok post limit",
			fields: fields{
				maxBodySize: 1,
			},
			args: args{
				ctx: ctx,
				r:   okPostRequest,
			},
			expectedMethod: "POST",
			expectedBody:   []byte("b"),
		},
		{
			name: "fail ip",
			args: args{
				ctx: noIPCtx,
				r:   noIPRequest,
			},
			wantErr: true,
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
					assert.Equal(t, tt.expectedBody, b)
					assert.Equal(t, len(tt.expectedBody), int(r.ContentLength))
				}
			})

			s := httptest.NewServer(h)
			t.Cleanup(s.Close)

			a := newAppSec(s.URL, "test-apikey", tt.fields.maxBodySize, logger)
			err := a.checkRequest(tt.args.ctx, tt.args.r)
			if tt.wantErr {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
		})
	}
}
