// Copyright 2024 Herman Slatman
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// 	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package httputils

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zaptest"
)

func newCaddyVarsContext(ctx context.Context) context.Context {
	return context.WithValue(ctx, caddyhttp.VarsCtxKey, map[string]any{})
}

func Test_determineIPFromRequest(t *testing.T) {
	okCtx := newCaddyVarsContext(t.Context())
	caddyhttp.SetVar(okCtx, caddyhttp.ClientIPVarKey, "127.0.0.1")
	noIPCtx := newCaddyVarsContext(t.Context())
	wrongTypeCtx := newCaddyVarsContext(t.Context())
	caddyhttp.SetVar(wrongTypeCtx, caddyhttp.ClientIPVarKey, 42)
	emptyIPCtx := newCaddyVarsContext(t.Context())
	caddyhttp.SetVar(emptyIPCtx, caddyhttp.ClientIPVarKey, "")
	invalidIPCtx := newCaddyVarsContext(t.Context())
	caddyhttp.SetVar(invalidIPCtx, caddyhttp.ClientIPVarKey, "127.0.0.1.x")
	type args struct {
		ctx context.Context
	}
	tests := []struct {
		name    string
		args    args
		want    netip.Addr
		wantErr bool
	}{
		{"ok", args{okCtx}, netip.MustParseAddr("127.0.0.1"), false},
		{"no-ip", args{noIPCtx}, netip.Addr{}, true},
		{"wrong-type", args{wrongTypeCtx}, netip.Addr{}, true},
		{"empty-ip", args{emptyIPCtx}, netip.Addr{}, true},
		{"invalid-ip", args{invalidIPCtx}, netip.Addr{}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := determineIPFromRequest(tt.args.ctx)
			if tt.wantErr {
				require.Error(t, err)
				require.Equal(t, netip.Addr{}, got)
				return
			}

			require.NoError(t, err)
			require.Equal(t, tt.want, got)
		})
	}
}

func TestWriteResponse_Ban(t *testing.T) {
	logger := zaptest.NewLogger(t)

	t.Run("useCaddyError=false writes directly to ResponseWriter", func(t *testing.T) {
		w := httptest.NewRecorder()
		err := WriteResponse(w, logger, "ban", "192.168.1.1", "", 0, false)

		require.NoError(t, err)
		assert.Equal(t, http.StatusForbidden, w.Code)
		assert.Equal(t, "text/plain; charset=utf-8", w.Header().Get("Content-Type"))
	})

	t.Run("useCaddyError=true returns Caddy HandlerError", func(t *testing.T) {
		w := httptest.NewRecorder()
		err := WriteResponse(w, logger, "ban", "192.168.1.1", "", 0, true)

		require.Error(t, err)
		var handlerErr caddyhttp.HandlerError
		require.True(t, errors.As(err, &handlerErr))
		assert.Equal(t, http.StatusForbidden, handlerErr.StatusCode)
		assert.ErrorIs(t, err, ErrBanned)

		// ResponseWriter shouldn't be touched
		assert.Equal(t, http.StatusOK, w.Code)
	})
}

func TestWriteResponse_Throttle(t *testing.T) {
	logger := zaptest.NewLogger(t)

	t.Run("useCaddyError=false writes throttle directly to ResponseWriter", func(t *testing.T) {
		w := httptest.NewRecorder()
		err := WriteResponse(w, logger, "throttle", "192.168.1.1", "10s", 0, false)

		require.NoError(t, err)
		assert.Equal(t, http.StatusTooManyRequests, w.Code)
		assert.Equal(t, "10", w.Header().Get("Retry-After"))
	})

	t.Run("useCaddyError=true delegates Caddy HandlerError for throttle", func(t *testing.T) {
		w := httptest.NewRecorder()
		err := WriteResponse(w, logger, "throttle", "192.168.1.1", "10s", 0, true)

		require.Error(t, err)
		var handlerErr caddyhttp.HandlerError
		require.True(t, errors.As(err, &handlerErr))
		assert.Equal(t, http.StatusTooManyRequests, handlerErr.StatusCode)
		assert.ErrorIs(t, err, ErrThrottled)

		assert.Equal(t, "10", w.Header().Get("Retry-After"))
	})
}

func TestWriteResponse_Challenge(t *testing.T) {
	logger := zaptest.NewLogger(t)

	// a challenge decision from the LAPI has nothing to render, and is enforced as a ban
	w := httptest.NewRecorder()
	err := WriteResponse(w, logger, "challenge", "192.168.1.1", "", 0, false)

	require.NoError(t, err)
	assert.Equal(t, http.StatusForbidden, w.Code)
}

func TestWriteChallengeResponse(t *testing.T) {
	w := httptest.NewRecorder()
	w.Header().Set("Content-Security-Policy", "default-src 'none'")
	w.Header().Set("X-Unrelated", "kept")

	headers := http.Header{
		"Content-Type":            {"text/html"},
		"Content-Security-Policy": {"default-src 'self'"},
	}
	cookies := []string{"__crowdsec_challenge=a; Path=/; HttpOnly", "other=b, c"}

	err := WriteChallengeResponse(w, http.StatusOK, headers, cookies, "<html>challenge</html>")
	require.NoError(t, err)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "<html>challenge</html>", w.Body.String())
	assert.Equal(t, "text/html", w.Header().Get("Content-Type"))
	assert.Equal(t, []string{"default-src 'self'"}, w.Header().Values("Content-Security-Policy"), "challenge headers must replace existing ones")
	assert.Equal(t, "kept", w.Header().Get("X-Unrelated"))
	assert.Equal(t, cookies, w.Header().Values("Set-Cookie"), "every cookie must be sent in its own header")
	assert.Equal(t, "22", w.Header().Get("Content-Length"))
}

func TestSetBlockVars(t *testing.T) {
	assert.Equal(t, "crowdsec.module", ModuleVarKey)
	assert.Equal(t, "crowdsec.remediation", RemediationVarKey)
	assert.Equal(t, "crowdsec.origin", OriginVarKey)
	assert.Equal(t, "crowdsec.duration", DurationVarKey)

	// The handlers set vars on a context derived from the request's context, 
	// so the request context is what the logger sees.
	requestCtx := newCaddyVarsContext(t.Context())
	handlerCtx := newContext(requestCtx, netip.MustParseAddr("127.0.0.1"))

	SetBlockVars(handlerCtx, "http", "ban", "CAPI", "3h59m58s")

	assert.Equal(t, "http", caddyhttp.GetVar(requestCtx, ModuleVarKey))
	assert.Equal(t, "ban", caddyhttp.GetVar(requestCtx, RemediationVarKey))
	assert.Equal(t, "CAPI", caddyhttp.GetVar(requestCtx, OriginVarKey))
	assert.Equal(t, "3h59m58s", caddyhttp.GetVar(requestCtx, DurationVarKey))
}
