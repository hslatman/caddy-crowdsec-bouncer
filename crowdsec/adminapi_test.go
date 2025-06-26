package crowdsec

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/crowdsecurity/crowdsec/pkg/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/hslatman/caddy-crowdsec-bouncer/internal/adminapi"
)

func TestAdminAPIRoutes(t *testing.T) {
	a := adminAPI{}

	routes := a.Routes()
	assert.Len(t, routes, 4)

	for _, r := range routes {
		assert.Contains(t, r.Pattern, "/crowdsec")
	}
}

type testAdminHandler struct {
	t      *testing.T
	routes []caddy.AdminRoute
}

func (h *testAdminHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) error {
	h.t.Helper()

	for _, route := range h.routes {
		if r.URL.Path == route.Pattern { // rudimentary matching; just for testing
			return route.Handler.ServeHTTP(w, r)
		}
	}

	h.t.Logf("no matching route for %s %s", r.Method, r.URL.String())

	w.WriteHeader(http.StatusNotFound)

	return nil
}

var _ (caddy.AdminHandler) = (*testAdminHandler)(nil)

func newTestAdminHandler(t *testing.T, a *adminAPI) *testAdminHandler {
	return &testAdminHandler{t: t, routes: a.Routes()}
}

type testAdmin struct{}

func (a *testAdmin) Info(_ context.Context) adminapi.Info {
	return adminapi.Info{
		StreamingEnabled:        true,
		TickerInterval:          "10s",
		AppSecURL:               "",
		ShouldFailHard:          false,
		UserAgent:               "user-agent",
		InstanceID:              "instance-id",
		Uptime:                  time.Duration(10 * time.Second),
		NumberOfActiveDecisions: 1337,
	}
}

func (a *testAdmin) Healthy(ctx context.Context) bool {
	return true
}

func (a *testAdmin) Ping(ctx context.Context) bool {
	return true
}

func (a *testAdmin) Check(_ context.Context, ip netip.Addr, forceLive bool) (bool, *models.Decision, error) {
	return true, nil, nil
}

func newFakeAdminAPIHandler(t *testing.T) caddy.AdminHandler {
	t.Helper()

	a := &adminAPI{
		admin: &testAdmin{},
	}

	return newTestAdminHandler(t, a)
}

func TestAdminAPIHandlesRequests(t *testing.T) {
	handler := newFakeAdminAPIHandler(t)

	t.Run("info", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/crowdsec/info", http.NoBody)
		w := httptest.NewRecorder()
		err := handler.ServeHTTP(w, req)
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, w.Code)
		assert.Equal(t, "application/json", w.Header().Get("Content-Type"))

		var r adminapi.InfoResponse
		err = json.Unmarshal(w.Body.Bytes(), &r)
		require.NoError(t, err)
		assert.True(t, r.Streaming.Enabled)
		assert.True(t, r.Live.Enabled)
		assert.False(t, r.AppSec.Enabled)
		assert.Equal(t, 1337, r.NumberOfActiveDecisions)
		assert.False(t, r.ShouldFailHard)
		assert.NotEmpty(t, r.InstanceID)
		assert.NotEmpty(t, r.UserAgent)
		assert.Equal(t, "apikey", r.AuthType)
		assert.Equal(t, "adhoc", r.Live.Mode)
		assert.Equal(t, "10s", r.Streaming.Interval)

		d, err := time.ParseDuration("0s")
		require.NoError(t, err)
		assert.Greater(t, r.Uptime, d)
	})

	t.Run("ping", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/crowdsec/ping", http.NoBody)
		w := httptest.NewRecorder()
		err := handler.ServeHTTP(w, req)
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, w.Code)
		assert.Equal(t, "application/json", w.Header().Get("Content-Type"))

		var r adminapi.PingResponse
		err = json.Unmarshal(w.Body.Bytes(), &r)
		require.NoError(t, err)
		assert.True(t, r.Ok)
	})

	t.Run("health", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/crowdsec/health", http.NoBody)
		w := httptest.NewRecorder()
		err := handler.ServeHTTP(w, req)
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, w.Code)
		assert.Equal(t, "application/json", w.Header().Get("Content-Type"))

		var r adminapi.HealthResponse
		err = json.Unmarshal(w.Body.Bytes(), &r)
		require.NoError(t, err)
		assert.True(t, r.Ok)
	})

	t.Run("check", func(t *testing.T) {
		body := bytes.NewReader([]byte(`{"ip": "127.0.0.1", "live": false}`))
		req := httptest.NewRequest(http.MethodPost, "/crowdsec/check", body)
		w := httptest.NewRecorder()
		err := handler.ServeHTTP(w, req)
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, w.Code)
		assert.Equal(t, "application/json", w.Header().Get("Content-Type"))

		var r adminapi.CheckResponse
		err = json.Unmarshal(w.Body.Bytes(), &r)
		require.NoError(t, err)
		assert.False(t, r.Blocked)
		assert.Empty(t, r.Reason)
	})

	t.Run("not-found", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/crowdsec/not-found", http.NoBody)
		w := httptest.NewRecorder()
		err := handler.ServeHTTP(w, req)
		require.NoError(t, err)
		assert.Equal(t, http.StatusNotFound, w.Code)
	})

	t.Run("wrong-method", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/crowdsec/info", http.NoBody)
		w := httptest.NewRecorder()
		err := handler.ServeHTTP(w, req)
		require.NoError(t, err)
		assert.Equal(t, http.StatusMethodNotAllowed, w.Code)
	})
}
