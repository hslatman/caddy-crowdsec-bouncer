package crowdsec

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zaptest"

	"github.com/hslatman/caddy-crowdsec-bouncer/internal/adminapi"
	"github.com/hslatman/caddy-crowdsec-bouncer/internal/bouncer"
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

func newFakeAdminAPIHandler(t *testing.T) caddy.AdminHandler {
	t.Helper()

	logger := zaptest.NewLogger(t)
	b, err := bouncer.New("key", "fake", "", 0, "10s", logger)
	require.NoError(t, err)

	a := &adminAPI{
		admin: &CrowdSec{
			APIUrl:  "fake",
			bouncer: b,
		},
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
		assert.False(t, r.AppSec.Enabled)
		assert.Equal(t, 0, r.NumberOfActiveDecisions)
		assert.False(t, r.ShouldFailHard)
		assert.NotEmpty(t, r.InstanceID)
		assert.NotEmpty(t, r.UserAgent)

		d, err := time.ParseDuration("0s")
		require.NoError(t, err)
		assert.Greater(t, r.Uptime, d)
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
