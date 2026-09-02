//go:build e2e

package e2e

import (
	"io"
	"net/http"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

const echoHandlerName = "e2e_echo"

func init() {
	caddy.RegisterModule(echoHandler{})
}

// echoHandler is a test-only Caddy handler that writes the request body back as
// the response body.
//
// It exists so tests can assert that a request body survives being buffered for
// the AppSec check: internal/core/appsec.go reads the body to forward it, then
// reassembles r.Body from the buffered prefix and the unread remainder. A
// handler further down the chain must still see the whole thing.
type echoHandler struct{}

func (echoHandler) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  caddy.ModuleID("http.handlers." + echoHandlerName),
		New: func() caddy.Module { return new(echoHandler) },
	}
}

func (echoHandler) ServeHTTP(w http.ResponseWriter, r *http.Request, _ caddyhttp.Handler) error {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return err
	}

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)

	return nil
}

var (
	_ caddy.Module                = (*echoHandler)(nil)
	_ caddyhttp.MiddlewareHandler = (*echoHandler)(nil)
)
