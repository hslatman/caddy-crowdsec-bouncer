package appsec

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/hslatman/caddy-crowdsec-bouncer/crowdsec"
)

type nextHandler struct{ called bool }

func (n *nextHandler) ServeHTTP(http.ResponseWriter, *http.Request) error {
	n.called = true
	return nil
}

func TestDisabledHandlerPassesThrough(t *testing.T) {
	disabled := false
	h := Handler{crowdsec: &crowdsec.CrowdSec{EnableAppSec: &disabled}}
	next := new(nextHandler)

	if err := h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil), next); err != nil {
		t.Fatal(err)
	}
	if !next.called {
		t.Fatal("next handler was not called")
	}
}
