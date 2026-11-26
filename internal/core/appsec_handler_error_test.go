package core

import (
	"errors"
	"net/http"
	"testing"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

func Test_appsec_failOpenOrErr_returnsHandlerError(t *testing.T) {
	cause := errors.New("appsec component unavailable")

	err := (&appsec{}).failOpenOrErr(cause)

	var handlerErr caddyhttp.HandlerError
	if !errors.As(err, &handlerErr) {
		t.Fatalf("got %T, want a caddyhttp.HandlerError", err)
	}
	if handlerErr.StatusCode != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", handlerErr.StatusCode)
	}
	if !errors.Is(err, cause) {
		t.Errorf("error %v does not wrap the cause", err)
	}
	if got := (&appsec{failOpen: true}).failOpenOrErr(cause); got != nil {
		t.Errorf("fail open returned %v, want nil", got)
	}
}
