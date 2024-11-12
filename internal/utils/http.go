package utils

import (
	"errors"
	"fmt"
	"net/http"
	"net/netip"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

// DetermineIPFromRequest returns the IP of the client based on the value that
// Caddy extracts from the original request and stores in the request context.
// Support for setting the real client IP in case a proxy sits in front of
// Caddy was added, so the client IP reported here is the actual client IP.
func DetermineIPFromRequest(r *http.Request) (netip.Addr, error) {
	zero := netip.Addr{}
	clientIPVar := caddyhttp.GetVar(r.Context(), caddyhttp.ClientIPVarKey)
	if clientIPVar == nil {
		return zero, errors.New("failed getting client IP from context")
	}

	var clientIP string
	var ok bool
	if clientIP, ok = clientIPVar.(string); !ok {
		return zero, fmt.Errorf("client IP from request context is invalid type %T", clientIPVar)
	}

	if clientIP == "" {
		return zero, errors.New("client IP from request context is empty")
	}

	ip, err := netip.ParseAddr(clientIP)
	if err != nil {
		return zero, fmt.Errorf("could not parse %q into netip.Addr", clientIP)
	}

	return ip, nil
}
