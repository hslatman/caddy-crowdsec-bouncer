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
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"strconv"
	"time"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"
)

var (
	ErrBanned    = errors.New("banned by crowdsec")
	ErrThrottled = errors.New("throttled by crowdsec")
)

// Keys of the Caddy variables set when a request is blocked.
const (
	ModuleVarKey      = "crowdsec.module"
	RemediationVarKey = "crowdsec.remediation"
	OriginVarKey      = "crowdsec.origin"
	DurationVarKey    = "crowdsec.duration"
)

// SetBlockVars records why a request was blocked, making the reason available
// to matchers and the access log as `{http.vars.crowdsec.*}` placeholders.
func SetBlockVars(ctx context.Context, module, remediation, origin, duration string) {
	caddyhttp.SetVar(ctx, ModuleVarKey, module)
	caddyhttp.SetVar(ctx, RemediationVarKey, remediation)
	caddyhttp.SetVar(ctx, OriginVarKey, origin)
	caddyhttp.SetVar(ctx, DurationVarKey, duration)
}

// determineIPFromRequest returns the IP of the client based on the value that
// Caddy extracts from the original request and stores in the request context.
// Support for setting the real client IP in case a proxy sits in front of
// Caddy was added, so the client IP reported here is the actual client IP.
func determineIPFromRequest(ctx context.Context) (netip.Addr, error) {
	zero := netip.Addr{}
	clientIPVar := caddyhttp.GetVar(ctx, caddyhttp.ClientIPVarKey)
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

// WriteResponse writes a response to the [http.ResponseWriter] based on the typ, value,
// duration and status code provide.
func WriteResponse(w http.ResponseWriter, logger *zap.Logger, typ, value, duration string, statusCode int, useCaddyError bool) error {
	switch typ {
	case "ban":
		logger.Debug(fmt.Sprintf("serving ban response to %s", value))
		return writeBanResponse(w, statusCode, useCaddyError)
	case "captcha":
		logger.Debug(fmt.Sprintf("serving captcha (ban) response to %s", value))
		return writeCaptchaResponse(w, statusCode, useCaddyError)
	case "throttle":
		logger.Debug(fmt.Sprintf("serving throttle response to %s", value))
		return writeThrottleResponse(w, duration, useCaddyError)
	case "challenge":
		// A challenge decision from the LAPI has no challenge content to
		// serve, so it is enforced as a ban.
		logger.Debug(fmt.Sprintf("serving challenge (ban) response to %s", value))
		return writeBanResponse(w, statusCode, useCaddyError)
	default:
		logger.Warn(fmt.Sprintf("got crowdsec decision type: %s", typ))
		logger.Debug(fmt.Sprintf("serving ban response to %s", value))
		return writeBanResponse(w, statusCode, useCaddyError)
	}
}

// WriteChallengeResponse relays a challenge response from the AppSec component
// to the client. Headers from the AppSec component replace any header with the
// same name already set, and every cookie is sent in its own Set-Cookie header.
// The AppSec component only sees the request path, so it can't tell when the
// client is on HTTPS; secure marks cookies Secure on its behalf.
func WriteChallengeResponse(w http.ResponseWriter, statusCode int, headers http.Header, cookies []string, body string, secure bool) error {
	h := w.Header()
	for key, values := range headers {
		h[key] = values
	}
	for _, cookie := range cookies {
		if secure {
			cookie = withSecure(cookie)
		}
		h.Add("Set-Cookie", cookie)
	}
	h.Set("Content-Length", strconv.Itoa(len(body)))

	w.WriteHeader(statusCode)
	_, err := io.WriteString(w, body)
	return err
}

// withSecure adds the Secure attribute to a Set-Cookie header value, unless it
// already has it or can't be parsed.
func withSecure(cookie string) string {
	c, err := http.ParseSetCookie(cookie)
	if err != nil || c.Secure {
		return cookie
	}
	return cookie + "; Secure"
}

// writeBanResponse writes a 403 status as response
func writeBanResponse(w http.ResponseWriter, statusCode int, useCaddyError bool) error {
	code := statusCode
	if code <= 0 {
		code = http.StatusForbidden
	}
	if useCaddyError {
		return caddyhttp.Error(code, ErrBanned)
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(code)
	return nil
}

// writeCaptchaResponse (currently) writes a 403 status as response
func writeCaptchaResponse(w http.ResponseWriter, statusCode int, useCaddyError bool) error {
	// TODO: implement showing a captcha in some way. How? hCaptcha? And how to handle afterwards?
	return writeBanResponse(w, statusCode, useCaddyError)
}

// writeThrottleResponse writes 429 status as response
func writeThrottleResponse(w http.ResponseWriter, duration string, useCaddyError bool) error {
	d, err := time.ParseDuration(duration)
	if err != nil {
		return err
	}

	// TODO: round this to the nearest multiple of the ticker interval? and/or include the time the decision was processed from stream vs. request time?
	retryAfter := fmt.Sprintf("%.0f", d.Seconds())
	w.Header().Add("Retry-After", retryAfter)

	if useCaddyError {
		return caddyhttp.Error(http.StatusTooManyRequests, ErrThrottled)
	}
	w.WriteHeader(http.StatusTooManyRequests)
	return nil
}
